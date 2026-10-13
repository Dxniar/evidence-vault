"""Opt-in PostgreSQL/Storage checks using an isolated schema and object prefix.

Run inside the Docker image with --run-live. No existing application rows are
modified. The final JSON states whether all temporary resources were removed.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pyotp
from flask_migrate import upgrade
from sqlalchemy import event, inspect, text
from werkzeug.security import generate_password_hash

import app as application_module
from models import AuditLog, Case, Evidence, User, db
from storage import StorageError


class NamespacedStorage:
    def __init__(self, raw, prefix):
        self.raw = raw
        self.prefix = prefix
        self.keys = set()

    def qualified(self, key):
        qualified = self.prefix + key
        if not qualified.startswith(self.prefix) or '..' in key.split('/'):
            raise ValueError('invalid temporary storage key')
        return qualified

    def upload(self, key, content, content_type):
        qualified = self.qualified(key)
        self.keys.add(qualified)
        return self.raw.upload(qualified, content, content_type)

    def download(self, key, max_bytes):
        return self.raw.download(self.qualified(key), max_bytes)

    def delete(self, key):
        qualified = self.qualified(key)
        self.raw.delete(qualified)
        self.keys.discard(qualified)


def main():
    if '--run-live' not in sys.argv:
        print('Explicit --run-live is required to create isolated temporary resources.')
        return 2
    run_id = secrets.token_hex(6)
    schema = 'ev_verify_' + run_id
    assert re.fullmatch(r'ev_verify_[0-9a-f]{12}', schema)
    report = {'schema': schema, 'checks': {}, 'cleanup': {}}
    production = application_module.create_app()
    raw_storage = production.extensions['evidence_storage']
    namespaced = NamespacedStorage(raw_storage, 'verification/' + run_id + '/')
    sandbox = None
    schema_created = False
    baseline = None

    def public_counts(engine):
        with engine.connect() as connection:
            return {table: connection.execute(text('SELECT COUNT(*) FROM public.' + table)).scalar_one()
                    for table in ('users', 'cases', 'evidence', 'audit_logs')}

    def token(client):
        with client.session_transaction() as session:
            return session['csrf_token']

    def post(client, path, payload=None, **kwargs):
        return client.post(path, data={'csrf_token': token(client), **(payload or {})}, **kwargs)

    password = secrets.token_urlsafe(24) + 'Aa1'

    try:
        with production.app_context():
            engine = db.engine
            baseline = public_counts(engine)
            with engine.begin() as connection:
                connection.execute(text('CREATE SCHEMA "' + schema + '"'))
            schema_created = True
            database_uri = production.config['SQLALCHEMY_DATABASE_URI']
        sandbox = application_module.create_app({
            'TESTING': True, 'SECRET_KEY': secrets.token_urlsafe(48),
            'READ_PAGE_AUTOCOMMIT': False,  # Keep the transaction-local namespace guard effective.
            'SQLALCHEMY_DATABASE_URI': database_uri,
            'SQLALCHEMY_ENGINE_OPTIONS': {'pool_pre_ping': True, 'pool_size': 5, 'max_overflow': 5,
                'connect_args': {'sslmode': 'require', 'connect_timeout': 15,
                    'application_name': schema}},
            'STORAGE': namespaced, 'SESSION_COOKIE_SECURE': False,
            'TRUSTED_HOSTS': ['localhost'], 'GOOGLE_OAUTH_CLIENT_ID': '', 'GOOGLE_OAUTH_CLIENT_SECRET': '',
        })
        with sandbox.app_context():
            @event.listens_for(db.engine, 'begin')
            def isolate_transaction(connection):
                # Poolers may ignore/reset connection startup options. Apply
                # and verify the namespace inside every actual transaction.
                connection.exec_driver_sql('SET LOCAL search_path = "' + schema + '"')
                connection.exec_driver_sql("SET LOCAL statement_timeout = '30s'")
                actual_schema = connection.exec_driver_sql('SELECT current_schema()').scalar_one()
                if actual_schema != schema:
                    raise RuntimeError('isolated schema not active; query execution stopped')
            with db.engine.connect() as connection:
                current_schema = connection.execute(text('SELECT current_schema()')).scalar_one()
                if current_schema != schema:
                    raise RuntimeError('database session did not retain the isolated schema')
            sandbox.extensions['migrate'].configure_args['version_table_schema'] = schema
        # The initial Supabase migration explicitly names public. Only the
        # temporary copy is retargeted; the project's migration stays unchanged.
        with tempfile.TemporaryDirectory(prefix='ev-verification-migrations-') as temporary:
            migration_dir = Path(temporary) / 'migrations'
            shutil.copytree(Path(__file__).resolve().parents[1] / 'migrations', migration_dir)
            for migration in (migration_dir / 'versions').glob('*.py'):
                source = migration.read_text(encoding='utf-8')
                source = source.replace('public.', schema + '.').replace('SCHEMA public', 'SCHEMA ' + schema)
                migration.write_text(source, encoding='utf-8')
            with sandbox.app_context():
                upgrade(directory=str(migration_dir))
                with db.engine.connect() as connection:
                    report['checks']['postgres_migration_head'] = connection.execute(text('SELECT version_num FROM alembic_version')).scalar_one()
                    report['checks']['postgres_tables'] = inspect(connection).get_table_names(schema=schema)
        print('Phase: isolated PostgreSQL migrations completed', flush=True)

        users = {}
        emails = {}
        with sandbox.app_context():
            for label, role in [('investigator', 'investigator'), ('other', 'investigator'), ('auditor', 'auditor'), ('admin', 'admin'), ('race', 'investigator')]:
                secret = pyotp.random_base32()
                emails[label] = label + '_' + run_id + '@verification.invalid'
                user = User(name='Verification ' + label, email=emails[label],
                            password_hash=generate_password_hash(password), totp_secret=secret,
                            totp_enabled=label not in {'investigator', 'race'}, role=role)
                db.session.add(user)
                db.session.flush()
                users[label] = (user.id, secret)
            db.session.commit()
        print('Phase: isolated test users created', flush=True)
        clients = {}
        for label in ['investigator', 'other', 'auditor', 'admin']:
            client = sandbox.test_client()
            client.get('/login')
            first = post(client, '/login', {'email': emails[label], 'password': password})
            second = post(client, '/setup-2fa' if label == 'investigator' else '/verify-2fa', {'code': pyotp.TOTP(users[label][1]).now()})
            clients[label] = client
            report['checks']['login_' + label] = {'password_status': first.status_code, 'totp_status': second.status_code, 'dashboard_status': client.get('/dashboard').status_code}
        print('Phase: password and TOTP checked for four roles/users', flush=True)
        investigator = clients['investigator']
        original = b'Evidence Vault real Supabase verification\n'
        post(investigator, '/cases', {'title': 'Temporary verification case', 'files': [
            (io.BytesIO(original), 'notes.txt'), (io.BytesIO(b'%PDF-1.4 verification'), 'document.pdf')]}, content_type='multipart/form-data')
        with sandbox.app_context():
            case = db.session.query(Case).filter_by(owner_id=users['investigator'][0]).one()
            evidence = db.session.query(Evidence).filter_by(case_id=case.id).order_by(Evidence.id).all()
            case_id, evidence_id, key = case.id, evidence[0].id, evidence[0].stored_name
            second_id, second_key = evidence[1].id, evidence[1].stored_name
            report['checks']['upload_count'] = len(evidence)
            report['checks']['stored_sha256_matches'] = evidence[0].sha256 == hashlib.sha256(original).hexdigest()
        download = investigator.get(f'/evidence/{evidence_id}/download')
        report['checks']['real_storage_roundtrip'] = download.status_code == 200 and download.data == original
        report['checks']['verify_status'] = post(investigator, f'/evidence/{evidence_id}/verify').status_code
        report['checks']['permissions'] = {
            'other_investigator_case': clients['other'].get(f'/cases/{case_id}').status_code,
            'other_investigator_download': clients['other'].get(f'/evidence/{evidence_id}/download').status_code,
            'auditor_case': clients['auditor'].get(f'/cases/{case_id}').status_code,
            'auditor_download': clients['auditor'].get(f'/evidence/{evidence_id}/download').status_code,
            'auditor_upload': post(clients['auditor'], f'/cases/{case_id}/upload', {'files': [(io.BytesIO(b'x'), 'x.txt')]}, content_type='multipart/form-data').status_code,
            'auditor_modify_integrity': post(clients['auditor'], f'/evidence/{evidence_id}/verify').status_code,
            'auditor_check_integrity': post(clients['auditor'], f'/evidence/{evidence_id}/check').status_code,
            'admin_case': clients['admin'].get(f'/cases/{case_id}').status_code,
            'investigator_admin_page': investigator.get('/admin/users').status_code,
        }
        print('Phase: real Storage roundtrip and role permissions checked', flush=True)
        cookie_name = sandbox.config['SESSION_COOKIE_NAME']
        saved_cookie = investigator.get_cookie(cookie_name).value
        post(investigator, '/logout')
        replay = sandbox.test_client()
        replay.set_cookie(cookie_name, saved_cookie)
        report['checks']['logout_cookie_replay_dashboard'] = replay.get('/dashboard').status_code
        # Continue with a fresh, authenticated session, never with the revoked
        # cookie. The next-step code is inside the application's TOTP window.
        replay.get('/login')
        post(replay, '/login', {'email': emails['investigator'], 'password': password})
        code = pyotp.TOTP(users['investigator'][1]).at(application_module.utc_now().timestamp() + 30)
        post(replay, '/verify-2fa', {'code': code})
        if replay.get('/dashboard').status_code != 200:
            raise RuntimeError('fresh verification session did not authenticate')

        qualified = namespaced.qualified(key)
        assert qualified in namespaced.keys
        response = raw_storage.client.post(raw_storage._url(qualified), data=b'modified test evidence',
            headers={**raw_storage.headers, 'Content-Type': 'application/octet-stream', 'x-upsert': 'true'}, timeout=(5, 30))
        response.raise_for_status()
        tampered_download = replay.get(f'/evidence/{evidence_id}/download')
        with sandbox.app_context():
            report['checks']['tampered_download_status'] = tampered_download.status_code
            report['checks']['status_after_tamper_detection'] = db.session.get(Evidence, evidence_id).integrity_status
            report['checks']['observed_status_after_tamper_detection'] = db.session.get(Evidence, evidence_id).current_integrity_status
        detail = replay.get(f'/cases/{case_id}').data.decode()
        card = re.search(r'<article class="evidence-card" data-evidence-id="' + str(evidence_id) + r'">(.*?)</article>', detail, re.S).group(1)
        report['checks']['detail_still_claims_verified'] = 'Целостность подтверждена' in card
        report['checks']['detail_contains_modified_warning'] = 'Файл изменён' in card

        namespaced.delete(second_key)
        qualified_missing = namespaced.qualified(second_key)
        with raw_storage.client.get(raw_storage._url(qualified_missing, authenticated=True), headers=raw_storage.headers, timeout=(5, 15), stream=True) as missing:
            report['checks']['real_storage_missing_http_status'] = missing.status_code
            if missing.status_code != 200:
                try:
                    body = missing.json()
                    report['checks']['real_storage_missing_body_code'] = body.get('statusCode')
                except ValueError:
                    pass
        report['checks']['missing_download_status'] = replay.get(f'/evidence/{second_id}/download').status_code
        report['checks']['missing_verify_status'] = post(replay, f'/evidence/{second_id}/verify').status_code
        print('Phase: logout, tampered and missing objects checked', flush=True)

        original_upload = namespaced.upload
        count = 0
        def fail_second(upload_key, content, content_type):
            nonlocal count
            count += 1
            if count == 2:
                raise StorageError('simulated second-file failure')
            return original_upload(upload_key, content, content_type)
        with patch.object(namespaced, 'upload', side_effect=fail_second):
            response = post(replay, '/cases', {'title': 'Temporary partial upload', 'files': [
                (io.BytesIO(b'first'), 'first.txt'), (io.BytesIO(b'second'), 'second.txt')]}, content_type='multipart/form-data')
        with sandbox.app_context():
            partial_case = db.session.query(Case).filter_by(title='Temporary partial upload').one()
            report['checks']['partial_upload'] = {'response': response.status_code, 'persisted_files': db.session.query(Evidence).filter_by(case_id=partial_case.id).count()}
        detail = replay.get(response.location).data.decode() if response.location else ''
        report['checks']['partial_upload']['success_reported'] = 'Загружено файлов: 1' in detail
        report['checks']['partial_upload']['failure_reported'] = 'Не сохранено файлов: 1 — «second.txt»' in detail

        with sandbox.app_context():
            user = db.session.get(User, users['investigator'][0])
            user.has_local_password = False
            user.google_sub = 'verification-only-google-id'
            db.session.commit()
        secret = users['investigator'][1]
        wrong_code = next(f'{number:06}' for number in range(10) if application_module.matching_totp_step(secret, f'{number:06}') is None)
        profile_cookie = replay.get_cookie(cookie_name).value
        profile_statuses = []
        for _ in range(6):
            replay.set_cookie(cookie_name, profile_cookie)
            profile_statuses.append(post(replay, '/account/password', {'new_password': 'NewStrongPass123', 'confirm_password': 'NewStrongPass123', 'code': wrong_code}).status_code)
        with sandbox.app_context():
            user = db.session.get(User, users['investigator'][0])
            report['checks']['profile_totp_failures'] = {'events': db.session.query(AuditLog).filter_by(event_type='PASSWORD_CHANGE_DENIED').count(), 'failed_attempts': user.failed_attempts, 'locked': user.locked_until is not None, 'post_statuses': profile_statuses}
        print('Phase: partial upload and profile TOTP checked', flush=True)

        def race_two(path):
            pair = [sandbox.test_client(), sandbox.test_client()]
            for client in pair:
                client.get('/login')
                post(client, '/login', {'email': emails['race'], 'password': password})
            barrier = threading.Barrier(2, timeout=20)
            original_preauth = application_module.preauth_user
            def synchronized_preauth():
                user = original_preauth()
                barrier.wait()
                return user
            code = pyotp.TOTP(users['race'][1]).now()
            with patch.object(application_module, 'preauth_user', side_effect=synchronized_preauth):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    responses = list(executor.map(lambda client: post(client, path, {'code': code}).status_code, pair))
            return {'post_statuses': responses, 'dashboard_statuses': [client.get('/dashboard').status_code for client in pair]}
        report['checks']['concurrent_totp_enrollment_postgres'] = race_two('/setup-2fa')
        with sandbox.app_context():
            user = db.session.get(User, users['race'][0])
            user.last_totp_step = int(application_module.utc_now().timestamp() // 30) - 2
            db.session.commit()
        report['checks']['concurrent_totp_verification_postgres'] = race_two('/verify-2fa')
        print('Phase: PostgreSQL concurrent TOTP checks completed', flush=True)

        post(clients['admin'], f'/admin/users/{users["other"][0]}/update', {'role': 'investigator'})
        report['checks']['revoked_session_dashboard_status'] = clients['other'].get('/dashboard').status_code
        report['checks']['untrusted_host_status'] = sandbox.test_client().get('/healthz', headers={'Host': 'invalid.example'}).status_code
        checks = report['checks']
        report['assertions'] = {
            'all_four_logins_succeed': all(checks['login_' + label]['dashboard_status'] == 200 for label in ['investigator','other','auditor','admin']),
            'real_storage_roundtrip': checks['real_storage_roundtrip'] and checks['stored_sha256_matches'],
            'roles_enforced': checks['permissions'] == {'other_investigator_case': 404, 'other_investigator_download': 404,
                'auditor_case': 200, 'auditor_download': 200, 'auditor_upload': 403, 'auditor_modify_integrity': 403,
                'auditor_check_integrity': 302, 'admin_case': 200, 'investigator_admin_page': 403},
            'logout_revokes_cookie': checks['logout_cookie_replay_dashboard'] == 302,
            'tamper_visible_and_blocked': checks['tampered_download_status'] == 409
                and checks['observed_status_after_tamper_detection'] == 'modified'
                and checks['detail_contains_modified_warning'] and not checks['detail_still_claims_verified'],
            'missing_object_handled': checks['missing_download_status'] == 404 and checks['missing_verify_status'] == 302,
            'partial_result_visible': checks['partial_upload'] == {'response': 302, 'persisted_files': 1,
                'success_reported': True, 'failure_reported': True},
            'profile_throttled': checks['profile_totp_failures']['locked']
                and checks['profile_totp_failures']['events'] == 5 and checks['profile_totp_failures']['post_statuses'][-1] == 429,
            'enrollment_code_consumed_once': sorted(checks['concurrent_totp_enrollment_postgres']['dashboard_statuses']) == [200,302],
            'verification_code_consumed_once': sorted(checks['concurrent_totp_verification_postgres']['dashboard_statuses']) == [200,302],
            'revocation_enforced': checks['revoked_session_dashboard_status'] == 302,
            'untrusted_host_rejected': checks['untrusted_host_status'] == 400,
        }
        report['completed'] = all(report['assertions'].values())
    except Exception as exc:
        report['completed'] = False
        report['error_type'] = type(exc).__name__
    except KeyboardInterrupt:
        report['completed'] = False
        report['error_type'] = 'Interrupted'
    finally:
        failed_objects = []
        for key in list(namespaced.keys):
            if not key.startswith(namespaced.prefix):
                failed_objects.append(key)
                continue
            try:
                raw_storage.delete(key)
                namespaced.keys.discard(key)
            except StorageError:
                failed_objects.append(key)
        report['cleanup']['remaining_storage_keys'] = failed_objects
        if sandbox is not None:
            with sandbox.app_context():
                db.session.remove()
                db.engine.dispose()
        with production.app_context():
            if schema_created:
                try:
                    assert re.fullmatch(r'ev_verify_[0-9a-f]{12}', schema)
                    with db.engine.begin() as connection:
                        connection.execute(text('DROP SCHEMA "' + schema + '" CASCADE'))
                    report['cleanup']['temporary_schema_removed'] = True
                except Exception as exc:
                    report['cleanup']['temporary_schema_removed'] = False
                    report['cleanup']['schema_error_type'] = type(exc).__name__
            if baseline is not None:
                report['cleanup']['public_counts_unchanged'] = public_counts(db.engine) == baseline
            with db.engine.connect() as connection:
                report['cleanup']['public_test_rows_absent'] = connection.execute(text(
                    "SELECT COUNT(*) FROM public.users WHERE email LIKE :pattern"),
                    {'pattern': '%_' + run_id + '@verification.invalid'}).scalar_one() == 0
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if (report.get('completed') and report['cleanup'].get('temporary_schema_removed')
                 and report['cleanup'].get('public_test_rows_absent')
                 and not report['cleanup']['remaining_storage_keys']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
