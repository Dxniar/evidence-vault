import io
import re
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pyotp
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash

import app as application_module
from models import AuditLog, Case, Evidence, User, db
from storage import StorageError
from tests.common import AppTestCase, MemoryStorage


class SecurityRegressionTestCase(AppTestCase):
    def make_file(self):
        user_id, _ = self.make_user()
        self.assume_session(user_id)
        self.post('/cases', {'title': 'Regression evidence', 'files': [(io.BytesIO(b'original'), 'file.txt')]},
                  content_type='multipart/form-data')
        with self.app.app_context():
            evidence = db.session.scalar(select(Evidence))
            return user_id, evidence.case_id, evidence.id, evidence.stored_name

    def test_logout_revokes_saved_cookie_and_other_devices(self):
        user_id, _ = self.make_user()
        self.assume_session(user_id)
        other = self.app.test_client()
        self.assume_session(user_id, other)
        cookie = self.client.get_cookie('session').value
        self.assertEqual(self.post('/logout').status_code, 302)
        replay = self.app.test_client()
        replay.set_cookie('session', cookie)
        self.assertIn('/login', replay.get('/dashboard').location)
        self.assertIn('/login', other.get('/dashboard').location)

    def test_profile_totp_lockout_survives_saved_cookie_replay(self):
        user_id, secret = self.make_user()
        with self.app.app_context():
            user = db.session.get(User, user_id)
            user.has_local_password = False
            user.google_sub = 'google-regression'
            db.session.commit()
        self.assume_session(user_id)
        cookie = self.client.get_cookie('session').value
        wrong = next(f'{number:06}' for number in range(10)
                     if application_module.matching_totp_step(secret, f'{number:06}') is None)
        for _ in range(5):
            self.client.set_cookie('session', cookie)
            self.assertEqual(self.post('/account/password', {'new_password': 'NewStrongPass123',
                'confirm_password': 'NewStrongPass123', 'code': wrong}).status_code, 302)
        self.client.set_cookie('session', cookie)
        with patch.object(application_module, 'matching_totp_step') as matcher:
            self.assertEqual(self.post('/account/password', {'new_password': 'NewStrongPass123',
                'confirm_password': 'NewStrongPass123', 'code': wrong}).status_code, 429)
            matcher.assert_not_called()
        with self.app.app_context():
            user = db.session.get(User, user_id)
            self.assertGreater(application_module.as_utc(user.locked_until), application_module.utc_now())
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type='PASSWORD_CHANGE_DENIED').count(), 5)

    def test_password_confirmation_errors_share_the_attempt_limit(self):
        from tests.test_google_auth import FakeGoogle
        user_id, _ = self.make_user()
        self.app.extensions['evidence_google_oauth'] = FakeGoogle()
        self.assume_session(user_id)
        cookie = self.client.get_cookie('session').value
        for _ in range(4):
            self.post('/account/password', {'current_password': 'wrong',
                'new_password': 'NewStrongPass123', 'confirm_password': 'NewStrongPass123'})
        self.post('/account/google/connect', {'password': 'wrong'})
        self.client.set_cookie('session', cookie)
        self.assertEqual(self.post('/account/google/connect', {'password': 'StrongPass123'}).status_code, 429)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, user_id).google_sub)

    def test_untrusted_host_returns_400_without_rendering_url_links(self):
        response = self.client.get('/healthz', headers={'Host': 'invalid.example'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('Недоверенный'.encode(), response.data)

    def test_tamper_observation_updates_card_and_dashboard(self):
        _, case_id, evidence_id, key = self.make_file()
        self.storage.objects[key] = b'changed'
        self.assertEqual(self.client.get(f'/evidence/{evidence_id}/download').status_code, 409)
        with self.app.app_context():
            evidence = db.session.get(Evidence, evidence_id)
            self.assertEqual(evidence.current_integrity_status, 'modified')
            self.assertIsNotNone(evidence.integrity_checked_at)
        page = self.client.get(f'/cases/{case_id}').data
        self.assertIn('Файл изменён'.encode(), page)
        self.assertNotIn('Целостность подтверждена'.encode(), page)
        dashboard = self.client.get('/dashboard').data.decode()
        self.assertEqual(re.search(r'<span>Целостность</span>\s*<strong>(\d+)</strong>', dashboard).group(1), '0')

    def test_legacy_hash_without_a_check_is_not_claimed_verified(self):
        _, case_id, evidence_id, _ = self.make_file()
        with self.app.app_context():
            evidence = db.session.get(Evidence, evidence_id)
            evidence.last_verified_at = None
            evidence.observed_integrity_status = None
            evidence.observed_integrity_at = None
            db.session.commit()
        page = self.client.get(f'/cases/{case_id}').data
        self.assertIn('Хеш рассчитан · требуется проверка'.encode(), page)
        self.assertNotIn('Целостность подтверждена'.encode(), page)

    def test_auditor_observes_missing_file_without_changing_manual_status(self):
        _, case_id, evidence_id, key = self.make_file()
        auditor_id, _ = self.make_user(role='auditor')
        self.assume_session(auditor_id)
        self.storage.objects.pop(key)
        self.assertEqual(self.client.get(f'/evidence/{evidence_id}/download').status_code, 404)
        with self.app.app_context():
            evidence = db.session.get(Evidence, evidence_id)
            self.assertEqual(evidence.integrity_status, 'verified')
            self.assertEqual(evidence.current_integrity_status, 'missing')
        self.assertIn('Файл отсутствует'.encode(), self.client.get(f'/cases/{case_id}').data)
        self.storage.objects[key] = b'original'
        self.assertEqual(self.post(f'/evidence/{evidence_id}/check').status_code, 302)
        with self.app.app_context():
            evidence = db.session.get(Evidence, evidence_id)
            self.assertEqual(evidence.current_integrity_status, 'verified')

    def test_partial_upload_reports_success_and_only_the_failed_filename(self):
        user_id, _ = self.make_user()
        self.assume_session(user_id)
        original_upload = self.storage.upload
        def upload(key, data, content_type):
            if data == b'second':
                raise StorageError('failure')
            original_upload(key, data, content_type)
        with patch.object(self.storage, 'upload', side_effect=upload):
            response = self.post('/cases', {'title': 'Partial regression', 'files': [
                (io.BytesIO(b'first'), 'first.txt'), (io.BytesIO(b'second'), 'second.txt'),
                (io.BytesIO(b'third'), 'third.txt')]}, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Загружено файлов: 2'.encode(), response.data)
        self.assertIn('Не сохранено файлов: 1 — «second.txt»'.encode(), response.data)
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 2)
        self.assertEqual(len(self.storage.objects), 2)

    def test_upload_verifies_readback_before_claiming_success(self):
        user_id, _ = self.make_user()
        self.assume_session(user_id)
        with patch.object(self.storage, 'download', return_value=b'corrupted readback'):
            response = self.post('/cases', {'title': 'Readback regression', 'files': [(io.BytesIO(b'original'), 'file.txt')]},
                                 content_type='multipart/form-data', follow_redirects=True)
        self.assertIn('Не сохранено файлов: 1'.encode(), response.data)
        self.assertFalse(self.storage.objects)
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 0)

    def test_lost_commit_reply_does_not_delete_a_committed_file(self):
        user_id, _ = self.make_user()
        self.assume_session(user_id)
        self.post('/cases', {'title': 'Ambiguous commit regression'})
        with self.app.app_context():
            case_id = db.session.scalar(select(Case.id))
        commit = db.session.commit
        attempts = 0
        def commit_then_disconnect():
            nonlocal attempts
            commit()
            attempts += 1
            if attempts == 1:
                raise OperationalError('commit', {}, RuntimeError('lost reply'))
        with patch.object(db.session, 'commit', side_effect=commit_then_disconnect):
            response = self.post(f'/cases/{case_id}/upload', {'files': [(io.BytesIO(b'original'), 'file.txt')]},
                                 content_type='multipart/form-data', follow_redirects=True)
        self.assertIn('Загружено файлов: 1'.encode(), response.data)
        self.assertEqual(len(self.storage.objects), 1)
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 1)

    def test_concurrent_first_enrollment_creates_only_one_session(self):
        with tempfile.TemporaryDirectory(prefix='ev-enrollment-') as temporary:
            secret = pyotp.random_base32()
            application = application_module.create_app({'TESTING': True, 'SECRET_KEY': 'race-secret',
                'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(Path(temporary) / 'race.sqlite'),
                'SQLALCHEMY_ENGINE_OPTIONS': {'connect_args': {'timeout': 15}}, 'STORAGE': MemoryStorage(),
                'SESSION_COOKIE_SECURE': False, 'TRUSTED_HOSTS': ['localhost']})
            with application.app_context():
                db.create_all()
                db.session.add(User(name='Enrollment', email='race@example.com',
                    password_hash=generate_password_hash('StrongPass123'), totp_secret=secret, totp_enabled=False))
                db.session.commit()
            clients = [application.test_client(), application.test_client()]
            tokens = []
            for client in clients:
                client.get('/login')
                with client.session_transaction() as session:
                    csrf = session['csrf_token']
                client.post('/login', data={'email': 'race@example.com', 'password': 'StrongPass123', 'csrf_token': csrf})
                with client.session_transaction() as session:
                    tokens.append(session['csrf_token'])
            original = application_module.preauth_user
            barrier = threading.Barrier(2, timeout=15)
            def synchronize():
                user = original()
                barrier.wait()
                return user
            code = pyotp.TOTP(secret).now()
            with patch.object(application_module, 'preauth_user', side_effect=synchronize):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    list(executor.map(lambda index: clients[index].post('/setup-2fa',
                        data={'csrf_token': tokens[index], 'code': code}), range(2)))
            self.assertEqual(sorted(client.get('/dashboard').status_code for client in clients), [200, 302])
            with application.app_context():
                self.assertEqual(db.session.query(AuditLog).filter_by(event_type='2FA_ENABLED').count(), 1)
                db.session.remove()
                db.engine.dispose()
