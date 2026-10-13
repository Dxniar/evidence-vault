"""Opt-in PostgreSQL checks; all writes use a temporary schema and fake Storage.

Run with --run-live inside the configured container. No real Storage operation,
Google sign-in, or write to the public application tables is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import secrets
import shutil
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pyotp
from flask_migrate import upgrade
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError
from werkzeug.security import generate_password_hash

from app import create_app
from models import AuditLog, Case, Evidence, User, db
from tests.common import MemoryStorage

SCHEMA_PATTERN = re.compile(r"ev_casework_[0-9a-f]{12}\Z")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-live", action="store_true", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    schema = "ev_casework_" + secrets.token_hex(6)
    assert SCHEMA_PATTERN.fullmatch(schema)
    report = {"schema": schema, "checks": {}, "observations": {}, "cleanup": {}, "completed": False}
    production = sandbox = None
    baseline, schema_created = None, False

    def counts(engine):
        with engine.connect() as connection:
            return {table: connection.execute(text("SELECT COUNT(*) FROM public." + table)).scalar_one()
                    for table in ("users", "cases", "evidence", "audit_logs")}

    def check(name, passed):
        report["checks"][name] = bool(passed)
        if not passed:
            raise AssertionError(name)

    def authenticated_client(user_id):
        client = sandbox.test_client()
        with sandbox.app_context():
            version = db.session.get(User, user_id).session_version
        with client.session_transaction() as session:
            session.update(user_id=user_id, session_version=version, csrf_token=secrets.token_urlsafe(24))
        return client

    def post(client, path, payload=None, **kwargs):
        with client.session_transaction() as session:
            token = session["csrf_token"]
        return client.post(path, data={"csrf_token": token, **(payload or {})}, **kwargs).status_code

    try:
        report["phase"] = "temporary_schema"
        production = create_app()
        with production.app_context():
            baseline = counts(db.engine)
            database_uri = production.config["SQLALCHEMY_DATABASE_URI"]
            with db.engine.begin() as connection:
                connection.execute(text('CREATE SCHEMA "' + schema + '"'))
                schema_created = True
        memory = MemoryStorage()
        sandbox = create_app({"TESTING": True, "SECRET_KEY": secrets.token_urlsafe(48),
            "READ_PAGE_AUTOCOMMIT": False,  # SET LOCAL namespace guard requires a real transaction.
            "SQLALCHEMY_DATABASE_URI": database_uri,
            "SQLALCHEMY_ENGINE_OPTIONS": {"pool_pre_ping": True, "pool_size": 5, "max_overflow": 2,
                "pool_timeout": 5, "connect_args": {"sslmode": "require", "connect_timeout": 10,
                                                     "application_name": schema}},
            "STORAGE": memory, "SESSION_COOKIE_SECURE": False, "TRUSTED_HOSTS": ["localhost"],
            "GOOGLE_OAUTH_CLIENT_ID": "", "GOOGLE_OAUTH_CLIENT_SECRET": ""})
        with sandbox.app_context():
            @event.listens_for(db.engine, "begin")
            def isolate_transaction(connection):
                connection.exec_driver_sql('SET LOCAL search_path = "' + schema + '"')
                connection.exec_driver_sql("SET LOCAL statement_timeout = '30s'")
                if connection.exec_driver_sql("SELECT current_schema()").scalar_one() != schema:
                    raise RuntimeError("Temporary schema isolation failed")

            sandbox.extensions["migrate"].configure_args["version_table_schema"] = schema
        report["phase"] = "isolated_migrations"
        with tempfile.TemporaryDirectory(prefix="ev-casework-migrations-") as temporary:
            migration_dir = Path(temporary) / "migrations"
            shutil.copytree(Path(__file__).resolve().parents[1] / "migrations", migration_dir)
            for migration in (migration_dir / "versions").glob("*.py"):
                source = migration.read_text(encoding="utf-8")
                migration.write_text(source.replace("public.", schema + ".")
                    .replace("SCHEMA public", "SCHEMA " + schema), encoding="utf-8")
            with sandbox.app_context():
                upgrade(directory=str(migration_dir))
                with db.engine.connect() as connection:
                    check("migration_and_namespace", connection.execute(text("SELECT current_schema()")).scalar_one() == schema
                          and connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "e24b8f0a6c31")

        report["phase"] = "viewer_permissions"
        content = b"Temporary casework fixture"
        digest = hashlib.sha256(content).hexdigest()
        key = "casework-fixture.txt"
        memory.objects[key] = content
        with sandbox.app_context():
            users = []
            for label in ("owner", "viewer"):
                user = User(name="Casework " + label, email=label + "_" + schema + "@casework.invalid",
                    password_hash=generate_password_hash(secrets.token_urlsafe(24)),
                    totp_secret=pyotp.random_base32(), totp_enabled=True, role="investigator")
                db.session.add(user)
                db.session.flush()
                users.append(user.id)
            owner_id, viewer_id = users
            case = Case(case_number="EV-CASEWORK", title="Temporary casework fixture", owner_id=owner_id)
            db.session.add(case)
            db.session.flush()
            evidence = Evidence(case_id=case.id, uploaded_by=owner_id, custodian_id=owner_id,
                original_name="fixture.txt", stored_name=key, mime_type="text/plain",
                size_bytes=len(content), sha256=digest)
            db.session.add(evidence)
            db.session.commit()
            case_id, evidence_id = case.id, evidence.id
        owner, viewer = authenticated_client(owner_id), authenticated_client(viewer_id)
        status = {"grant": post(owner, f"/cases/{case_id}/members", {"user_id": viewer_id,
            "permission": "viewer", "reason": "Temporary permission check"}),
            "view": viewer.get(f"/cases/{case_id}").status_code,
            "upload": post(viewer, f"/cases/{case_id}/upload", {"files": [(io.BytesIO(b"x"), "x.txt")]},
                           content_type="multipart/form-data"),
            "manual_verify": post(viewer, f"/evidence/{evidence_id}/verify"),
            "observe": post(viewer, f"/evidence/{evidence_id}/check")}
        report["observations"]["viewer_http_statuses"] = status
        check("viewer_permissions", status == {"grant": 302, "view": 200, "upload": 403,
                                                "manual_verify": 403, "observe": 302})

        report["phase"] = "concurrent_acceptance"
        check("transfer_requested", post(owner, f"/evidence/{evidence_id}/transfer",
            {"to_user_id": viewer_id, "reason": "Temporary concurrency check"}) == 302)
        with sandbox.app_context():
            from models import EvidenceTransfer
            transfer_id = db.session.scalar(select(EvidenceTransfer.id).where(
                EvidenceTransfer.evidence_id == evidence_id, EvidenceTransfer.status == "pending"))
        pair = [authenticated_client(viewer_id), authenticated_client(viewer_id)]
        barrier = threading.Barrier(2)

        def accept(client):
            barrier.wait(timeout=10)
            return post(client, f"/transfers/{transfer_id}/accept")

        with ThreadPoolExecutor(max_workers=2) as pool:
            acceptance = sorted(pool.map(accept, pair))
        report["observations"]["concurrent_acceptance_statuses"] = acceptance
        with sandbox.app_context():
            accepted_events = list(db.session.scalars(select(AuditLog).where(
                AuditLog.evidence_id == evidence_id, AuditLog.event_type == "CUSTODY_TRANSFER_ACCEPTED")))
            check("exactly_one_acceptance", acceptance == [302, 409]
                  and db.session.get(Evidence, evidence_id).custodian_id == viewer_id and len(accepted_events) == 1)
            audit_id, actor_name = accepted_events[0].id, accepted_events[0].name
            original_audit_description = accepted_events[0].description
            db.session.get(User, viewer_id).name = "Renamed temporary viewer"
            db.session.commit()
            check("actor_snapshot_retained", db.session.get(AuditLog, audit_id).name == actor_name == "Casework viewer")

        report["phase"] = "closed_case"
        closed = {"close": post(owner, f"/cases/{case_id}/status", {"status": "closed", "reason": "Temporary closure check"}),
            "upload": post(owner, f"/cases/{case_id}/upload", {"files": [(io.BytesIO(b"x"), "x.txt")]},
                           content_type="multipart/form-data"),
            "view": viewer.get(f"/cases/{case_id}").status_code,
            "manual_verify": post(owner, f"/evidence/{evidence_id}/verify")}
        report["observations"]["closed_case_http_statuses"] = closed
        with sandbox.app_context():
            evidence = db.session.get(Evidence, evidence_id)
            check("closed_case_permissions_and_observations", closed == {"close": 302, "upload": 409,
                "view": 200, "manual_verify": 302} and evidence.integrity_status == "verified"
                and evidence.last_verified_at is not None and evidence.observed_integrity_status == "verified")

        report["phase"] = "postgres_guards_and_rls"
        failures = []
        with sandbox.app_context():
            statements = [("UPDATE audit_logs SET description = 'Changed' WHERE id = :id", audit_id),
                          ("DELETE FROM audit_logs WHERE id = :id", audit_id),
                          ("UPDATE evidence SET sha256 = :hash WHERE id = :id", evidence_id)]
            for statement, record_id in statements:
                try:
                    with db.engine.begin() as connection:
                        connection.execute(text(statement), {"id": record_id, "hash": "00" * 32})
                except DBAPIError as exc:
                    failures.append(getattr(exc.orig, "sqlstate", None))
                else:
                    failures.append(None)
            with db.engine.connect() as connection:
                same_hash = connection.execute(text("SELECT sha256 FROM evidence WHERE id = :id"),
                                               {"id": evidence_id}).scalar_one() == digest
                same_audit = connection.execute(text("SELECT description FROM audit_logs WHERE id = :id"),
                                                {"id": audit_id}).scalar_one() == original_audit_description
                protected = []
                for table in ("case_members", "evidence_transfers"):
                    privileges = connection.execute(text("SELECT has_table_privilege('anon', :table, 'SELECT')"),
                                                    {"table": schema + "." + table}).scalar_one()
                    rls = connection.execute(text("SELECT relrowsecurity FROM pg_class WHERE oid = CAST(:table AS regclass)"),
                                             {"table": schema + "." + table}).scalar_one()
                    protected.append(rls and not privileges)
            report["observations"]["guard_sqlstates"] = failures
            check("direct_sql_identity_and_audit_guards", failures == ["55000"] * 3 and same_hash and same_audit)
            check("new_tables_rls_and_anon_denied", all(protected))
        report["completed"] = all(report["checks"].values())
        report["phase"] = "completed"
    except Exception as exc:
        report["error_type"] = type(exc).__name__
    except KeyboardInterrupt:
        report["error_type"] = "Interrupted"
    finally:
        if sandbox is not None:
            try:
                with sandbox.app_context():
                    db.session.remove()
                    db.engine.dispose()
            except Exception as exc:
                report["cleanup"]["sandbox_error_type"] = type(exc).__name__
        if production is not None:
            with production.app_context():
                if schema_created:
                    try:
                        if SCHEMA_PATTERN.fullmatch(schema) is None:
                            raise RuntimeError("Refusing unsafe cleanup target")
                        with db.engine.begin() as connection:
                            connection.execute(text('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE'))
                        report["cleanup"]["temporary_schema_removed"] = True
                    except Exception as exc:
                        report["cleanup"]["temporary_schema_removed"] = False
                        report["cleanup"]["schema_error_type"] = type(exc).__name__
                try:
                    report["cleanup"]["public_counts_unchanged"] = baseline is not None and counts(db.engine) == baseline
                except Exception as exc:
                    report["cleanup"]["public_counts_unchanged"] = False
                    report["cleanup"]["counts_error_type"] = type(exc).__name__
                try:
                    db.session.remove()
                    db.engine.dispose()
                except Exception as exc:
                    report["cleanup"]["production_error_type"] = type(exc).__name__
    payload = json.dumps(report, ensure_ascii=True, indent=2) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    cleanup_ok = all(report["cleanup"].get(key) for key in (
        "temporary_schema_removed", "public_counts_unchanged")) and not any(
            key.endswith("_error_type") for key in report["cleanup"])
    return 0 if report["completed"] and cleanup_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
