import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from flask import Flask
from sqlalchemy import event, select
from sqlalchemy.dialects import postgresql

from audit_restore import (AuditRestoreError, RESTORE_EVENT, _restart_postgres_sequence,
                           register_restore, restore_backup)
from models import AuditLog, Case, Evidence, User, db


def archive_bytes(rows, *, corrupt=False):
    journal = b"".join((json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                       for row in rows)
    manifest = {
        "format": "evidence-vault.audit-backup", "format_version": 1,
        "created_at": "2026-10-14T09:10:11Z", "created_by": {"id": 1, "name": "Администратор"},
        "snapshot_max_id": rows[-1]["id"] if rows else 0, "record_count": len(rows),
        "journal_sha256": hashlib.sha256(journal).hexdigest(), "journal_bytes": len(journal),
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False).encode("utf-8"))
        archive.writestr("journal.jsonl", journal + (b"tampered" if corrupt else b""))
    return output.getvalue()


def source_rows():
    common = {
        "user_id": 1, "event_type": "CASE_CREATED", "description": "Исходное событие",
        "severity": "success", "ip_address": "192.0.2.10",
        "created_at": "2026-10-10T03:04:05.123456Z", "actor_name": "Историческое имя",
        "actor_email": "old@example.com", "case_id": 7, "evidence_id": 11,
        "details_json": '{"old":"исходные сведения"}',
    }
    return [{**common, "id": 17}, {**common, "id": 29, "user_id": None,
                                     "actor_name": None, "actor_email": None,
                                     "details_json": "legacy text"}]


class AuditRestoreTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask("audit_restore_isolated_test")
        self.app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
                               SQLALCHEMY_ENGINE_OPTIONS={})
        db.init_app(self.app)
        register_restore(self.app)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        db.session.add(User(id=1, name="Администратор", email="admin@example.com", role="admin",
                            password_hash="test-only", totp_secret="test-only", is_active=True))
        db.session.add(Case(id=7, case_number="RESTORE-7", title="Исходное дело", owner_id=1))
        db.session.add(Evidence(id=11, case_id=7, uploaded_by=1, original_name="original.txt",
                                stored_name="restore/original", mime_type="text/plain",
                                size_bytes=3, sha256="0" * 64))
        db.session.commit()
        self.content = archive_bytes(source_rows())

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def journal(self):
        return db.session.scalars(select(AuditLog).order_by(AuditLog.id)).all()

    def test_restore_preserves_ids_times_snapshots_links_and_records_recovery(self):
        result = restore_backup(self.content, "ADMIN@example.com")
        events = self.journal()
        self.assertEqual([row.id for row in events], [17, 29, 30])
        self.assertEqual(result["record_count"], 2)
        first, second, recovery = events
        self.assertEqual(first.created_at.replace(tzinfo=timezone.utc),
                         datetime(2026, 10, 10, 3, 4, 5, 123456, timezone.utc))
        self.assertEqual((first.user_id, first.case_id, first.evidence_id), (1, 7, 11))
        self.assertEqual(first.actor_name, "Историческое имя")
        self.assertIsNone(second.actor_name)
        self.assertIsNone(second.actor_email)
        self.assertEqual(second.details_json, "legacy text")
        self.assertEqual(recovery.event_type, RESTORE_EVENT)
        self.assertEqual(recovery.actor_email, "admin@example.com")
        self.assertEqual(recovery.ip_address, "CLI")
        details = json.loads(recovery.details_json)
        self.assertEqual(details["journal_sha256"], result["journal_sha256"])
        self.assertEqual(details["snapshot_max_id"], 29)
        # Ordinary application INSERTs continue after all explicit source IDs.
        following = AuditLog(event_type="AFTER_RECOVERY", description="Новая запись")
        db.session.add(following)
        db.session.commit()
        self.assertEqual(following.id, 31)

    def test_nonempty_journal_is_never_merged_replaced_or_deleted(self):
        db.session.add(AuditLog(id=3, event_type="KEEP", description="Существующая запись"))
        db.session.commit()
        with self.assertRaisesRegex(AuditRestoreError, "не пуст"):
            restore_backup(self.content, "admin@example.com")
        self.assertEqual([(row.id, row.event_type) for row in self.journal()], [(3, "KEEP")])

    def test_missing_foreign_keys_refuse_before_any_import_even_without_sqlite_fk(self):
        for field in ("user_id", "case_id", "evidence_id"):
            with self.subTest(field=field):
                rows = source_rows()
                rows[0][field] = 999
                with self.assertRaisesRegex(AuditRestoreError, "Не найдены исходные записи"):
                    restore_backup(archive_bytes(rows), "admin@example.com")
                self.assertEqual(self.journal(), [])

    def test_corrupt_archive_is_rejected_before_opening_a_database_transaction(self):
        engine = Mock()
        engine.begin.side_effect = AssertionError("Database must not be accessed")
        with self.assertRaises(ValueError):
            restore_backup(archive_bytes(source_rows(), corrupt=True), "admin@example.com", engine=engine)
        engine.begin.assert_not_called()

    def test_sequence_failure_rolls_back_import_and_recovery_event_together(self):
        with patch("audit_restore._restart_postgres_sequence", side_effect=RuntimeError("sequence failure")):
            with self.assertRaisesRegex(RuntimeError, "sequence failure"):
                restore_backup(self.content, "admin@example.com")
        self.assertEqual(self.journal(), [])
        # The failed attempt must not prevent a corrected retry.
        self.assertEqual(restore_backup(self.content, "admin@example.com")["restored_event_id"], 30)

    def test_actor_must_be_existing_active_admin(self):
        for email in ("missing@example.com", ""):
            with self.subTest(email=email), self.assertRaises(AuditRestoreError):
                restore_backup(self.content, email)
        db.session.get(User, 1).role = "auditor"
        db.session.commit()
        with self.assertRaises(AuditRestoreError):
            restore_backup(self.content, "admin@example.com")
        self.assertEqual(self.journal(), [])

    def test_repeated_restore_is_refused_and_first_archive_stays_intact(self):
        restore_backup(self.content, "admin@example.com")
        before = [(row.id, row.description) for row in self.journal()]
        with self.assertRaisesRegex(AuditRestoreError, "не пуст"):
            restore_backup(self.content, "admin@example.com")
        self.assertEqual([(row.id, row.description) for row in self.journal()], before)

    def test_cli_verification_is_offline_and_restore_requires_explicit_flag(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.zip"
            path.write_bytes(self.content)
            statements = []

            def record_statement(_connection, _cursor, statement, _parameters, _context, _executemany):
                statements.append(statement)

            event.listen(db.engine, "before_cursor_execute", record_statement)
            try:
                verify = self.app.test_cli_runner().invoke(args=["audit-verify-backup", "--file", str(path)])
                refused = self.app.test_cli_runner().invoke(args=["audit-restore-backup", "--file", str(path),
                                                                 "--actor-email", "admin@example.com"])
            finally:
                event.remove(db.engine, "before_cursor_execute", record_statement)
            self.assertEqual(verify.exit_code, 0, verify.output)
            self.assertIn("Архив проверен", verify.output)
            self.assertNotEqual(refused.exit_code, 0)
            self.assertIn("--confirm-empty", refused.output)
            self.assertEqual(statements, [])
            completed = self.app.test_cli_runner().invoke(args=[
                "audit-restore-backup", "--file", str(path), "--actor-email", "admin@example.com", "--confirm-empty"])
            self.assertEqual(completed.exit_code, 0, completed.output)
            self.assertEqual(len(self.journal()), 3)

    def test_empty_archive_still_leaves_a_recovery_record(self):
        result = restore_backup(archive_bytes([]), "admin@example.com")
        self.assertEqual(result["record_count"], 0)
        self.assertEqual([(row.id, row.event_type) for row in self.journal()], [(1, RESTORE_EVENT)])


class PostgreSQLSequenceTestCase(unittest.TestCase):
    def test_sequence_restart_uses_transactional_ddl_and_quotes_database_identifiers(self):
        connection = Mock()
        connection.dialect = postgresql.dialect()
        connection.execute.return_value.mappings.return_value.one_or_none.return_value = {
            "schema_name": "public", "sequence_name": 'audit"sequence',
        }
        _restart_postgres_sequence(connection, 32)
        commands = [str(call.args[0]) for call in connection.execute.call_args_list]
        self.assertEqual(commands[-1], 'ALTER SEQUENCE public."audit""sequence" RESTART WITH 32')
        self.assertFalse(any("setval" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
