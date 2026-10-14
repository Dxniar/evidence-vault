import csv
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from unittest.mock import patch

from flask import g
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

import audit_archive
from audit_archive import (AuditArchiveError, BACKUP_EVENT, backup_catalog, build_backup,
                           event_record, read_verified_backup)
from models import AuditLog, User, db
from storage import StorageError
from tests.common import AppTestCase


class AuditArchiveTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        if "audit_archive" not in self.app.blueprints:
            audit_archive.register_audit_archive(self.app)
        self.admin_id, _ = self.make_user("admin")
        self.assume_session(self.admin_id)

    def seed_events(self, count=1, **values):
        with self.app.app_context():
            ids = []
            for index in range(count):
                row = AuditLog(user_id=self.admin_id, event_type="TEST_EVENT",
                               description=f"Событие {index}", severity="info",
                               actor_name="Данияр", actor_email="admin@example.com",
                               created_at=datetime(2026, 10, 14, 8, 0, index % 60, tzinfo=timezone.utc))
                for key, value in values.items():
                    setattr(row, key, value)
                db.session.add(row)
                db.session.flush()
                ids.append(row.id)
            db.session.commit()
            return ids

    def backup_event(self):
        with self.app.app_context():
            event = db.session.scalar(select(AuditLog).where(AuditLog.event_type == BACKUP_EVENT)
                                      .order_by(AuditLog.id.desc()))
            return event.id, json.loads(event.details_json)

    def standalone_archive(self):
        self.seed_events(3, details_json='{"значение":"исходные данные"}')
        with self.app.app_context():
            rows = db.session.scalars(select(AuditLog).order_by(AuditLog.id)).all()
            expected = [event_record(row) for row in rows]
            content, manifest = build_backup(rows, snapshot_max_id=rows[-1].id,
                                             created_by={"id": self.admin_id, "name": "Админ"})
        return content, manifest, expected

    def rewrite_archive(self, content, *, manifest_change=None, journal_change=None, extra=None):
        with zipfile.ZipFile(io.BytesIO(content)) as source:
            payload = source.read("journal.jsonl")
            manifest = json.loads(source.read("manifest.json"))
        if manifest_change:
            manifest_change(manifest)
        if journal_change:
            payload = journal_change(payload)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            archive.writestr("journal.jsonl", payload)
            if extra:
                archive.writestr(extra, b"unexpected")
        return output.getvalue()

    def test_csv_exports_all_filtered_rows_beyond_one_page_and_audits_exact_count(self):
        self.seed_events(63, severity="warning", description="Фильтр 100%_тест")
        self.seed_events(2, severity="warning", description="Фильтр 100протест")
        self.seed_events(1, severity="danger", description="Фильтр 100%_тест")
        response = self.post("/audit/export", {"q": "100%_тест", "severity": "warning"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b"\xef\xbb\xbf"))
        rows = list(csv.reader(io.StringIO(response.data.decode("utf-8-sig")), delimiter=";"))
        self.assertEqual(len(rows), 64)
        self.assertTrue(all(row[3] == "warning" for row in rows[1:]))
        self.assertIn("attachment;", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        with self.app.app_context():
            event = db.session.scalar(select(AuditLog).where(AuditLog.event_type == "AUDIT_EXPORTED"))
            metadata = json.loads(event.details_json)
            self.assertEqual(metadata["record_count"], 63)
            self.assertEqual(metadata["sha256"], hashlib.sha256(response.data).hexdigest())
            self.assertNotIn("100%_тест", event.details_json)

    def test_csv_neutralizes_formulas_in_every_text_field(self):
        self.seed_events(actor_name="=HYPERLINK(\"evil\")", actor_email=" +SUM(A1)",
                         event_type="@DANGEROUS", description="\t=1+1", ip_address="-1+2",
                         details_json="\n=BAD")
        response = self.post("/audit/export")
        row = list(csv.reader(io.StringIO(response.data.decode("utf-8-sig")), delimiter=";"))[1]
        for index in (2, 4, 5, 6, 10, 11):
            self.assertTrue(row[index].startswith("'"), (index, row[index]))

    def test_export_is_admin_or_auditor_only_and_backup_is_admin_only(self):
        self.seed_events()
        self.assertEqual(self.post("/audit/backups").status_code, 302)
        event_id, _ = self.backup_event()
        for role in ("auditor", "investigator"):
            user_id, _ = self.make_user(role)
            self.assume_session(user_id)
            self.assertEqual(self.post("/audit/export").status_code, 200 if role == "auditor" else 403)
            self.assertEqual(self.post("/audit/backups").status_code, 403)
            self.assertEqual(self.post(f"/audit/backups/{event_id}/download").status_code, 403)
        self.assertEqual(len(self.storage.objects), 1)

    def test_csrf_and_post_are_required_for_export_and_backup(self):
        for path in ("/audit/export", "/audit/backups", "/audit/backups/1/download"):
            self.assertEqual(self.client.post(path).status_code, 400)
            self.assertEqual(self.client.get(path).status_code, 405)
        self.assertFalse(self.storage.objects)

    def test_csv_limit_rejects_whole_export_without_success_event(self):
        self.seed_events(3)
        with patch.object(audit_archive, "MAX_RECORDS", 2):
            response = self.post("/audit/export")
        self.assertEqual(response.status_code, 413)
        self.assertNotIn("Content-Disposition", response.headers)
        with self.app.app_context():
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="AUDIT_EXPORTED").count(), 0)

    def test_backup_preserves_exact_records_and_metadata_sha256(self):
        self.seed_events(55, details_json=' { "данные": "не преобразовывать" } ')
        with self.app.app_context():
            expected = [event_record(row) for row in db.session.scalars(select(AuditLog).order_by(AuditLog.id))]
        response = self.post("/audit/backups")
        self.assertEqual(response.status_code, 302)
        event_id, metadata = self.backup_event()
        self.assertRegex(metadata["storage_key"], r"^audit-backups/[a-f0-9]{32}\.zip$")
        content = self.storage.objects[metadata["storage_key"]]
        manifest, records = read_verified_backup(content)
        self.assertEqual(records, expected)
        self.assertEqual(metadata["snapshot_max_id"], expected[-1]["id"])
        self.assertGreater(event_id, metadata["snapshot_max_id"])
        self.assertEqual(manifest["record_count"], 55)
        self.assertEqual(metadata["archive_sha256"], hashlib.sha256(content).hexdigest())
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            self.assertEqual(set(archive.namelist()), {"manifest.json", "journal.jsonl"})
            self.assertEqual(metadata["journal_sha256"], hashlib.sha256(archive.read("journal.jsonl")).hexdigest())
        response = self.post(f"/audit/backups/{event_id}/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, content)
        with self.app.app_context():
            event = db.session.scalar(select(AuditLog).where(AuditLog.event_type == "AUDIT_BACKUP_DOWNLOADED"))
            self.assertEqual(json.loads(event.details_json)["backup_event_id"], event_id)

    def test_empty_journal_backup_is_valid(self):
        self.assertEqual(self.post("/audit/backups").status_code, 302)
        _, metadata = self.backup_event()
        manifest, records = read_verified_backup(self.storage.objects[metadata["storage_key"]])
        self.assertEqual((manifest["record_count"], manifest["snapshot_max_id"], records), (0, 0, []))

    def test_catalog_recovered_from_database_not_process_memory_and_paginates(self):
        self.seed_events()
        self.post("/audit/backups")
        first_id, _ = self.backup_event()
        self.post("/audit/backups")
        second_id, _ = self.backup_event()
        with self.app.test_request_context():
            g.user = db.session.get(User, self.admin_id)
            self.assertEqual([row["event_id"] for row in backup_catalog(limit=1)], [second_id])
            self.assertEqual([row["event_id"] for row in backup_catalog(limit=1, offset=1)], [first_id])
        self.assertEqual(self.post(f"/audit/backups/{first_id}/download").status_code, 200)

    def test_failed_storage_does_not_publish_catalog_or_leave_uploaded_object(self):
        self.seed_events()
        for failure in ("upload", "download"):
            with self.subTest(failure=failure):
                with patch.object(self.storage, failure, side_effect=StorageError("secret must not be exposed")):
                    response = self.post("/audit/backups")
                self.assertEqual(response.status_code, 503)
                self.assertNotIn(b"secret must not be exposed", response.data)
                self.assertFalse(self.storage.objects)
                with self.app.app_context():
                    self.assertEqual(db.session.query(AuditLog).filter_by(event_type=BACKUP_EVENT).count(), 0)

    def test_corrupted_readback_not_catalogued_and_cleaned(self):
        self.seed_events()
        with patch.object(self.storage, "download", return_value=b"corrupted"):
            response = self.post("/audit/backups")
        self.assertEqual(response.status_code, 503)
        self.assertFalse(self.storage.objects)
        with self.app.app_context():
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type=BACKUP_EVENT).count(), 0)

    def test_committed_backup_survives_lost_commit_reply(self):
        self.seed_events()
        commit = db.session.commit
        def lost_reply():
            commit()
            raise OperationalError("commit", {}, RuntimeError("connection lost"))
        with patch.object(db.session, "commit", side_effect=lost_reply):
            response = self.post("/audit/backups")
        self.assertEqual(response.status_code, 302)
        event_id, metadata = self.backup_event()
        self.assertIn(metadata["storage_key"], self.storage.objects)
        self.assertEqual(self.post(f"/audit/backups/{event_id}/download").status_code, 200)

    def test_failed_database_commit_does_not_leave_orphaned_backup(self):
        self.seed_events()
        with patch.object(db.session, "commit", side_effect=OperationalError("commit", {}, RuntimeError("lost"))):
            response = self.post("/audit/backups")
        self.assertEqual(response.status_code, 503)
        self.assertFalse(self.storage.objects)
        with self.app.app_context():
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type=BACKUP_EVENT).count(), 0)

    def test_download_rejects_corrupted_object_without_success_event(self):
        self.seed_events()
        self.post("/audit/backups")
        event_id, metadata = self.backup_event()
        self.storage.objects[metadata["storage_key"]] += b"bad"
        self.assertEqual(self.post(f"/audit/backups/{event_id}/download").status_code, 503)
        with self.app.app_context():
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="AUDIT_BACKUP_DOWNLOADED").count(), 0)

    def test_download_checks_fresh_role_after_storage_read(self):
        self.seed_events()
        self.post("/audit/backups")
        event_id, _ = self.backup_event()
        download = self.storage.download
        def revoke_then_read(key, max_bytes):
            with self.app.app_context():
                user = db.session.get(User, self.admin_id)
                user.role = "investigator"
                db.session.commit()
            return download(key, max_bytes)
        with patch.object(self.storage, "download", side_effect=revoke_then_read):
            self.assertEqual(self.post(f"/audit/backups/{event_id}/download").status_code, 403)
        with self.app.app_context():
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="AUDIT_BACKUP_DOWNLOADED").count(), 0)

    def test_create_checks_fresh_role_after_storage_read_and_cleans_object(self):
        self.seed_events()
        download = self.storage.download
        def revoke_then_read(key, max_bytes):
            with self.app.app_context():
                user = db.session.get(User, self.admin_id)
                user.is_active = False
                db.session.commit()
            return download(key, max_bytes)
        with patch.object(self.storage, "download", side_effect=revoke_then_read):
            self.assertEqual(self.post("/audit/backups").status_code, 403)
        self.assertFalse(self.storage.objects)
        with self.app.app_context():
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type=BACKUP_EVENT).count(), 0)

    def test_backup_size_limit_fails_before_storage_without_truncation(self):
        self.seed_events(3)
        with patch.object(audit_archive, "MAX_RECORDS", 2):
            self.assertEqual(self.post("/audit/backups").status_code, 413)
        self.assertFalse(self.storage.objects)

    def test_verifier_is_offline_and_preserves_raw_values(self):
        content, manifest, expected = self.standalone_archive()
        with patch.object(self.storage, "download", side_effect=AssertionError("offline")):
            actual_manifest, records = read_verified_backup(content)
        self.assertEqual(actual_manifest, manifest)
        self.assertEqual(records, expected)

    def test_verifier_rejects_bad_hash_manifest_count_dates_and_record_types(self):
        content, _, _ = self.standalone_archive()
        changes = [lambda m: m.update(record_count=2), lambda m: m.update(format_version=True),
                   lambda m: m.update(created_at="2026-01-01"), lambda m: m.update(snapshot_max_id=99),
                   lambda m: m.update(journal_sha256="0" * 64), lambda m: m.update(created_by={"id": True, "name": "x"})]
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(AuditArchiveError):
                    read_verified_backup(self.rewrite_archive(content, manifest_change=change))
        with self.assertRaises(AuditArchiveError):
            read_verified_backup(self.rewrite_archive(content, journal_change=lambda value: value + b"x"))
        with self.assertRaises(AuditArchiveError):
            read_verified_backup(self.rewrite_archive(content, extra="../unexpected.txt"))
        with self.assertRaises(AuditArchiveError):
            read_verified_backup(b"not a zip")

    def test_verifier_rejects_uncompressed_size_before_reading_large_payload(self):
        content, _, _ = self.standalone_archive()
        with patch.object(audit_archive, "MAX_UNCOMPRESSED_BYTES", 10):
            with self.assertRaises(AuditArchiveError):
                read_verified_backup(content)

    def test_verifier_checks_record_schema_even_when_hash_matches(self):
        content, _, expected = self.standalone_archive()
        for change in (lambda rows: rows[0].update(id=True),
                       lambda rows: rows[1].update(id=rows[0]["id"]),
                       lambda rows: rows[0].update(created_at="2026-01-01T00:00:00+05:00"),
                       lambda rows: rows[0].update(password_hash="must not be a field"),
                       lambda rows: rows[0].update(actor_name="x" * 121)):
            rows = [dict(row) for row in expected]
            change(rows)
            payload = b"".join(json.dumps(row, ensure_ascii=False).encode() + b"\n" for row in rows)
            def update_manifest(manifest):
                manifest["journal_bytes"] = len(payload)
                manifest["journal_sha256"] = hashlib.sha256(payload).hexdigest()
            altered = self.rewrite_archive(content, manifest_change=update_manifest,
                                           journal_change=lambda _value: payload)
            with self.subTest(change=change), self.assertRaises(AuditArchiveError):
                read_verified_backup(altered)

    def test_catalog_is_not_available_to_auditor_or_investigator(self):
        self.seed_events()
        self.post("/audit/backups")
        for role in ("auditor", "investigator"):
            user_id, _ = self.make_user(role)
            with self.app.test_request_context():
                g.user = db.session.get(User, user_id)
                from werkzeug.exceptions import Forbidden
                with self.assertRaises(Forbidden):
                    backup_catalog()

    def test_compressed_and_uncompressed_limits_reject_before_upload(self):
        self.seed_events(2)
        for name in ("MAX_ARCHIVE_BYTES", "MAX_UNCOMPRESSED_BYTES"):
            with self.subTest(limit=name), patch.object(audit_archive, name, 10):
                self.assertEqual(self.post("/audit/backups").status_code, 413)
                self.assertFalse(self.storage.objects)

