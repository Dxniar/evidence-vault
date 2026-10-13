import hashlib
from datetime import datetime, timezone
from unittest.mock import patch

from sqlalchemy import event, select

from models import AuditLog, Case, Evidence, User, db
from reports import export_filename
from tests.common import AppTestCase


class CaseReportTestCase(AppTestCase):
    def make_material(self, title="Материалы осмотра", original_name="протокол.txt"):
        owner_id, _ = self.make_user()
        content = b"evidence content"
        checksum = hashlib.sha256(content).hexdigest()
        with self.app.app_context():
            case = Case(case_number="EV-REPORT-001", title=title, owner_id=owner_id,
                        reference_number="Дело № 42")
            db.session.add(case)
            db.session.flush()
            evidence = Evidence(case_id=case.id, uploaded_by=owner_id,
                                custodian_id=owner_id, original_name=original_name,
                                stored_name="private/secret-object-key", mime_type="text/plain",
                                size_bytes=len(content), sha256=checksum,
                                source_label="Осмотр рабочего компьютера",
                                source_reference="Протокол № 17",
                                acquisition_method="Побитовая копия",
                                acquired_at=datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc),
                                source_sha256=checksum)
            db.session.add(evidence)
            db.session.commit()
            result = owner_id, case.id, evidence.id, checksum
        self.assume_session(owner_id)
        return result

    def test_manifest_describes_exact_bytes_without_reading_storage_or_exposing_secrets(self):
        owner_id, case_id, evidence_id, checksum = self.make_material()
        with self.app.app_context():
            secret = db.session.get(User, owner_id).totp_secret
        with patch.object(self.storage, "download", side_effect=AssertionError("metadata only")):
            response = self.client.get(f"/cases/{case_id}/manifest")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertIn("attachment;", response.headers["Content-Disposition"])
        manifest = response.get_json()
        self.assertEqual(manifest["format_version"], 1)
        self.assertEqual(manifest["case"]["reference_number"], "Дело № 42")
        self.assertEqual(manifest["generated_by"]["id"], owner_id)
        self.assertTrue(manifest["generated_at"].endswith("Z"))
        item = manifest["evidence"][0]
        self.assertEqual(item["id"], evidence_id)
        self.assertEqual(item["sha256"], checksum)
        self.assertEqual(item["size_bytes"], len(b"evidence content"))
        self.assertEqual(item["export_name"], f"{evidence_id}_протокол.txt")
        self.assertEqual(item["source_details"]["acquired_at"], "2026-10-12T10:00:00Z")
        self.assertEqual(item["integrity"], {"status": "not_checked", "checked_at": None,
                                             "checked_during_export": False})
        raw = response.data.decode()
        for forbidden in (secret, "private/secret-object-key", "password_hash", "totp_secret", "stored_name"):
            self.assertNotIn(forbidden, raw)
        with self.app.app_context():
            event = db.session.scalar(select(AuditLog).where(AuditLog.event_type == "MANIFEST_EXPORTED"))
            self.assertEqual(event.case_id, case_id)
            self.assertEqual(event.user_id, owner_id)

    def test_foreign_investigator_cannot_read_reports_or_manifest(self):
        _, case_id, _, _ = self.make_material()
        other_id, _ = self.make_user(email="outside@example.com")
        self.assume_session(other_id)
        for endpoint in ("report", "manifest"):
            response = self.client.get(f"/cases/{case_id}/{endpoint}")
            self.assertIn(response.status_code, (403, 404))
            self.assertNotIn("Материалы осмотра".encode(), response.data)
        with self.app.app_context():
            self.assertEqual(db.session.query(AuditLog).filter(
                AuditLog.event_type.in_(["MANIFEST_EXPORTED", "CASE_REPORT_OPENED"])).count(), 0)

    def test_manifest_scopes_materials_and_includes_transfer_history(self):
        from models import CaseMember, EvidenceTransfer
        owner_id, case_id, evidence_id, checksum = self.make_material()
        recipient_id, _ = self.make_user(email="recipient@example.com")
        with self.app.app_context():
            db.session.add(CaseMember(case_id=case_id, user_id=recipient_id, permission="viewer"))
            db.session.add(EvidenceTransfer(evidence_id=evidence_id, from_user_id=owner_id,
                                           to_user_id=recipient_id, requested_by=owner_id,
                                           status="accepted", reason="Передача эксперту",
                                           decided_at=datetime(2026, 10, 12, 11, 0, tzinfo=timezone.utc)))
            other = Case(case_number="EV-REPORT-OTHER", title="Другой материал", owner_id=owner_id)
            db.session.add(other)
            db.session.flush()
            db.session.add(Evidence(case_id=other.id, uploaded_by=owner_id,
                                   original_name="outside-case.txt", stored_name="outside-key",
                                   mime_type="text/plain", size_bytes=1, sha256=checksum))
            db.session.commit()
        response = self.client.get(f"/cases/{case_id}/manifest")
        self.assertEqual(response.status_code, 200)
        items = response.get_json()["evidence"]
        self.assertEqual([item["id"] for item in items], [evidence_id])
        transfer = items[0]["custody"]["transfers"][0]
        self.assertEqual(transfer["status"], "accepted")
        self.assertEqual(transfer["to"]["id"], recipient_id)
        self.assertEqual(transfer["reason"], "Передача эксперту")
        self.assertEqual(transfer["decided_at"], "2026-10-12T11:00:00Z")
        self.assertNotIn("outside-case.txt", response.data.decode())

    def test_assigned_viewer_can_read_a_case_summary(self):
        from models import CaseMember
        _, case_id, _, _ = self.make_material()
        viewer_id, _ = self.make_user(email="viewer@example.com")
        with self.app.app_context():
            db.session.add(CaseMember(case_id=case_id, user_id=viewer_id, permission="viewer"))
            db.session.commit()
        self.assume_session(viewer_id)
        self.assertEqual(self.client.get(f"/cases/{case_id}/report").status_code, 200)
        self.assertEqual(self.client.get(f"/cases/{case_id}/manifest").status_code, 200)

    def test_report_escapes_user_text_and_does_not_claim_fresh_verification(self):
        _, case_id, _, _ = self.make_material(title="<script>alert('title')</script>",
                                            original_name="<img src=x onerror=alert(1)>.txt")
        response = self.client.get(f"/cases/{case_id}/report")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode()
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img src=x", html)
        self.assertIn("Требуется проверка", html)
        self.assertIn("не является подписанным процессуальным документом", html)
        self.assertIn("Не проводилась", html)
        with self.app.app_context():
            event = db.session.scalar(select(AuditLog).where(AuditLog.event_type == "CASE_REPORT_OPENED"))
            self.assertEqual(event.case_id, case_id)

    def test_report_history_is_scoped_to_this_case_and_keeps_actor_snapshot(self):
        owner_id, case_id, _, _ = self.make_material()
        with self.app.app_context():
            other = Case(case_number="EV-REPORT-002", title="Чужая запись", owner_id=owner_id)
            db.session.add(other)
            db.session.flush()
            db.session.add(AuditLog(user_id=owner_id, case_id=case_id, event_type="CASE_ACTION",
                                   description="Действие внутри дела", actor_name="Историческое имя",
                                   actor_email="old@example.com"))
            db.session.add(AuditLog(user_id=owner_id, case_id=other.id, event_type="SECRET_ACTION",
                                   description="Секретное действие другого дела"))
            db.session.commit()
        html = self.client.get(f"/cases/{case_id}/report").data.decode()
        self.assertIn("Действие внутри дела", html)
        self.assertIn("Историческое имя", html)
        self.assertNotIn("Секретное действие другого дела", html)

    def test_report_query_count_stays_constant_with_many_legacy_authors(self):
        owner_id, case_id, _, _ = self.make_material()

        def add_history(start, count):
            with self.app.app_context():
                owner = db.session.get(User, owner_id)
                for index in range(start, start + count):
                    author = User(name=f"Автор истории {index:03}",
                                  email=f"history-{index}@example.com",
                                  password_hash=owner.password_hash,
                                  totp_secret="JBSWY3DPEHPK3PXP", totp_enabled=True,
                                  role="investigator", is_active=False)
                    db.session.add(author)
                    db.session.flush()
                    # Legacy events lack actor snapshots, so the report must
                    # resolve every different author without lazy SQL queries.
                    db.session.add(AuditLog(user_id=author.id, case_id=case_id,
                                           event_type="LEGACY_HISTORY",
                                           description=f"История действия {index:03}"))
                db.session.commit()

        def measured_report():
            statements = []
            with self.app.app_context():
                engine = db.engine

            def capture(_connection, _cursor, statement, _parameters, _context, _many):
                if statement.lstrip().upper().startswith("SELECT"):
                    statements.append(statement)

            event.listen(engine, "before_cursor_execute", capture)
            try:
                response = self.client.get(f"/cases/{case_id}/report")
            finally:
                event.remove(engine, "before_cursor_execute", capture)
            self.assertEqual(response.status_code, 200)
            return len(statements), response.data.decode()

        add_history(0, 1)
        small_count, small_html = measured_report()
        self.assertIn("Автор истории 000", small_html)
        add_history(1, 40)
        large_count, large_html = measured_report()
        self.assertEqual(large_count, small_count,
                         "Rendering history must not query each event or author after commit")
        self.assertIn("Автор истории 040", large_html)
        self.assertIn("История действия 040", large_html)
        with self.app.app_context():
            self.assertEqual(db.session.query(AuditLog).filter_by(
                case_id=case_id, event_type="CASE_REPORT_OPENED").count(), 2)

    def test_export_filename_is_portable_and_unique_for_long_unsafe_names(self):
        for original in ("../../bad:\\evidence<one>?.txt", "CON", "...", "\x00\n",
                         "Оченьдлинноеимя" * 30 + ".txt"):
            name = export_filename(123, original)
            self.assertTrue(name.startswith("123_"))
            self.assertLessEqual(len(name.encode("utf-8")), 255)
            for forbidden in '/\\<>:"|?*\x00\n':
                self.assertNotIn(forbidden, name)
            self.assertFalse(name.endswith((".", " ")))
        self.assertNotEqual(export_filename(1, "same.txt"), export_filename(2, "same.txt"))

    def test_reports_require_an_authenticated_session(self):
        _, case_id, _, _ = self.make_material()
        anonymous = self.app.test_client()
        for endpoint in ("report", "manifest"):
            response = anonymous.get(f"/cases/{case_id}/{endpoint}")
            self.assertEqual(response.status_code, 302)
            self.assertIn("/login", response.location)

    def test_audit_search_keeps_filters_and_paginates_without_dropping_events(self):
        owner_id, case_id, _, _ = self.make_material()
        with self.app.app_context():
            for index in range(55):
                db.session.add(AuditLog(user_id=owner_id, case_id=case_id, severity="warning",
                                       event_type="REPORT_TEST", description=f"Поисковое событие {index:03}"))
            db.session.add(AuditLog(user_id=owner_id, severity="success", event_type="OTHER",
                                   description="Не должно попасть в фильтр"))
            db.session.commit()
        first = self.client.get("/audit?q=Поисковое&severity=warning").data.decode()
        second = self.client.get("/audit?q=Поисковое&severity=warning&page=2").data.decode()
        self.assertEqual(first.count("<strong>Поисковое событие"), 50)
        self.assertEqual(second.count("<strong>Поисковое событие"), 5)
        self.assertIn("Далее →", first)
        self.assertIn("← Назад", second)
        self.assertIn('name="q" value="Поисковое"', first)
        self.assertNotIn("Не должно попасть в фильтр", first + second)


if __name__ == "__main__":
    import unittest
    unittest.main()
