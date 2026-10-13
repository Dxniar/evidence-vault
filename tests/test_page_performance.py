import hashlib
import re
from unittest.mock import patch

from flask import template_rendered
from sqlalchemy import event

from models import AuditLog, Case, CaseMember, Evidence, EvidenceTransfer, User, db, utc_now
from tests.common import AppTestCase


class PagePerformanceTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        self.owner_id, _ = self.make_user(email="performance-owner@example.com")
        self.assume_session(self.owner_id)
        with self.app.app_context():
            case = Case(case_number="EV-PERFORMANCE", title="Проверка скорости", owner_id=self.owner_id)
            db.session.add(case)
            db.session.commit()
            self.case_id = case.id

    def measured_get(self, path):
        with self.app.app_context():
            engine = db.engine
        queries = []

        def record(_connection, _cursor, statement, _parameters, _context, _many):
            if statement.lstrip().upper().startswith(("SELECT", "WITH")):
                queries.append(statement)

        event.listen(engine, "before_cursor_execute", record)
        try:
            response = self.client.get(path)
            body = response.get_data()
            status = response.status_code
            response.close()
            return status, body, len(queries)
        finally:
            event.remove(engine, "before_cursor_execute", record)

    def add_people_and_materials(self, start, count):
        with self.app.app_context():
            for number in range(start, start + count):
                person = User(name=f"Сотрудник скорости {number}", email=f"speed-{number}@example.com",
                              password_hash="test-fixture", totp_secret="A" * 32,
                              totp_enabled=True, role="investigator")
                db.session.add(person)
                db.session.flush()
                db.session.add(CaseMember(case_id=self.case_id, user_id=person.id, permission="viewer"))
                evidence = Evidence(case_id=self.case_id, uploaded_by=self.owner_id,
                                    custodian_id=person.id, original_name=f"source-{number}.txt",
                                    stored_name=f"performance/{number}.txt", mime_type="text/plain",
                                    size_bytes=1, sha256=hashlib.sha256(b"x").hexdigest())
                db.session.add(evidence)
                db.session.flush()
                db.session.add(EvidenceTransfer(evidence_id=evidence.id, from_user_id=person.id,
                                               to_user_id=self.owner_id, requested_by=person.id,
                                               reason="Тестовая передача"))
                db.session.add(AuditLog(user_id=person.id, case_id=self.case_id,
                                       event_type="PERFORMANCE_FIXTURE", description=f"Событие {number}"))
            db.session.commit()

    def test_static_resources_work_without_database_and_do_not_revoke_session(self):
        with patch.object(db.session, "get", side_effect=AssertionError("Static must not read users")):
            for filename in ("style.css", "theme.js", "app.js", "favicon.svg"):
                status, _, query_count = self.measured_get(f"/static/{filename}")
                self.assertEqual(status, 200)
                self.assertEqual(query_count, 0)
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_id"], self.owner_id)

    def test_versioned_assets_are_cached_but_private_pages_are_not(self):
        response = self.client.get("/account")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        links = re.findall(rb'(/static/[^"\s]+\?v=[a-f0-9]{12})', response.data)
        self.assertEqual(len(links), 4)
        for link in links:
            asset = self.client.get(link.decode())
            self.assertIn("immutable", asset.headers["Cache-Control"])
            self.assertIn("max-age=31536000", asset.headers["Cache-Control"])
            self.assertNotIn("Cookie", asset.headers.get("Vary", ""))
            conditional = self.client.get(link.decode(), headers={"If-None-Match": asset.headers["ETag"]})
            self.assertEqual(conditional.status_code, 304)
            conditional.close()
            asset.close()
        unversioned = self.client.get("/static/style.css")
        self.assertNotIn("immutable", unversioned.headers["Cache-Control"])
        unversioned.close()

    def test_case_queries_do_not_grow_with_people_files_and_history(self):
        self.add_people_and_materials(1, 1)
        status, _, small_count = self.measured_get(f"/cases/{self.case_id}")
        self.assertEqual(status, 200)
        self.add_people_and_materials(2, 20)
        status, body, large_count = self.measured_get(f"/cases/{self.case_id}")
        self.assertEqual(status, 200)
        self.assertIn("Сотрудник скорости 21".encode(), body)
        self.assertEqual(large_count, small_count)
        self.assertLessEqual(large_count, 7)

    def test_audit_queries_do_not_grow_with_legacy_authors(self):
        self.add_people_and_materials(1, 1)
        status, _, small_count = self.measured_get("/audit")
        self.assertEqual(status, 200)
        self.add_people_and_materials(2, 20)
        status, body, large_count = self.measured_get("/audit")
        self.assertEqual(status, 200)
        self.assertIn("Сотрудник скорости 21".encode(), body)
        self.assertEqual(large_count, small_count)
        self.assertLessEqual(large_count, 2)

    def test_dashboard_counts_include_shared_cases_and_exclude_hidden_and_unchecked_files(self):
        other_id, _ = self.make_user(email="performance-other@example.com")
        with self.app.app_context():
            shared = Case(case_number="EV-SHARED-SPEED", title="Совместное дело", owner_id=other_id)
            hidden = Case(case_number="EV-HIDDEN-SPEED", title="Скрытое дело", owner_id=other_id)
            db.session.add_all([shared, hidden])
            db.session.flush()
            db.session.add(CaseMember(case_id=shared.id, user_id=self.owner_id, permission="viewer"))
            for number, (case_id, checked, observed) in enumerate([
                (self.case_id, True, None), (shared.id, False, None),
                (shared.id, True, "modified"), (hidden.id, True, None)
            ]):
                db.session.add(Evidence(case_id=case_id, uploaded_by=other_id,
                    original_name=f"stat-{number}.txt", stored_name=f"stats/{number}.txt",
                    mime_type="text/plain", size_bytes=1, sha256=hashlib.sha256(b"x").hexdigest(),
                    last_verified_at=utc_now() if checked else None,
                    observed_integrity_status=observed, observed_integrity_at=utc_now() if observed else None))
            db.session.commit()
        rendered = {}

        def capture(_sender, template, context, **_extra):
            if template.name == "dashboard.html":
                rendered.update({key: context[key] for key in ("case_count", "evidence_count", "verified_count")})

        template_rendered.connect(capture, self.app)
        try:
            status, _, query_count = self.measured_get("/dashboard")
        finally:
            template_rendered.disconnect(capture, self.app)
        self.assertEqual(status, 200)
        self.assertEqual(rendered, {"case_count": 2, "evidence_count": 3, "verified_count": 1})
        self.assertLessEqual(query_count, 4)

