import io

from models import Case, Evidence, User, db
from tests.common import AppTestCase


class PermissionTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        self.admin_id, _ = self.make_user("admin")
        self.investigator_id, _ = self.make_user("investigator")
        self.other_id, _ = self.make_user("investigator", "other@example.com")
        self.auditor_id, _ = self.make_user("auditor")
        with self.app.app_context():
            case = Case(case_number="EV-2026-TEST", title="Чужое дело", owner_id=self.other_id)
            db.session.add(case)
            db.session.commit()
            evidence = Evidence(case_id=case.id, uploaded_by=self.other_id, original_name="file.txt",
                                stored_name="private/file.txt", mime_type="text/plain", size_bytes=4,
                                sha256="00" * 32)
            db.session.add(evidence)
            db.session.commit()
            self.case_id, self.evidence_id = case.id, evidence.id
        self.storage.objects["private/file.txt"] = b"data"

    def test_investigator_cannot_read_or_modify_foreign_case(self):
        self.assume_session(self.investigator_id)
        self.assertEqual(self.client.get(f"/cases/{self.case_id}").status_code, 404)
        self.assertEqual(self.client.get(f"/evidence/{self.evidence_id}/download").status_code, 404)
        self.assertEqual(self.post(f"/cases/{self.case_id}/upload", {"files": [(io.BytesIO(b"a"), "a.txt")]},
                                   content_type="multipart/form-data").status_code, 404)

    def test_auditor_reads_all_but_cannot_write(self):
        self.assume_session(self.auditor_id)
        self.assertEqual(self.client.get(f"/cases/{self.case_id}").status_code, 200)
        self.assertEqual(self.client.get("/audit").status_code, 200)
        self.assertEqual(self.post("/cases", {"title": "Forbidden case"}).status_code, 403)
        self.assertEqual(self.post(f"/cases/{self.case_id}/upload", {"files": [(io.BytesIO(b"a"), "a.txt")]},
                                   content_type="multipart/form-data").status_code, 403)
        self.assertEqual(self.post(f"/evidence/{self.evidence_id}/verify").status_code, 403)
        self.assertEqual(self.post(f"/evidence/{self.evidence_id}/check").status_code, 302)
        with self.app.app_context():
            self.assertEqual(db.session.get(Evidence, self.evidence_id).integrity_status, "verified")

    def test_admin_user_creation_and_revocation(self):
        self.assume_session(self.admin_id)
        response = self.post("/admin/users", {"name": "Новый аудитор", "email": "new@example.com",
                                                  "password": "StrongPass123", "role": "auditor"})
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            user = db.session.query(User).filter_by(email="new@example.com").one()
            new_id = user.id
        self.assertEqual(self.post(f"/admin/users/{new_id}/update", {"role": "investigator"}).status_code, 302)
        with self.app.app_context():
            user = db.session.get(User, new_id)
            self.assertFalse(user.is_active)
            self.assertEqual(user.session_version, 1)

    def test_non_admin_cannot_manage_users(self):
        self.assume_session(self.investigator_id)
        self.assertEqual(self.client.get("/admin/users").status_code, 403)
        self.assertEqual(self.post("/admin/users", {"role": "admin"}).status_code, 403)
