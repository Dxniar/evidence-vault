import hashlib
import io

from sqlalchemy import select

from models import Case, Evidence, db
from tests.common import AppTestCase


class EvidenceUploadTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        user_id, _ = self.make_user()
        self.assume_session(user_id)

    def test_upload_verify_download_and_tamper_block(self):
        first = b"first evidence"
        second = b"%PDF-1.4 second evidence"
        response = self.post("/cases", {"title": "Проверка загрузки", "priority": "high",
                         "files": [(io.BytesIO(first), "notes.txt"), (io.BytesIO(second), "document.pdf")]},
                         content_type="multipart/form-data")
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            case = db.session.scalar(select(Case))
            evidence = db.session.scalars(select(Evidence).order_by(Evidence.id)).all()
            self.assertEqual(len(evidence), 2)
            self.assertEqual(evidence[0].sha256, hashlib.sha256(first).hexdigest())
            case_id, evidence_id, key = case.id, evidence[0].id, evidence[0].stored_name
        self.assertEqual(self.client.get(f"/cases/{case_id}").status_code, 200)
        self.assertEqual(self.client.get(f"/evidence/{evidence_id}/download").data, first)
        self.assertEqual(self.post(f"/evidence/{evidence_id}/verify").status_code, 302)
        self.storage.objects[key] = b"tampered"
        self.assertEqual(self.client.get(f"/evidence/{evidence_id}/download").status_code, 409)
        self.post(f"/evidence/{evidence_id}/verify")
        with self.app.app_context():
            self.assertEqual(db.session.get(Evidence, evidence_id).integrity_status, "modified")

    def test_unsupported_file_does_not_enter_storage(self):
        response = self.post("/cases", {"title": "Проверка формата", "priority": "normal",
                         "files": [(io.BytesIO(b"binary"), "program.exe")]},
                         content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("неподдерживаемый тип".encode(), response.data)
        self.assertFalse(self.storage.objects)
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 0)

    def test_bad_priority_is_rejected(self):
        self.post("/cases", {"title": "Valid title", "priority": "<script>"})
        with self.app.app_context():
            self.assertEqual(db.session.query(Case).count(), 0)
