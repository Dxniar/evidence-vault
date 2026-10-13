import hashlib
import io
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sqlalchemy import select

from app import as_utc
from models import AuditLog, Case, CaseMember, Evidence, EvidenceTransfer, User, db, utc_now
from tests.common import AppTestCase


class CaseworkTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        self.owner_id, _ = self.make_user(email="case-owner@example.com")
        self.member_id, _ = self.make_user(email="case-member@example.com")
        self.outsider_id, _ = self.make_user(email="case-outsider@example.com")
        self.content = b"original casework evidence"
        self.original_key = "casework/original.txt"
        self.original_digest = hashlib.sha256(self.content).hexdigest()
        self.storage.objects[self.original_key] = self.content
        with self.app.app_context():
            owner = db.session.get(User, self.owner_id)
            owner.name = "Первоначальное имя владельца"
            case = Case(case_number="EV-CASEWORK", title="Совместное расследование",
                        description="Исходное описание", reference_number="REFERENCE-OLD",
                        priority="normal", owner_id=self.owner_id)
            foreign = Case(case_number="EV-FOREIGN", title="Постороннее закрытое расследование",
                           owner_id=self.outsider_id)
            db.session.add_all([case, foreign])
            db.session.flush()
            evidence = Evidence(case_id=case.id, uploaded_by=self.owner_id, custodian_id=self.owner_id,
                                original_name="original.txt", stored_name=self.original_key,
                                mime_type="text/plain", size_bytes=len(self.content),
                                sha256=self.original_digest)
            db.session.add(evidence)
            db.session.add_all([
                AuditLog(user_id=self.owner_id, actor_name=owner.name, actor_email=owner.email,
                         event_type="CASE_INITIAL_RECORD", description="Событие совместного дела",
                         case_id=case.id),
                AuditLog(user_id=self.outsider_id, event_type="CASE_INITIAL_RECORD",
                         description="СОБЫТИЕ ЧУЖОГО ДЕЛА", case_id=foreign.id),
            ])
            db.session.commit()
            self.case_id, self.foreign_case_id, self.evidence_id = case.id, foreign.id, evidence.id
        self.assume_session(self.owner_id)

    def test_invalid_source_on_creation_does_not_leave_case_or_audit_records(self):
        with self.app.app_context():
            before_cases = db.session.query(Case).count()
            before_events = db.session.query(AuditLog).count()
        for source in ({"acquired_at": "invalid-date"}, {"source_sha256": "invalid-hash"}):
            response = self.post("/cases", {"title": "Проверка неверного источника",
                "files": [(io.BytesIO(b"source"), "source.txt")], **source}, content_type="multipart/form-data")
            self.assertEqual(response.status_code, 400)
        with self.app.app_context():
            self.assertEqual(db.session.query(Case).count(), before_cases)
            self.assertEqual(db.session.query(AuditLog).count(), before_events)

    def test_member_can_be_removed_after_global_role_changes(self):
        self.assertEqual(self.grant("editor").status_code, 302)
        with self.app.app_context():
            user = db.session.get(User, self.member_id)
            user.role = "auditor"
            user.session_version += 1
            db.session.commit()
        self.assume_session(self.owner_id)
        response = self.post(f"/cases/{self.case_id}/members",
            {"user_id": self.member_id, "permission": "remove", "reason": "Изменение должности"})
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertIsNone(db.session.scalar(select(CaseMember).where(
                CaseMember.case_id == self.case_id, CaseMember.user_id == self.member_id)))

    def test_download_filename_matches_export_manifest(self):
        manifest = self.client.get(f"/cases/{self.case_id}/manifest").get_json()
        expected = manifest["evidence"][0]["export_name"]
        response = self.client.get(f"/evidence/{self.evidence_id}/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, self.content)
        self.assertIn(expected, response.headers["Content-Disposition"])

    def grant(self, permission="viewer"):
        self.assume_session(self.owner_id)
        return self.post(f"/cases/{self.case_id}/members", {
            "user_id": self.member_id, "permission": permission, "reason": "Назначение участника дела",
        })

    def upload(self, **source):
        return self.post(f"/cases/{self.case_id}/upload", {
            "files": [(io.BytesIO(b"new case material"), "new-material.txt")], **source,
        }, content_type="multipart/form-data")

    def update_case(self, reason="Уточнение исходных сведений"):
        return self.post(f"/cases/{self.case_id}/update", {
            "title": "Уточнённое совместное расследование", "description": "Новое описание",
            "reference_number": "REFERENCE-NEW", "priority": "high", "reason": reason,
        })

    def status(self, status, reason="Решение ответственного сотрудника"):
        return self.post(f"/cases/{self.case_id}/status", {"status": status, "reason": reason})

    def test_viewer_scope_and_automatic_check_without_editing_original_check(self):
        self.assertEqual(self.grant().status_code, 302)
        self.assume_session(self.member_id)
        cases = self.client.get("/cases").data.decode()
        self.assertIn("Совместное расследование", cases)
        self.assertNotIn("Постороннее закрытое расследование", cases)
        self.assertEqual(self.client.get(f"/cases/{self.case_id}").status_code, 200)
        self.assertEqual(self.client.get(f"/cases/{self.foreign_case_id}").status_code, 404)
        self.assertEqual(self.upload().status_code, 403)
        self.assertEqual(self.post(f"/evidence/{self.evidence_id}/verify").status_code, 403)
        self.assertEqual(self.post(f"/evidence/{self.evidence_id}/check").status_code, 302)
        self.assertEqual(self.client.get(f"/evidence/{self.evidence_id}/download").data, self.content)
        with self.app.app_context():
            evidence = db.session.get(Evidence, self.evidence_id)
            self.assertEqual(evidence.observed_integrity_status, "verified")
            self.assertIsNotNone(evidence.observed_integrity_at)
            self.assertIsNone(evidence.last_verified_at)
            self.assertEqual(evidence.sha256, self.original_digest)

    def test_editor_can_upload_but_cannot_manage_members_status_or_metadata(self):
        self.assertEqual(self.grant("editor").status_code, 302)
        self.assume_session(self.member_id)
        self.assertEqual(self.upload().status_code, 302)
        self.assertEqual(self.update_case().status_code, 403)
        self.assertEqual(self.status("closed").status_code, 403)
        self.assertEqual(self.post(f"/cases/{self.case_id}/members", {
            "user_id": self.outsider_id, "permission": "editor", "reason": "Расширение команды",
        }).status_code, 403)
        with self.app.app_context():
            uploaded = db.session.scalar(select(Evidence).where(Evidence.id != self.evidence_id))
            self.assertEqual(uploaded.uploaded_by, self.member_id)
            self.assertEqual(uploaded.custodian_id, self.member_id)
            self.assertEqual(db.session.get(Case, self.case_id).status, "active")

    def test_revocation_hides_case_and_its_audit_from_former_viewer(self):
        self.grant()
        self.assume_session(self.member_id)
        audit = self.client.get("/audit").data.decode()
        self.assertIn("Событие совместного дела", audit)
        self.assertNotIn("СОБЫТИЕ ЧУЖОГО ДЕЛА", audit)
        self.assume_session(self.owner_id)
        self.assertEqual(self.post(f"/cases/{self.case_id}/members", {
            "user_id": self.member_id, "permission": "remove", "reason": "Участие в деле завершено",
        }).status_code, 302)
        self.assume_session(self.member_id)
        self.assertNotIn("Совместное расследование", self.client.get("/cases").data.decode())
        self.assertNotIn("Событие совместного дела", self.client.get("/audit").data.decode())
        self.assertEqual(self.client.get(f"/cases/{self.case_id}").status_code, 404)
        self.assertEqual(self.client.get(f"/evidence/{self.evidence_id}/download").status_code, 404)
        self.assertEqual(self.post(f"/evidence/{self.evidence_id}/check").status_code, 404)
        with self.app.app_context():
            access = db.session.scalars(select(AuditLog).where(
                AuditLog.event_type == "CASE_ACCESS_CHANGED").order_by(AuditLog.id)).all()
            self.assertEqual(len(access), 2)
            self.assertTrue(all(event.case_id == self.case_id for event in access))
            self.assertEqual(json.loads(access[-1].details_json)["after"], None)

    def test_responsible_member_cannot_be_removed_without_transfer(self):
        self.grant("editor")
        self.assume_session(self.member_id)
        self.upload()
        self.assume_session(self.owner_id)
        self.assertEqual(self.post(f"/cases/{self.case_id}/members", {
            "user_id": self.member_id, "permission": "remove", "reason": "Участие в деле завершено",
        }).status_code, 409)
        with self.app.app_context():
            self.assertIsNotNone(db.session.scalar(select(CaseMember).where(
                CaseMember.case_id == self.case_id, CaseMember.user_id == self.member_id)))

    def test_close_and_reopen_require_reason_and_keep_history(self):
        self.assertEqual(self.status("closed", "").status_code, 400)
        self.assertEqual(self.status("closed", "ab").status_code, 400)
        self.assertEqual(self.status("closed", "Материалы подготовлены к архивированию").status_code, 302)
        with self.app.app_context():
            case = db.session.get(Case, self.case_id)
            self.assertEqual(case.status, "closed")
            self.assertEqual(case.closed_by, self.owner_id)
            self.assertIsNotNone(case.closed_at)
            self.assertEqual(case.closure_reason, "Материалы подготовлены к архивированию")
        self.assertEqual(self.status("closed").status_code, 409)
        self.assertEqual(self.status("active", "").status_code, 400)
        self.assertEqual(self.status("active", "Появились дополнительные материалы").status_code, 302)
        with self.app.app_context():
            case = db.session.get(Case, self.case_id)
            self.assertEqual(case.status, "active")
            self.assertIsNone(case.closed_by)
            self.assertIsNone(case.closed_at)
            events = db.session.scalars(select(AuditLog).where(
                AuditLog.event_type.in_(["CASE_CLOSED", "CASE_REOPENED"])).order_by(AuditLog.id)).all()
            self.assertEqual(len(events), 2)
            self.assertEqual(json.loads(events[0].details_json)["before"], "active")
            self.assertEqual(json.loads(events[1].details_json)["reason"], "Появились дополнительные материалы")

    def test_pending_transfer_blocks_closure_and_recipient_access_removal(self):
        self.grant()
        with self.app.app_context():
            transfer = EvidenceTransfer(evidence_id=self.evidence_id, from_user_id=self.owner_id,
                                        to_user_id=self.member_id, requested_by=self.owner_id,
                                        status="pending", reason="Для исследования материалов")
            db.session.add(transfer)
            db.session.commit()
            transfer_id = transfer.id
        self.assertEqual(self.status("closed").status_code, 409)
        self.assertEqual(self.post(f"/cases/{self.case_id}/members", {
            "user_id": self.member_id, "permission": "remove", "reason": "Участие в деле завершено",
        }).status_code, 409)
        with self.app.app_context():
            self.assertEqual(db.session.get(Case, self.case_id).status, "active")
            transfer = db.session.get(EvidenceTransfer, transfer_id)
            transfer.status = "cancelled"
            transfer.decided_at = utc_now()
            db.session.commit()
        self.assertEqual(self.status("closed").status_code, 302)

    def test_closed_case_keeps_read_and_integrity_checks_but_blocks_changes(self):
        self.grant()
        self.assertEqual(self.status("closed").status_code, 302)
        self.assertEqual(self.upload().status_code, 409)
        self.assertEqual(self.update_case().status_code, 409)
        self.assertEqual(self.post(f"/cases/{self.case_id}/members", {
            "user_id": self.member_id, "permission": "remove", "reason": "Сокращение команды",
        }).status_code, 409)
        self.assertEqual(self.post(f"/evidence/{self.evidence_id}/verify").status_code, 302)
        self.assume_session(self.member_id)
        self.assertEqual(self.client.get(f"/cases/{self.case_id}").status_code, 200)
        self.assertEqual(self.post(f"/evidence/{self.evidence_id}/check").status_code, 302)
        self.assertEqual(self.client.get(f"/evidence/{self.evidence_id}/download").data, self.content)
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 1)

    def test_case_update_records_before_after_reason_and_preserves_original_hash(self):
        self.assertEqual(self.update_case("").status_code, 400)
        self.assertEqual(self.update_case().status_code, 302)
        with self.app.app_context():
            event = db.session.scalar(select(AuditLog).where(AuditLog.event_type == "CASE_UPDATED"))
            details = json.loads(event.details_json)
            self.assertEqual(event.case_id, self.case_id)
            self.assertEqual(details["before"], {
                "title": "Совместное расследование", "description": "Исходное описание",
                "reference_number": "REFERENCE-OLD", "priority": "normal",
            })
            self.assertEqual(details["after"], {
                "title": "Уточнённое совместное расследование", "description": "Новое описание",
                "reference_number": "REFERENCE-NEW", "priority": "high",
            })
            self.assertEqual(details["reason"], "Уточнение исходных сведений")
            self.assertEqual(db.session.get(Evidence, self.evidence_id).sha256, self.original_digest)

    def test_original_hash_and_saved_audit_are_immutable_through_orm(self):
        with self.app.app_context():
            evidence = db.session.get(Evidence, self.evidence_id)
            evidence.sha256 = "ff" * 32
            with self.assertRaises(ValueError):
                db.session.commit()
            db.session.rollback()
            self.assertEqual(db.session.get(Evidence, self.evidence_id).sha256, self.original_digest)
            event = db.session.scalar(select(AuditLog).where(AuditLog.case_id == self.case_id))
            event_id = event.id
            event.description = "Переписанная история"
            with self.assertRaises(ValueError):
                db.session.commit()
            db.session.rollback()
            event = db.session.get(AuditLog, event_id)
            self.assertEqual(event.description, "Событие совместного дела")
            db.session.delete(event)
            with self.assertRaises(ValueError):
                db.session.commit()
            db.session.rollback()
            self.assertIsNotNone(db.session.get(AuditLog, event_id))

    def test_audit_actor_snapshot_survives_employee_rename(self):
        self.update_case()
        with self.app.app_context():
            owner = db.session.get(User, self.owner_id)
            owner.name = "Новое имя владельца"
            owner.email = "renamed-owner@example.com"
            db.session.commit()
            event = db.session.scalar(select(AuditLog).where(AuditLog.event_type == "CASE_UPDATED"))
            self.assertEqual(event.name, "Первоначальное имя владельца")
            self.assertEqual(event.email, "case-owner@example.com")
            self.assertEqual(event.actor_name, "Первоначальное имя владельца")
            self.assertEqual(event.actor_email, "case-owner@example.com")

    def test_source_hash_mismatch_never_uploads_remote_object(self):
        with patch.object(self.storage, "upload", wraps=self.storage.upload) as upload:
            self.assertEqual(self.upload(source_sha256="00" * 32).status_code, 302)
            upload.assert_not_called()
        self.assertEqual(set(self.storage.objects), {self.original_key})
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 1)
            event = db.session.scalar(select(AuditLog).where(AuditLog.event_type == "SOURCE_HASH_MISMATCH"))
            self.assertEqual(event.case_id, self.case_id)

    def test_valid_source_metadata_and_timezone_persist(self):
        digest = hashlib.sha256(b"new case material").hexdigest()
        self.assertEqual(self.upload(
            source_label="Рабочая копия носителя № 42", source_reference="Протокол № 7",
            acquisition_method="Копирование с контрольной проверкой",
            acquired_at="2026-09-01T10:30:00+05:00", source_sha256=digest.upper(),
        ).status_code, 302)
        with self.app.app_context():
            uploaded = db.session.scalar(select(Evidence).where(Evidence.id != self.evidence_id))
            self.assertEqual(uploaded.source_label, "Рабочая копия носителя № 42")
            self.assertEqual(uploaded.source_reference, "Протокол № 7")
            self.assertEqual(uploaded.acquisition_method, "Копирование с контрольной проверкой")
            self.assertEqual(as_utc(uploaded.acquired_at), datetime(2026, 9, 1, 5, 30, tzinfo=timezone.utc))
            self.assertEqual(uploaded.source_sha256, digest)
            self.assertEqual(uploaded.sha256, digest)
            self.assertEqual(uploaded.custodian_id, self.owner_id)
            event = db.session.scalar(select(AuditLog).where(AuditLog.event_type == "EVIDENCE_UPLOADED"))
            self.assertEqual(event.evidence_id, uploaded.id)
            self.assertEqual(json.loads(event.details_json)["acquired_at"], "2026-09-01T05:30:00+00:00")

    def test_future_or_invalid_source_metadata_is_rejected_before_storage(self):
        future = (utc_now() + timedelta(days=1)).isoformat()
        for metadata in ({"acquired_at": future}, {"acquired_at": "unknown date"},
                         {"source_sha256": "not-a-sha256"}, {"source_label": "x" * 501}):
            with self.subTest(metadata=list(metadata)):
                with patch.object(self.storage, "upload", wraps=self.storage.upload) as upload:
                    self.assertEqual(self.upload(**metadata).status_code, 400)
                    upload.assert_not_called()
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 1)

    def test_case_closure_during_storage_readback_cleans_unpublished_object(self):
        original_download = self.storage.download

        def close_case(key, maximum):
            content = original_download(key, maximum)
            with self.app.app_context():
                db.session.get(Case, self.case_id).status = "closed"
                db.session.commit()
            return content

        with patch.object(self.storage, "download", side_effect=close_case):
            self.assertEqual(self.upload().status_code, 409)
        self.assertEqual(set(self.storage.objects), {self.original_key})
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 1)
            self.assertEqual(db.session.get(Case, self.case_id).status, "closed")
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="EVIDENCE_UPLOADED").count(), 0)

    def test_account_revocation_during_storage_readback_cleans_unpublished_object(self):
        original_download = self.storage.download

        def revoke_actor(key, maximum):
            content = original_download(key, maximum)
            with self.app.app_context():
                actor = db.session.get(User, self.owner_id)
                actor.is_active = False
                actor.session_version += 1
                db.session.commit()
            return content

        with patch.object(self.storage, "download", side_effect=revoke_actor):
            self.assertEqual(self.upload().status_code, 403)
        self.assertEqual(set(self.storage.objects), {self.original_key})
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 1)
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="EVIDENCE_UPLOADED").count(), 0)
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_edit_permission_revocation_during_storage_readback_cleans_unpublished_object(self):
        self.grant("editor")
        self.assume_session(self.member_id)
        original_download = self.storage.download

        def remove_editor(key, maximum):
            content = original_download(key, maximum)
            with self.app.app_context():
                db.session.query(CaseMember).filter_by(case_id=self.case_id, user_id=self.member_id).delete()
                db.session.commit()
            return content

        with patch.object(self.storage, "download", side_effect=remove_editor):
            self.assertEqual(self.upload().status_code, 404)
        self.assertEqual(set(self.storage.objects), {self.original_key})
        with self.app.app_context():
            self.assertEqual(db.session.query(Evidence).count(), 1)
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="EVIDENCE_UPLOADED").count(), 0)
