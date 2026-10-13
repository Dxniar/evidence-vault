from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import select

from models import AuditLog, Case, CaseMember, Evidence, EvidenceTransfer, User, db
from tests.common import AppTestCase


class CustodyTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        self.owner_id, _ = self.make_user(email="owner@example.com")
        self.recipient_id, _ = self.make_user(email="recipient@example.com")
        self.outsider_id, _ = self.make_user(email="outsider@example.com")
        self.admin_id, _ = self.make_user("admin")
        self.auditor_id, _ = self.make_user("auditor")
        with self.app.app_context():
            case = Case(case_number="EV-CUSTODY", title="Проверка передачи", owner_id=self.owner_id)
            db.session.add(case)
            db.session.flush()
            db.session.add(CaseMember(case_id=case.id, user_id=self.recipient_id, permission="viewer"))
            evidence = Evidence(case_id=case.id, uploaded_by=self.owner_id,
                                custodian_id=self.owner_id, original_name="original.txt",
                                stored_name="custody/original.txt", mime_type="text/plain",
                                size_bytes=4, sha256="00" * 32)
            db.session.add(evidence)
            db.session.commit()
            self.case_id, self.evidence_id = case.id, evidence.id
        self.assume_session(self.owner_id)

    def request(self, recipient_id=None, reason="Для исследования экспертом"):
        return self.post(f"/evidence/{self.evidence_id}/transfer", {
            "to_user_id": recipient_id if recipient_id is not None else self.recipient_id,
            "reason": reason,
        })

    def pending(self):
        with self.app.app_context():
            transfer = db.session.scalar(select(EvidenceTransfer).where(
                EvidenceTransfer.evidence_id == self.evidence_id, EvidenceTransfer.status == "pending"))
            return transfer.id

    def evidence_custodian(self):
        with self.app.app_context():
            return db.session.get(Evidence, self.evidence_id).custodian_id

    def test_request_waits_for_recipient_and_records_case_and_evidence(self):
        self.assertEqual(self.request().status_code, 302)
        self.assertEqual(self.evidence_custodian(), self.owner_id)
        with self.app.app_context():
            transfer = db.session.get(EvidenceTransfer, self.pending())
            self.assertEqual(transfer.from_user_id, self.owner_id)
            self.assertEqual(transfer.to_user_id, self.recipient_id)
            self.assertEqual(transfer.requested_by, self.owner_id)
            self.assertIsNone(transfer.decided_at)
            event = db.session.scalar(select(AuditLog).where(
                AuditLog.event_type == "CUSTODY_TRANSFER_REQUESTED"))
            self.assertEqual(event.case_id, self.case_id)
            self.assertEqual(event.evidence_id, self.evidence_id)

    def test_viewer_recipient_accepts_once_and_cannot_replay(self):
        self.request()
        transfer_id = self.pending()
        self.assume_session(self.recipient_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 302)
        self.assertEqual(self.evidence_custodian(), self.recipient_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 409)
        with self.app.app_context():
            transfer = db.session.get(EvidenceTransfer, transfer_id)
            self.assertEqual(transfer.status, "accepted")
            self.assertIsNotNone(transfer.decided_at)
            self.assertEqual(db.session.query(AuditLog).filter_by(
                event_type="CUSTODY_TRANSFER_ACCEPTED").count(), 1)
        # A viewer responsible for an item may send it back to another authorised employee.
        self.assertEqual(self.request(self.owner_id, "Исследование завершено").status_code, 302)

    def test_only_current_custodian_may_request_transfer(self):
        for user_id in (self.recipient_id, self.admin_id, self.auditor_id):
            self.assume_session(user_id)
            self.assertEqual(self.request(self.owner_id).status_code, 403)
        self.assertEqual(self.evidence_custodian(), self.owner_id)

    def test_outsider_cannot_access_custody_routes(self):
        self.request()
        transfer_id = self.pending()
        self.assume_session(self.outsider_id)
        self.assertEqual(self.request().status_code, 404)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 404)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/cancel").status_code, 404)

    def test_only_designated_recipient_may_accept(self):
        self.request()
        transfer_id = self.pending()
        for user_id in (self.owner_id, self.admin_id, self.auditor_id):
            self.assume_session(user_id)
            self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 403)
        self.assertEqual(self.evidence_custodian(), self.owner_id)

    def test_recipient_must_be_active_eligible_and_have_case_access(self):
        inactive_id, _ = self.make_user(email="inactive@example.com", active=False)
        for recipient_id in (self.owner_id, self.outsider_id, self.auditor_id, inactive_id, 99999):
            with self.subTest(recipient=recipient_id):
                self.assertEqual(self.request(recipient_id).status_code, 400)
        self.assertEqual(self.evidence_custodian(), self.owner_id)
        with self.app.app_context():
            self.assertEqual(db.session.query(EvidenceTransfer).count(), 0)

    def test_reason_is_required_and_bounded(self):
        for reason in ("", "  ", "ab", "x" * 1001):
            with self.subTest(length=len(reason)):
                self.assertEqual(self.request(reason=reason).status_code, 400)
        self.assertEqual(self.request(reason="   Для экспертизы   ").status_code, 302)
        with self.app.app_context():
            self.assertEqual(db.session.get(EvidenceTransfer, self.pending()).reason, "Для экспертизы")

    def test_only_one_pending_transfer_and_csrf_required(self):
        response = self.client.post(f"/evidence/{self.evidence_id}/transfer", data={
            "to_user_id": self.recipient_id, "reason": "Для экспертизы"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.request().status_code, 302)
        self.assertEqual(self.request(self.admin_id).status_code, 409)
        with self.app.app_context():
            self.assertEqual(db.session.query(EvidenceTransfer).count(), 1)

    def test_cancel_preserves_custodian_and_blocks_acceptance(self):
        self.request()
        transfer_id = self.pending()
        self.assertEqual(self.post(f"/transfers/{transfer_id}/cancel").status_code, 302)
        self.assertEqual(self.evidence_custodian(), self.owner_id)
        self.assume_session(self.recipient_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 409)
        with self.app.app_context():
            self.assertEqual(db.session.get(EvidenceTransfer, transfer_id).status, "cancelled")

    def test_recipient_cannot_cancel_but_owner_can_cancel_after_transfer(self):
        self.request()
        transfer_id = self.pending()
        self.assume_session(self.recipient_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/cancel").status_code, 403)
        self.post(f"/transfers/{transfer_id}/accept")
        self.request(self.admin_id)
        transfer_id = self.pending()
        self.assume_session(self.owner_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/cancel").status_code, 302)
        self.assertEqual(self.evidence_custodian(), self.recipient_id)

    def test_closed_case_blocks_init_and_accept_but_allows_cancellation(self):
        self.request()
        transfer_id = self.pending()
        with self.app.app_context():
            db.session.get(Case, self.case_id).status = "closed"
            db.session.commit()
        self.assertEqual(self.request().status_code, 409)
        self.assume_session(self.recipient_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 409)
        self.assume_session(self.owner_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/cancel").status_code, 302)

    def test_legacy_item_without_custodian_cannot_invent_first_sender(self):
        with self.app.app_context():
            db.session.get(Evidence, self.evidence_id).custodian_id = None
            db.session.commit()
        self.assertEqual(self.request().status_code, 403)
        self.assertIsNone(self.evidence_custodian())

    def test_sender_revocation_invalidates_pending_acceptance(self):
        self.request()
        transfer_id = self.pending()
        with self.app.app_context():
            db.session.get(User, self.owner_id).is_active = False
            db.session.commit()
        self.assume_session(self.recipient_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 409)
        self.assertEqual(self.evidence_custodian(), self.owner_id)
        self.assume_session(self.admin_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/cancel").status_code, 302)

    def test_recipient_permission_and_role_are_rechecked(self):
        self.request()
        transfer_id = self.pending()
        with self.app.app_context():
            db.session.query(CaseMember).filter_by(case_id=self.case_id, user_id=self.recipient_id).delete()
            db.session.commit()
        self.assume_session(self.recipient_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 404)
        with self.app.app_context():
            db.session.get(User, self.recipient_id).role = "auditor"
            db.session.commit()
        self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 403)
        self.assertEqual(self.evidence_custodian(), self.owner_id)

    def test_stale_current_custodian_prevents_acceptance(self):
        self.request()
        transfer_id = self.pending()
        with self.app.app_context():
            db.session.get(Evidence, self.evidence_id).custodian_id = self.admin_id
            db.session.commit()
        self.assume_session(self.recipient_id)
        self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 409)
        self.assertEqual(self.evidence_custodian(), self.admin_id)

    def test_conflicting_update_rolls_back_without_custodian_change_or_event(self):
        self.request()
        transfer_id = self.pending()
        self.assume_session(self.recipient_id)
        original_execute = db.session.execute

        def conflict(statement, *args, **kwargs):
            if getattr(statement, "is_update", False) and statement.table.name == "evidence_transfers":
                return SimpleNamespace(rowcount=0)
            return original_execute(statement, *args, **kwargs)

        with patch.object(db.session, "execute", side_effect=conflict):
            self.assertEqual(self.post(f"/transfers/{transfer_id}/accept").status_code, 409)
        self.assertEqual(self.evidence_custodian(), self.owner_id)
        with self.app.app_context():
            self.assertEqual(db.session.get(EvidenceTransfer, transfer_id).status, "pending")
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="CUSTODY_TRANSFER_ACCEPTED").count(), 0)
