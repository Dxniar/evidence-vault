import io
import json
import logging
import unittest

from flask import Flask, g
from sqlalchemy import select

from app import append_event
from audit_logging import configure_application_logging
from models import AuditLog, Case, User, db
from tests.common import AppTestCase


class DiagnosticLoggingTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask("evidence_diagnostic_test")
        self.output = io.StringIO()
        self.logger = self.app.logger
        self.previous = (list(self.logger.handlers), self.logger.level, self.logger.propagate)
        configure_application_logging(self.app, stream=self.output)

    def tearDown(self):
        for handler in tuple(self.logger.handlers):
            self.logger.removeHandler(handler)
        for handler in self.previous[0]:
            self.logger.addHandler(handler)
        self.logger.setLevel(self.previous[1])
        self.logger.propagate = self.previous[2]

    def records(self):
        return [json.loads(line) for line in self.output.getvalue().splitlines()]

    def test_level_threshold_and_reconfiguration_emit_once(self):
        self.app.config["APP_LOG_LEVEL"] = "WARNING"
        configure_application_logging(self.app, stream=self.output)
        configure_application_logging(self.app, stream=self.output)
        self.logger.info("Hidden informational message")
        self.logger.warning("Visible warning")
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(self.records()[0]["level"], "WARNING")

    def test_request_correlation_and_utc_timestamp_without_request_data(self):
        with self.app.test_request_context("/?token=sensitive-query", headers={"Authorization": "Bearer private"}):
            g.request_id = "0123456789abcdef"
            self.logger.error("Database operation failed: OperationalError", extra={"password": "private"})
        record = self.records()[0]
        self.assertEqual(record["request_id"], "0123456789abcdef")
        self.assertTrue(record["timestamp"].endswith("Z"))
        self.assertEqual(set(record), {"timestamp", "level", "logger", "message", "request_id"})
        self.assertNotIn("sensitive-query", self.output.getvalue())
        self.assertNotIn("private", self.output.getvalue())

    def test_exception_values_and_tracebacks_are_omitted(self):
        try:
            raise RuntimeError("database password confidential SQL parameters")
        except RuntimeError as error:
            self.logger.exception("Operation failed: %s", error)
        record = self.records()[0]
        self.assertEqual(record["exception_type"], "RuntimeError")
        self.assertEqual(record["message"], "Operation failed: RuntimeError")
        self.assertNotIn("confidential", self.output.getvalue())
        self.assertNotIn("Traceback", self.output.getvalue())

    def test_secrets_and_dsn_are_redacted_without_extra_fields(self):
        self.logger.warning(
            "password=pass123 token='tok123' Bearer bearer123 "
            "postgresql+psycopg://user:dsn123@host/db "
            "https://host/oauth?code=code123 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123")
        text = self.output.getvalue()
        for secret in ("pass123", "tok123", "bearer123", "dsn123", "code123", "signature123"):
            self.assertNotIn(secret, text)
        self.assertIn("REDACTED", text)

    def test_newlines_cannot_forge_a_second_record_and_messages_are_bounded(self):
        self.logger.warning("first\r\nERROR forged " + "x" * 3000)
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(len(self.records()[0]["message"]), 2048)

    def test_invalid_level_fails_without_changing_the_logger(self):
        self.app.config["APP_LOG_LEVEL"] = "TRACE"
        with self.assertRaises(ValueError):
            configure_application_logging(self.app, stream=self.output)
        self.logger.info("Existing logger still works")
        self.assertEqual(len(self.records()), 1)

    def test_non_request_context_does_not_require_flask_globals(self):
        self.logger.error("Outside HTTP request")
        self.assertNotIn("request_id", self.records()[0])


class AuditJournalTestCase(AppTestCase):
    def test_event_captures_actor_ip_time_and_case_in_business_transaction(self):
        actor_id, _ = self.make_user()
        with self.app.test_request_context("/cases", environ_base={"REMOTE_ADDR": "192.0.2.15"}):
            g.user = db.session.get(User, actor_id)
            case = Case(case_number="LAB3-DEMO", title="Проверка журналирования", owner_id=actor_id)
            db.session.add(case)
            db.session.flush()
            append_event("CASE_CREATED", "Создано дело для проверки", "success", case_id=case.id,
                         details={"purpose": "isolated verification"})
            db.session.commit()
            event = db.session.scalar(select(AuditLog))
            self.assertEqual(event.user_id, actor_id)
            self.assertEqual(event.actor_name, g.user.name)
            self.assertEqual(event.actor_email, g.user.email)
            self.assertEqual(event.ip_address, "192.0.2.15")
            self.assertEqual(event.case_id, case.id)
            self.assertIsNotNone(event.created_at)
            self.assertEqual(json.loads(event.details_json)["purpose"], "isolated verification")

    def test_rollback_removes_event_and_action_together(self):
        actor_id, _ = self.make_user()
        with self.app.test_request_context("/cases"):
            g.user = db.session.get(User, actor_id)
            case = Case(case_number="LAB3-ROLLBACK", title="Незавершённое действие", owner_id=actor_id)
            db.session.add(case)
            db.session.flush()
            append_event("CASE_CREATED", "Незавершённое событие", case_id=case.id)
            db.session.flush()
            db.session.rollback()
            self.assertEqual(db.session.query(AuditLog).count(), 0)
            self.assertEqual(db.session.query(Case).count(), 0)

    def test_saved_audit_is_immutable_and_actor_snapshot_survives_rename(self):
        actor_id, _ = self.make_user()
        with self.app.test_request_context("/account"):
            g.user = db.session.get(User, actor_id)
            original_name = g.user.name
            append_event("PASSWORD_CHANGED", "Пароль изменён", "success")
            db.session.commit()
            event = db.session.scalar(select(AuditLog))
            g.user.name = "Новое имя"
            db.session.commit()
            self.assertEqual(event.name, original_name)
            event.description = "Подмена"
            with self.assertRaises(ValueError):
                db.session.commit()
            db.session.rollback()
            db.session.delete(event)
            with self.assertRaises(ValueError):
                db.session.commit()
            db.session.rollback()

    def test_viewer_cannot_read_another_case_events(self):
        owner_id, _ = self.make_user(email="owner@example.com")
        outsider_id, _ = self.make_user(email="outsider@example.com")
        with self.app.test_request_context("/cases"):
            g.user = db.session.get(User, owner_id)
            case = Case(case_number="LAB3-PRIVATE", title="Чужое дело", owner_id=owner_id)
            db.session.add(case)
            db.session.flush()
            append_event("CASE_CREATED", "LAB3_PRIVATE_EVENT_MARKER", case_id=case.id)
            db.session.commit()
        self.assume_session(outsider_id)
        response = self.client.get("/audit")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"LAB3_PRIVATE_EVENT_MARKER", response.data)


if __name__ == "__main__":
    unittest.main()
