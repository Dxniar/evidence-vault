import pyotp
from werkzeug.security import check_password_hash

from app import as_utc, utc_now
from models import User, db
from tests.common import AppTestCase


class AuthenticationTestCase(AppTestCase):
    def test_public_registration_is_closed(self):
        self.assertEqual(self.client.get("/register").status_code, 404)
        self.assertEqual(self.post("/register", {"role": "admin"}).status_code, 404)

    def test_password_then_totp_and_replay_rejected(self):
        user_id, secret = self.make_user(enabled=False)
        response = self.post("/login", {"email": "investigator@example.com", "password": "StrongPass123"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/setup-2fa", response.location)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        code = pyotp.TOTP(secret).now()
        response = self.post("/setup-2fa", {"code": code})
        self.assertIn("/dashboard", response.location)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.post("/logout")
        self.client.get("/login")
        response = self.post("/login", {"email": "investigator@example.com", "password": "StrongPass123"})
        self.assertIn("/verify-2fa", response.location)
        self.assertEqual(self.post("/verify-2fa", {"code": code}).status_code, 200)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        # Simulate the next 30-second interval instead of waiting in the test.
        with self.app.app_context():
            user = db.session.get(User, user_id)
            user.last_totp_step -= 2
            db.session.commit()
        self.assertEqual(self.post("/verify-2fa", {"code": code}).status_code, 302)

    def test_account_lockout_and_revoked_session(self):
        user_id, _ = self.make_user()
        for _ in range(5):
            self.post("/login", {"email": "investigator@example.com", "password": "WrongPassword1"})
        with self.app.app_context():
            user = db.session.get(User, user_id)
            self.assertGreater(as_utc(user.locked_until), utc_now())
        self.assertEqual(self.post("/login", {"email": "investigator@example.com", "password": "StrongPass123"}).status_code, 200)

        self.assume_session(user_id)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        with self.app.app_context():
            user = db.session.get(User, user_id)
            user.session_version += 1
            user.is_active = False
            db.session.commit()
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_csrf_is_required(self):
        self.assertEqual(self.client.post("/login", data={"email": "x"}).status_code, 400)

    def test_initial_password_must_be_changed_and_old_sessions_are_revoked(self):
        admin_id, _ = self.make_user(role="admin")
        self.assume_session(admin_id)
        self.post("/admin/users", {"name": "Новый сотрудник", "email": "new@example.com",
                                   "password": "InitialPass123", "role": "investigator"})
        with self.app.app_context():
            user = db.session.query(User).filter_by(email="new@example.com").one()
            new_id, totp_secret = user.id, user.totp_secret
            self.assertTrue(user.must_change_password)
        self.post("/logout")
        self.client.get("/login")
        self.assertIn("/setup-2fa", self.post("/login", {"email": "new@example.com",
                                                         "password": "InitialPass123"}).location)
        self.assertIn("/account", self.post("/setup-2fa", {"code": pyotp.TOTP(totp_secret).now()}).location)
        self.assertIn("/account", self.client.get("/dashboard").location)
        self.assertIn("/account", self.post("/account/google/connect", {"password": "InitialPass123"}).location)
        self.assertIn(b"\xd0\xa1\xd0\xbc\xd0\xb5\xd0\xbd\xd0\xb8\xd1\x82\xd1\x8c", self.client.get("/account").data)

        old_client = self.app.test_client()
        self.assume_session(new_id, client=old_client)
        self.assertIn("/account", self.post("/account/password", {
            "current_password": "wrong", "new_password": "NewStrongPass123",
            "confirm_password": "NewStrongPass123"}).location)
        with self.app.app_context():
            self.assertTrue(db.session.get(User, new_id).must_change_password)
        self.assertIn("/account", self.post("/account/password", {
            "current_password": "InitialPass123", "new_password": "NewStrongPass123",
            "confirm_password": "NewStrongPass123"}).location)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertIn("/login", old_client.get("/dashboard").location)
        with self.app.app_context():
            user = db.session.get(User, new_id)
            self.assertFalse(user.must_change_password)
            self.assertTrue(check_password_hash(user.password_hash, "NewStrongPass123"))
        self.post("/logout")
        self.client.get("/login")
        self.assertEqual(self.post("/login", {"email": "new@example.com", "password": "InitialPass123"}).status_code, 200)
        self.assertIn("/verify-2fa", self.post("/login", {"email": "new@example.com",
                                                        "password": "NewStrongPass123"}).location)
