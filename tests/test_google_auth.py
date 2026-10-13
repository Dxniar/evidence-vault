from flask import redirect
from authlib.integrations.flask_client import OAuth
import pyotp
from datetime import timedelta

from models import AuditLog, User, db, utc_now
from tests.common import AppTestCase


class FakeGoogle:
    """Replace only the Google transport; the application's account rules stay real."""

    def __init__(self):
        self.claims = {"sub": "google-id-123", "email": "student@gmail.com", "email_verified": True}
        self.redirect_uri = None

    def authorize_redirect(self, redirect_uri):
        self.redirect_uri = redirect_uri
        return redirect("/fake-google")

    def authorize_access_token(self):
        return {"userinfo": self.claims}


class GoogleLoginTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        self.google = FakeGoogle()
        self.app.extensions["evidence_google_oauth"] = self.google

    def test_google_redirect_is_allowed_by_form_policy(self):
        user_id, _ = self.make_user(email="student@gmail.com")
        self.assume_session(user_id)
        profile_policy = self.client.get("/account").headers["Content-Security-Policy"]
        self.assertIn("form-action 'self' https://accounts.google.com;", profile_policy)
        self.assertIn("form-action 'self';", self.client.get("/dashboard").headers["Content-Security-Policy"])
        self.post("/logout")
        login_policy = self.client.get("/login").headers["Content-Security-Policy"]
        self.assertIn("form-action 'self' https://accounts.google.com;", login_policy)

    def test_only_prelinked_accounts_can_sign_in(self):
        user_id, _ = self.make_user(email="student@gmail.com")
        self.assertIn(b"Google", self.client.get("/login").data)
        self.assertEqual(self.post("/auth/google").status_code, 302)
        self.assertEqual(self.google.redirect_uri, "http://localhost/auth/google/callback")
        self.assertIn("/login", self.client.get("/auth/google/callback").location)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, user_id).google_sub)
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="GOOGLE_LOGIN_DENIED").count(), 1)

        # Matching email alone is not enough; the immutable Google ID must be linked.
        with self.app.app_context():
            db.session.get(User, user_id).google_sub = "another-google-id"
            db.session.commit()
        self.client.get("/login")
        self.post("/auth/google")
        self.assertIn("/login", self.client.get("/auth/google/callback").location)

    def test_link_then_google_login_requires_totp_and_keeps_role(self):
        user_id, secret = self.make_user(email="student@gmail.com")
        self.assume_session(user_id)
        self.assertEqual(self.post("/account/google/connect", {"password": "wrong"}).status_code, 302)
        self.assertIsNone(self.google.redirect_uri)
        self.assertEqual(self.post("/account/google/connect", {"password": "StrongPass123"}).status_code, 302)
        self.assertEqual(self.google.redirect_uri, "http://localhost/auth/google/callback")
        self.assertIn("/account", self.client.get("/auth/google/callback").location)
        with self.app.app_context():
            user = db.session.get(User, user_id)
            self.assertEqual(user.google_sub, "google-id-123")
            self.assertEqual(user.role, "investigator")
            self.assertEqual(user.session_version, 1)

        self.post("/logout")
        self.client.get("/login")
        self.post("/auth/google")
        self.assertIn("/verify-2fa", self.client.get("/auth/google/callback").location)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.assertIn("/dashboard", self.post("/verify-2fa", {"code": pyotp.TOTP(secret).now()}).location)
        self.assertEqual(self.client.get("/admin/users").status_code, 403)
        with self.app.app_context():
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="GOOGLE_LINKED").count(), 1)
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="GOOGLE_LOGIN_SUCCESS").count(), 1)

    def test_link_rejects_unverified_or_other_email_or_duplicate_id(self):
        user_id, _ = self.make_user(email="student@gmail.com")
        self.assume_session(user_id)
        self.post("/account/google/connect", {"password": "StrongPass123"})
        self.google.claims["email_verified"] = False
        self.assertIn("/account", self.client.get("/auth/google/callback").location)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, user_id).google_sub)

        self.post("/account/google/connect", {"password": "StrongPass123"})
        self.google.claims.update(email_verified=True, email="someone@gmail.com")
        self.assertIn("/account", self.client.get("/auth/google/callback").location)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, user_id).google_sub)

        other_id, _ = self.make_user(email="other@gmail.com")
        with self.app.app_context():
            db.session.get(User, other_id).google_sub = "google-id-123"
            db.session.commit()
        self.post("/account/google/connect", {"password": "StrongPass123"})
        self.google.claims["email"] = "student@gmail.com"
        self.assertIn("/account", self.client.get("/auth/google/callback").location)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, user_id).google_sub)

    def test_disabled_user_and_unlink(self):
        user_id, _ = self.make_user(email="student@gmail.com")
        with self.app.app_context():
            user = db.session.get(User, user_id)
            user.google_sub = "google-id-123"
            db.session.commit()
        self.assume_session(user_id)
        self.assertIn("/account", self.post("/account/google/disconnect", {"password": "wrong"}).location)
        with self.app.app_context():
            self.assertEqual(db.session.get(User, user_id).google_sub, "google-id-123")
        self.assertIn("/account", self.post("/account/google/disconnect", {"password": "StrongPass123"}).location)
        with self.app.app_context():
            user = db.session.get(User, user_id)
            self.assertIsNone(user.google_sub)
            self.assertEqual(user.session_version, 1)
            user.google_sub = "google-id-123"
            user.is_active = False
            db.session.commit()
        self.client.get("/login")
        self.post("/auth/google")
        self.assertIn("/login", self.client.get("/auth/google/callback").location)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_google_can_enroll_totp_but_cannot_skip_it(self):
        user_id, secret = self.make_user(email="student@gmail.com", enabled=False)
        with self.app.app_context():
            db.session.get(User, user_id).google_sub = "google-id-123"
            db.session.commit()
        self.post("/auth/google")
        self.assertIn("/setup-2fa", self.client.get("/auth/google/callback").location)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.assertIn("/dashboard", self.post("/setup-2fa", {"code": pyotp.TOTP(secret).now()}).location)

    def test_google_posts_require_csrf(self):
        user_id, _ = self.make_user(email="student@gmail.com")
        self.assertEqual(self.client.post("/auth/google").status_code, 400)
        self.assume_session(user_id)
        self.assertEqual(self.client.post("/account/google/connect", data={"password": "StrongPass123"}).status_code, 400)

    def test_invited_google_user_gets_preapproved_role_and_can_add_password(self):
        admin_id, _ = self.make_user(role="admin")
        self.assume_session(admin_id)
        self.assertIn("/admin/users", self.post("/admin/users/google", {
            "name": "Новый аудитор", "email": "student@gmail.com", "role": "auditor"}).location)
        with self.app.app_context():
            invited = db.session.query(User).filter_by(email="student@gmail.com").one()
            invited_id, secret = invited.id, invited.totp_secret
            self.assertFalse(invited.has_local_password)
            self.assertIsNone(invited.google_sub)
            self.assertGreater(invited.google_invite_expires_at.replace(tzinfo=None), utc_now().replace(tzinfo=None))
        self.post("/logout")
        self.client.get("/login")
        self.assertEqual(self.post("/login", {"email": "student@gmail.com",
                                              "password": "Anything12345"}).status_code, 200)
        self.assertIn("/fake-google", self.post("/auth/google").location)
        self.assertIn("/setup-2fa", self.client.get("/auth/google/callback").location)
        with self.app.app_context():
            invited = db.session.get(User, invited_id)
            self.assertEqual(invited.google_sub, "google-id-123")
            self.assertIsNone(invited.google_invite_expires_at)
            self.assertEqual(invited.role, "auditor")
        code = pyotp.TOTP(secret).now()
        self.assertIn("/dashboard", self.post("/setup-2fa", {"code": code}).location)
        self.assertEqual(self.client.get("/cases").status_code, 200)
        self.assertEqual(self.post("/cases", {"title": "Forbidden"}).status_code, 403)
        self.assertIn("/account", self.post("/account/google/disconnect", {"password": "anything"}).location)
        with self.app.app_context():
            self.assertEqual(db.session.get(User, invited_id).google_sub, "google-id-123")
        self.assertIn("/account", self.post("/account/password", {
            "new_password": "NewStrongPass123", "confirm_password": "NewStrongPass123", "code": code}).location)
        with self.app.app_context():
            self.assertFalse(db.session.get(User, invited_id).has_local_password)
            db.session.get(User, invited_id).last_totp_step -= 2
            db.session.commit()
        self.assertIn("/account", self.post("/account/password", {
            "new_password": "NewStrongPass123", "confirm_password": "NewStrongPass123", "code": code}).location)
        with self.app.app_context():
            self.assertTrue(db.session.get(User, invited_id).has_local_password)
            self.assertEqual(db.session.query(AuditLog).filter_by(event_type="GOOGLE_INVITE_ACCEPTED").count(), 1)

    def test_invitation_rejects_wrong_identity_and_expiry_until_admin_renews(self):
        admin_id, _ = self.make_user(role="admin")
        self.assume_session(admin_id)
        self.post("/admin/users/google", {"name": "Новый аудитор", "email": "student@gmail.com", "role": "auditor"})
        with self.app.app_context():
            invited = db.session.query(User).filter_by(email="student@gmail.com").one()
            invited_id = invited.id
            invited.google_invite_expires_at = utc_now() - timedelta(minutes=1)
            db.session.commit()
        self.post("/logout")
        self.client.get("/login")
        self.post("/auth/google")
        self.assertIn("/login", self.client.get("/auth/google/callback").location)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, invited_id).google_sub)
        self.assume_session(admin_id)
        self.assertIn("/admin/users", self.post(f"/admin/users/{invited_id}/google-invite/renew").location)
        self.post("/logout")
        self.client.get("/login")
        self.google.claims["email"] = "wrong@gmail.com"
        self.post("/auth/google")
        self.assertIn("/login", self.client.get("/auth/google/callback").location)
        self.client.get("/login")
        self.google.claims.update(email="student@gmail.com", email_verified=False)
        self.post("/auth/google")
        self.assertIn("/login", self.client.get("/auth/google/callback").location)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, invited_id).google_sub)
        self.client.get("/login")
        self.google.claims["email_verified"] = True
        self.post("/auth/google")
        self.assertIn("/setup-2fa", self.client.get("/auth/google/callback").location)

    def test_non_admin_cannot_invite_google_user(self):
        investigator_id, _ = self.make_user(role="investigator")
        self.assume_session(investigator_id)
        self.assertEqual(self.post("/admin/users/google", {"name": "Bad", "email": "x@example.com",
                                                             "role": "admin"}).status_code, 403)

    def test_real_oidc_client_rejects_unrequested_callback_state(self):
        oauth = OAuth(self.app)
        self.app.extensions["evidence_google_oauth"] = oauth.register(
            "google", client_id="fake-client", client_secret="fake-secret",
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email"})
        with self.client.session_transaction() as session:
            session["google_flow"] = "login"
        response = self.client.get("/auth/google/callback?code=fake&state=unexpected")
        self.assertIn("/login", response.location)
        with self.client.session_transaction() as session:
            self.assertNotIn("preauth_user_id", session)
            self.assertNotIn("google_flow", session)


class GoogleDisabledTestCase(AppTestCase):
    def test_login_is_hidden_until_configured(self):
        self.assertNotIn(b"/auth/google", self.client.get("/login").data)
        self.assertEqual(self.post("/auth/google").status_code, 404)
