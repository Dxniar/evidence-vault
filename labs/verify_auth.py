"""Reproducible laboratory 1/2 checks without a working database or network.

Run from the project root: python labs/verify_auth.py
Only an in-memory SQLite database, synthetic users, MemoryStorage, and a
FakeGoogle transport are used. No .env file is read and no real Google login
or Supabase request is made. The JSON report deliberately excludes passwords,
TOTP seeds, OTP values, session cookies, and OAuth credentials.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pyotp
from flask import redirect
from requests.sessions import Session
from werkzeug.security import generate_password_hash

import app as application
from models import AuditLog, User, db
from storage import StorageNotFound


class MemoryStorage:
    def __init__(self):
        self.objects = {}

    def upload(self, key, content, content_type):
        if key in self.objects:
            raise AssertionError("Unexpected object replacement")
        self.objects[key] = content

    def download(self, key, max_bytes):
        if key not in self.objects:
            raise StorageNotFound("Synthetic object absent")
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


class FakeGoogle:
    """Synthetic claims replace transport, not Evidence Vault account rules."""
    def __init__(self):
        self.claims = {"sub": "lab-google-sub", "email": "oidc@example.invalid",
                       "email_verified": True}
        self.redirect_uri = None

    def authorize_redirect(self, redirect_uri, **kwargs):
        self.redirect_uri = redirect_uri
        return redirect("/fake-google")

    def authorize_access_token(self):
        return {"userinfo": dict(self.claims)}


def deny_network(*args, **kwargs):
    raise AssertionError("Network access is forbidden in this laboratory check")


def verify():
    report = {
        "laboratories": [1, 2], "mode": "isolated demonstration",
        "database": "SQLite :memory:", "storage": "MemoryStorage",
        "federation_transport": "FakeGoogle (synthetic claims)",
        "real_google_sign_in_performed": False,
        "working_database_or_users_used": False,
        "network_requests_allowed": False, "checks": {},
    }
    app = application.create_app({
        "TESTING": True, "SECRET_KEY": "isolated-lab-session-key-never-for-production",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_ENGINE_OPTIONS": {}, "STORAGE": MemoryStorage(),
        "SESSION_COOKIE_SECURE": False, "TRUSTED_HOSTS": ["localhost"],
        "GOOGLE_OAUTH_CLIENT_ID": "", "GOOGLE_OAUTH_CLIENT_SECRET": "",
        "DISPLAY_TIMEZONE_OFFSET_HOURS": 5,
    })
    fake_google = FakeGoogle()
    app.extensions["evidence_google_oauth"] = fake_google
    now = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
    credentials = {}
    with app.app_context():
        db.create_all()
        for label, role, enabled, linked in (
            ("local", "investigator", False, False),
            ("locked", "investigator", True, False),
            ("oidc", "auditor", True, True),
            ("unlinked", "investigator", True, False),
        ):
            seed = pyotp.random_base32()
            user = User(name=f"Лабораторный {label}", email=f"{label}@example.invalid",
                        password_hash=generate_password_hash("SyntheticLabPass123"),
                        totp_secret=seed, totp_enabled=enabled, role=role,
                        google_sub="lab-google-sub" if linked else None)
            db.session.add(user)
            db.session.flush()
            credentials[label] = (user.id, seed)
        db.session.commit()

    def check(name, passed):
        report["checks"][name] = bool(passed)
        if not passed:
            raise AssertionError(name)

    def client():
        value = app.test_client()
        value.get("/login")
        return value

    def post(value, path, data=None):
        with value.session_transaction() as session:
            csrf = session["csrf_token"]
        return value.post(path, data={"csrf_token": csrf, **(data or {})})

    def password(value, label, submitted="SyntheticLabPass123"):
        return post(value, "/login", {"email": f"{label}@example.invalid", "password": submitted})

    def begin_google(value):
        value.get("/login")
        return post(value, "/auth/google")

    try:
        with patch.object(socket, "create_connection", deny_network), \
             patch.object(Session, "request", deny_network), \
             patch.object(application, "utc_now", lambda: now):
            local = client()
            check("missing_csrf_rejected", local.post("/login", data={"email": "local@example.invalid"}).status_code == 400)
            check("wrong_password_denied", password(local, "local", "wrong").status_code == 200
                  and local.get("/dashboard").status_code == 302)
            check("password_creates_only_preauth", "/setup-2fa" in password(local, "local").location
                  and local.get("/dashboard").status_code == 302)
            check("malformed_totp_denied", post(local, "/setup-2fa", {"code": "ABC"}).status_code == 200)
            seed = credentials["local"][1]
            used_code = pyotp.TOTP(seed).at(now.timestamp())
            check("totp_enrollment_opens_session", "/dashboard" in post(local, "/setup-2fa", {"code": used_code}).location
                  and local.get("/dashboard").status_code == 200)
            post(local, "/logout")
            local.get("/login")
            check("enrolled_user_requires_totp_again", "/verify-2fa" in password(local, "local").location
                  and local.get("/dashboard").status_code == 302)
            check("consumed_totp_replay_denied", post(local, "/verify-2fa", {"code": used_code}).status_code == 200
                  and local.get("/dashboard").status_code == 302)
            now += timedelta(seconds=30)
            check("next_time_step_code_accepted", "/dashboard" in post(local, "/verify-2fa", {
                "code": pyotp.TOTP(seed).at(now.timestamp())}).location)
            old_cookie = local.get_cookie("session").value
            post(local, "/logout")
            replay = client()
            replay.set_cookie("session", old_cookie)
            check("logout_revokes_saved_cookie", replay.get("/dashboard").status_code == 302)

            locked = client()
            for _ in range(application.AUTH_ATTEMPT_LIMIT):
                password(locked, "locked", "wrong")
            with app.app_context():
                locked_until = application.as_utc(db.session.get(User, credentials["locked"][0]).locked_until)
            check("five_failures_block_for_300_seconds", locked_until == now + timedelta(seconds=300)
                  and password(locked, "locked").status_code == 200)

            google = client()
            check("oidc_redirect_started", "/fake-google" in begin_google(google).location
                  and fake_google.redirect_uri == "http://localhost/auth/google/callback")
            check("google_success_still_requires_totp", "/verify-2fa" in google.get("/auth/google/callback").location
                  and google.get("/dashboard").status_code == 302)
            check("google_totp_opens_session", "/dashboard" in post(google, "/verify-2fa", {
                "code": pyotp.TOTP(credentials["oidc"][1]).at(now.timestamp())}).location
                  and google.get("/dashboard").status_code == 200)
            check("federation_preserves_preassigned_auditor_role", post(google, "/cases", {"title": "Forbidden"}).status_code == 403
                  and google.get("/admin/users").status_code == 403)
            post(google, "/logout")

            unlinked = client()
            fake_google.claims.update(sub="unlinked-google-sub", email="unlinked@example.invalid")
            begin_google(unlinked)
            check("matching_email_alone_is_not_linking", "/login" in unlinked.get("/auth/google/callback").location
                  and unlinked.get("/dashboard").status_code == 302)
            fake_google.claims.update(sub="lab-google-sub", email="oidc@example.invalid", email_verified=False)
            begin_google(unlinked)
            check("unverified_google_email_denied", "/login" in unlinked.get("/auth/google/callback").location)
            check("callback_without_flow_denied", "/login" in client().get("/auth/google/callback").location)
            fake_google.claims["email_verified"] = True
            with app.app_context():
                db.session.get(User, credentials["oidc"][0]).is_active = False
                db.session.commit()
            begin_google(unlinked)
            check("disabled_federated_user_denied", "/login" in unlinked.get("/auth/google/callback").location
                  and unlinked.get("/dashboard").status_code == 302)
            with app.app_context():
                events = [event.event_type for event in db.session.query(AuditLog).order_by(AuditLog.id)]
            check("success_and_denial_are_audited", "LOGIN_SUCCESS" in events and "2FA_ENABLED" in events
                  and "GOOGLE_LOGIN_SUCCESS" in events and "GOOGLE_LOGIN_DENIED" in events
                  and "2FA_FAILED" in events and "LOGIN_FAILED" in events)
            report["audit_event_types"] = events
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
    report["checks_passed"] = sum(report["checks"].values())
    report["checks_total"] = len(report["checks"])
    report["all_passed"] = all(report["checks"].values())
    report["temporary_database_destroyed"] = True
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=PROJECT_ROOT / "labs" / "evidence" / "auth-verification.json")
    args = parser.parse_args()
    result = verify()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
