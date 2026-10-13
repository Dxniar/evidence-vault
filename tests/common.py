import unittest

import pyotp
from werkzeug.security import generate_password_hash

from app import create_app
from models import User, db
from storage import StorageNotFound


class MemoryStorage:
    def __init__(self):
        self.objects = {}

    def upload(self, key, content, content_type):
        assert key not in self.objects
        self.objects[key] = content

    def download(self, key, max_bytes):
        if key not in self.objects:
            raise StorageNotFound("missing")
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.storage = MemoryStorage()
        self.app = create_app({
            "TESTING": True, "SECRET_KEY": "test-secret-for-unit-tests",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_ENGINE_OPTIONS": {}, "STORAGE": self.storage,
            "SESSION_COOKIE_SECURE": False, "TRUSTED_HOSTS": ["localhost"],
        })
        with self.app.app_context():
            db.create_all()
        self.client = self.app.test_client()
        self.client.get("/login")

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def csrf(self, client=None):
        with (client or self.client).session_transaction() as session:
            return session["csrf_token"]

    def post(self, path, data=None, client=None, **kwargs):
        client = client or self.client
        payload = {"csrf_token": self.csrf(client), **(data or {})}
        return client.post(path, data=payload, **kwargs)

    def make_user(self, role="investigator", email=None, enabled=True, active=True):
        email = email or f"{role}@example.com"
        secret = pyotp.random_base32()
        with self.app.app_context():
            user = User(name="Тестовый пользователь", email=email,
                        password_hash=generate_password_hash("StrongPass123"),
                        totp_secret=secret, totp_enabled=enabled, role=role, is_active=active)
            db.session.add(user)
            db.session.commit()
            return user.id, secret

    def assume_session(self, user_id, client=None):
        client = client or self.client
        with self.app.app_context():
            version = db.session.get(User, user_id).session_version
        with client.session_transaction() as session:
            session["user_id"] = user_id
            session["session_version"] = version
            session["csrf_token"] = "test-csrf"
