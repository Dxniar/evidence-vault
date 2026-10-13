import hashlib
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from sqlalchemy import select

from models import AuditLog, Case, Evidence, User, db
from tests.common import AppTestCase


OLD_SCHEMA = """
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password_hash TEXT,
 totp_secret TEXT, totp_enabled INTEGER, role TEXT, failed_attempts INTEGER,
 locked_until TEXT, last_login TEXT, created_at TEXT);
CREATE TABLE cases (id INTEGER PRIMARY KEY, case_number TEXT, title TEXT, description TEXT,
 status TEXT, priority TEXT, owner_id INTEGER, created_at TEXT, updated_at TEXT);
CREATE TABLE evidence (id INTEGER PRIMARY KEY, case_id INTEGER, uploaded_by INTEGER,
 original_name TEXT, stored_name TEXT, mime_type TEXT, size_bytes INTEGER, sha256 TEXT,
 description TEXT, integrity_status TEXT, last_verified_at TEXT, created_at TEXT);
CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, user_id INTEGER, event_type TEXT,
 description TEXT, severity TEXT, ip_address TEXT, created_at TEXT);
"""


class LegacyImportTestCase(AppTestCase):
    def test_import_keeps_hashes_and_promotes_existing_user(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            uploads = root / "uploads"
            uploads.mkdir()
            content = b"original evidence"
            (uploads / "old.txt").write_bytes(content)
            database = root / "legacy.db"
            with closing(sqlite3.connect(database)) as conn, conn:
                conn.executescript(OLD_SCHEMA)
                conn.execute("INSERT INTO users VALUES (1,'Original','original@example.com','hash','JBSWY3DPEHPK3PXP',1,'investigator',0,NULL,NULL,'2026-09-01T00:00:00+00:00')")
                conn.execute("INSERT INTO cases VALUES (5,'EV-2026-OLD','Old case','','active','normal',1,'2026-09-01T00:00:00+00:00','2026-09-01T00:00:00+00:00')")
                conn.execute("INSERT INTO evidence VALUES (8,5,1,'old.txt','old.txt','text/plain',?,?, '', 'verified',NULL,'2026-09-01T00:00:00+00:00')",
                             (len(content), hashlib.sha256(content).hexdigest()))
                conn.execute("INSERT INTO audit_logs VALUES (3,1,'OLD_EVENT','Old action','info','127.0.0.1','2026-09-01T00:00:00+00:00')")
            result = self.app.test_cli_runner().invoke(args=["import-legacy", "--sqlite-file", str(database),
                                                             "--uploads-dir", str(uploads),
                                                             "--admin-email", "original@example.com"])
            self.assertEqual(result.exit_code, 0, result.output)
            with self.app.app_context():
                user = db.session.get(User, 1)
                evidence = db.session.get(Evidence, 8)
                self.assertEqual(user.role, "admin")
                self.assertEqual(db.session.get(Case, 5).case_number, "EV-2026-OLD")
                self.assertEqual(db.session.get(AuditLog, 3).event_type, "OLD_EVENT")
                self.assertEqual(self.storage.objects[evidence.stored_name], content)
            second = self.app.test_cli_runner().invoke(args=["import-legacy", "--sqlite-file", str(database),
                                                             "--uploads-dir", str(uploads)])
            self.assertNotEqual(second.exit_code, 0)
