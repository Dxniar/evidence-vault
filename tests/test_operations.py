import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from flask import Flask
from sqlalchemy import event

import operations
from models import db
from operations import ManifestVerificationError, register_operations, verify_manifest_files
from storage import StorageError


class ProbeStorage:
    def __init__(self, healthy=True):
        self.healthy = healthy
        self.calls = []

    def check_bucket(self, minimum_size, *, timeout):
        self.calls.append((minimum_size, timeout))
        if not self.healthy:
            raise StorageError("private-bucket-key-must-not-be-shown")


def probe_app(storage):
    app = Flask(__name__)
    app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
                      SQLALCHEMY_ENGINE_OPTIONS={})
    db.init_app(app)
    app.extensions["evidence_storage"] = storage
    register_operations(app)
    return app


class ReadinessTests(unittest.TestCase):
    def test_registration_does_not_check_dependencies_and_real_select_one_is_used(self):
        storage = ProbeStorage()
        app = probe_app(storage)
        self.assertEqual(storage.calls, [])
        queries = []
        with app.app_context():
            event.listen(db.engine, "before_cursor_execute",
                         lambda connection, cursor, statement, parameters, context, many: queries.append(statement))
        response = app.test_client().get("/readyz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ready", "services": {"database": True, "storage": True}})
        self.assertIn("SELECT 1", queries)
        self.assertEqual(storage.calls, [(16 * 1024 * 1024, (2, 3))])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_database_failure_returns_generic_503_without_secret_in_response_or_logs(self):
        app = probe_app(ProbeStorage())
        with app.app_context():
            engine = db.engine
        secret = "postgresql://private-user:private-password@example.invalid/private"
        with patch.object(engine, "connect", side_effect=RuntimeError(secret)), self.assertLogs(app.logger, "WARNING") as logs:
            response = app.test_client().get("/readyz")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json["services"], {"database": False, "storage": True})
        self.assertNotIn(secret, response.get_data(as_text=True))
        self.assertNotIn(secret, "\n".join(logs.output))

    def test_storage_failure_is_cached_and_refreshes_after_fifteen_seconds(self):
        storage = ProbeStorage(healthy=False)
        app = probe_app(storage)
        client = app.test_client()
        with patch.object(operations, "monotonic", return_value=1) as clock:
            self.assertEqual(client.get("/readyz").status_code, 503)
            storage.healthy = True
            clock.return_value = 15
            cached = client.get("/readyz")
            self.assertEqual(cached.status_code, 503)
            self.assertEqual(cached.json["services"], {"database": True, "storage": False})
            self.assertNotIn("private-bucket-key", cached.get_data(as_text=True))
            self.assertEqual(len(storage.calls), 1)
            clock.return_value = 16
            self.assertEqual(client.get("/readyz").status_code, 200)
            self.assertEqual(len(storage.calls), 2)

    def test_success_cache_and_failure_cache_are_isolated_between_apps(self):
        first, second = ProbeStorage(), ProbeStorage(healthy=False)
        app1, app2 = probe_app(first), probe_app(second)
        self.assertEqual(app1.test_client().get("/readyz").status_code, 200)
        self.assertEqual(app1.test_client().get("/readyz").status_code, 200)
        self.assertEqual(app2.test_client().get("/readyz").status_code, 503)
        self.assertEqual(len(first.calls), 1)
        self.assertEqual(len(second.calls), 1)
        self.assertIsNot(app1.extensions["evidence_readiness"], app2.extensions["evidence_readiness"])

    def test_concurrent_probes_only_check_once_per_cache_window(self):
        storage = ProbeStorage()
        app = probe_app(storage)
        with patch.object(operations, "_database_ready", return_value=True) as database:
            with ThreadPoolExecutor(max_workers=6) as pool:
                responses = list(pool.map(lambda _: app.test_client().get("/readyz").status_code, range(12)))
        self.assertEqual(responses, [200] * 12)
        self.assertEqual(database.call_count, 1)
        self.assertEqual(len(storage.calls), 1)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.files = self.root / "files"
        self.files.mkdir()
        self.path = self.root / "manifest.json"
        self.content = b"original evidence bytes"
        self.entry = {"id": 1, "original_name": "proof.txt", "export_name": "1_proof.txt",
                      "size_bytes": len(self.content), "sha256": hashlib.sha256(self.content).hexdigest()}
        self.manifest = {"format_version": 1, "evidence": [self.entry]}
        self.write_manifest()
        (self.files / "1_proof.txt").write_bytes(self.content)

    def tearDown(self):
        self.directory.cleanup()

    def write_manifest(self):
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def verify(self):
        return verify_manifest_files(self.path, self.files)

    def test_original_and_empty_files_are_verified(self):
        self.assertEqual(self.verify(), 1)
        self.entry.update(size_bytes=0, sha256=hashlib.sha256(b"").hexdigest())
        self.write_manifest()
        (self.files / "1_proof.txt").write_bytes(b"")
        self.assertEqual(self.verify(), 1)

    def test_changed_content_and_size_are_rejected(self):
        (self.files / "1_proof.txt").write_bytes(b"x" * len(self.content))
        with self.assertRaisesRegex(ManifestVerificationError, "SHA-256"):
            self.verify()
        (self.files / "1_proof.txt").write_bytes(self.content + b"x")
        with self.assertRaisesRegex(ManifestVerificationError, "размер"):
            self.verify()

    def test_missing_file_and_missing_directory_are_rejected(self):
        (self.files / "1_proof.txt").unlink()
        with self.assertRaisesRegex(ManifestVerificationError, "отсутствует"):
            self.verify()
        with self.assertRaisesRegex(ManifestVerificationError, "Каталог"):
            verify_manifest_files(self.path, self.root / "absent")

    def test_malformed_manifest_fields_are_rejected(self):
        for key, bad_values in {"id": [0, -1, True, "1"], "size_bytes": [-1, True, "4"],
                                "sha256": ["abcd", "g" * 64, 1], "original_name": [None, ""]}.items():
            original = self.entry[key]
            for bad in bad_values:
                with self.subTest(key=key, bad=bad):
                    self.entry[key] = bad
                    self.write_manifest()
                    with self.assertRaises(ManifestVerificationError):
                        self.verify()
            self.entry[key] = original
        for malformed in [{}, {"format_version": True, "evidence": []}, {"format_version": 1, "evidence": {}}]:
            self.path.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaises(ManifestVerificationError):
                self.verify()

    def test_duplicate_ids_and_names_are_rejected(self):
        for duplicate in [dict(self.entry), {**self.entry, "id": 2, "export_name": "1_proof.txt"}]:
            self.manifest["evidence"] = [self.entry, duplicate]
            self.write_manifest()
            with self.assertRaises(ManifestVerificationError):
                self.verify()

    def test_absolute_traversal_windows_paths_and_alias_names_are_rejected(self):
        for name in ["../1_proof.txt", "/1_proof.txt", "C:\\1_proof.txt", "1_../proof.txt",
                     "1_..\\proof.txt", "1_proof.txt:stream", "1_proof.txt.", "1_proof.txt "]:
            with self.subTest(name=name):
                self.entry["export_name"] = name
                self.write_manifest()
                with self.assertRaisesRegex(ManifestVerificationError, "небезопасное"):
                    self.verify()

    def test_symlink_escape_is_rejected(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(self.content)
        path = self.files / "1_proof.txt"
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError:
            self.skipTest("Creating symlinks is not permitted on this platform.")
        with self.assertRaisesRegex(ManifestVerificationError, "ссылка"):
            self.verify()

    def test_invalid_json_and_duplicate_json_keys_are_rejected(self):
        for content in ["not JSON", '{"format_version":1,"format_version":1,"evidence":[]}',
                        '{"format_version":1,"evidence":[],"unexpected":NaN}',
                        '{"format_version":1,"evidence":[],"unexpected":' + '1' * 5000 + '}']:
            self.path.write_text(content, encoding="utf-8")
            with self.assertRaises(ManifestVerificationError):
                self.verify()

    def test_command_is_offline_and_exits_nonzero_on_changed_bytes(self):
        app = Flask(__name__)
        register_operations(app)
        runner = app.test_cli_runner()
        args = ["verify-manifest", "--manifest", str(self.path), "--files-dir", str(self.files)]
        with patch.object(operations, "_database_ready", side_effect=AssertionError("Must be offline")), \
                patch.object(operations, "_storage_ready", side_effect=AssertionError("Must be offline")):
            result = runner.invoke(args=args)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("1 файлов", result.output)
            (self.files / "1_proof.txt").write_bytes(b"x" * len(self.content))
            result = runner.invoke(args=args)
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("SHA-256 не совпадает", result.output)


if __name__ == "__main__":
    unittest.main()
