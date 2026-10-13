from unittest import TestCase
from unittest.mock import MagicMock, Mock
from time import monotonic
from requests import HTTPError

from storage import StorageError, StorageNotFound, SupabaseStorage, storage_deadline


class StorageApiTestCase(TestCase):
    def test_upload_uses_private_server_key_and_no_upsert(self):
        storage = SupabaseStorage("https://project.supabase.co", "sb_secret_example", "evidence-private")
        storage.client = Mock()
        storage.client.post.return_value.status_code = 200
        storage.upload("1/file.txt", b"abc", "application/octet-stream")
        args, kwargs = storage.client.post.call_args
        self.assertEqual(args[0], "https://project.supabase.co/storage/v1/object/evidence-private/1/file.txt")
        self.assertEqual(kwargs["headers"]["apikey"], "sb_secret_example")
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertEqual(kwargs["headers"]["x-upsert"], "false")

    def test_download_is_bounded_and_authenticated(self):
        storage = SupabaseStorage("https://project.supabase.co", "sb_secret_example", "evidence-private")
        response = MagicMock()
        response.status_code = 200
        response.iter_content.return_value = iter([b"ab", b"cd"])
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        storage.client = Mock()
        storage.client.get.return_value = response
        self.assertEqual(storage.download("1/file.txt", 4), b"abcd")
        self.assertIn("/object/authenticated/", storage.client.get.call_args.args[0])
        response.iter_content.return_value = iter([b"abcde"])
        with self.assertRaises(StorageError):
            storage.download("1/file.txt", 4)

    def test_legacy_service_role_still_uses_bearer(self):
        storage = SupabaseStorage("https://project.supabase.co", "eyJ.one.two", "evidence-private")
        self.assertEqual(storage.headers["Authorization"], "Bearer eyJ.one.two")

    def response_storage(self, status, body):
        storage = SupabaseStorage('https://project.supabase.co', 'sb_secret_example', 'evidence-private')
        response = MagicMock()
        response.status_code = status
        response.json.return_value = body
        response.raise_for_status.side_effect = HTTPError(response=response)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        storage.client = Mock()
        storage.client.get.return_value = response
        storage.client.delete.return_value = response
        return storage

    def test_supabase_400_with_not_found_payload_is_missing(self):
        for code in ['404', 404]:
            with self.subTest(code=code):
                storage = self.response_storage(400, {'statusCode': code, 'error': 'not_found'})
                with self.assertRaises(StorageNotFound):
                    storage.download('1/missing.txt', 100)
                storage.delete('1/missing.txt')

    def test_other_400_and_permission_errors_are_not_missing(self):
        for status, body in [(400, {'statusCode': '400', 'error': 'invalid_request'}),
                             (403, {'statusCode': '403', 'error': 'unauthorized'}),
                             (400, ['not_found'])]:
            with self.subTest(status=status, body=body):
                storage = self.response_storage(status, body)
                with self.assertRaises(StorageError) as captured:
                    storage.download('1/file.txt', 100)
                self.assertNotIsInstance(captured.exception, StorageNotFound)

    def test_expired_operation_does_not_start_an_upload(self):
        storage = SupabaseStorage('https://project.supabase.co', 'sb_secret_example', 'evidence-private')
        storage.client = Mock()
        with storage_deadline(monotonic() - 1):
            with self.assertRaises(StorageError):
                storage.upload('1/file.txt', b'original', 'application/octet-stream')
        storage.client.post.assert_not_called()

    def test_bucket_preflight_requires_private_usable_bucket(self):
        storage = SupabaseStorage("https://project.supabase.co", "sb_secret_example", "evidence-private")
        storage.client = Mock()
        response = storage.client.get.return_value
        response.json.return_value = {"id": "evidence-private", "public": False,
                                      "file_size_limit": 16 * 1024 * 1024,
                                      "allowed_mime_types": None}
        storage.check_bucket(16 * 1024 * 1024)
        self.assertEqual(storage.client.get.call_args.args[0],
                         "https://project.supabase.co/storage/v1/bucket/evidence-private")
        self.assertNotIn("Authorization", storage.client.get.call_args.kwargs["headers"])
        response.json.return_value["public"] = True
        with self.assertRaises(StorageError):
            storage.check_bucket(16 * 1024 * 1024)
        response.json.return_value["public"] = False
        response.json.return_value["file_size_limit"] = 1024
        with self.assertRaises(StorageError):
            storage.check_bucket(16 * 1024 * 1024)
