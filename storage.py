"""Private Supabase Storage access. The elevated key stays on the server."""

from urllib.parse import quote
from contextlib import contextmanager
from contextvars import ContextVar
from time import monotonic

import requests

_deadline = ContextVar("evidence_storage_deadline", default=None)


@contextmanager
def storage_deadline(deadline: float):
    token = _deadline.set(deadline)
    try:
        yield
    finally:
        _deadline.reset(token)


def request_timeout() -> tuple[float, float]:
    deadline = _deadline.get()
    if deadline is None:
        return (5, 30)
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise StorageError("Истекло время операции с хранилищем.")
    return (min(5, remaining), min(30, remaining))


class StorageError(Exception):
    pass


class StorageNotFound(StorageError):
    pass


class StorageIntegrityError(StorageError):
    pass


def response_is_not_found(response) -> bool:
    if response.status_code == 404:
        return True
    if response.status_code != 400:
        return False
    try:
        details = response.json()
    except ValueError:
        return False
    return (isinstance(details, dict) and str(details.get("statusCode")) == "404"
            and details.get("error") == "not_found")


class SupabaseStorage:
    def __init__(self, url: str, service_key: str, bucket: str):
        if not url.startswith("https://") or not service_key or not bucket:
            raise ValueError("Настройте SUPABASE_URL, SUPABASE_SECRET_KEY и SUPABASE_STORAGE_BUCKET.")
        if not (service_key.startswith("sb_secret_") or service_key.count(".") == 2):
            raise ValueError("Нужен серверный sb_secret_ ключ или прежний service_role JWT.")
        self.storage_base = url.rstrip("/") + "/storage/v1"
        self.base = self.storage_base + "/object"
        self.bucket = bucket
        self.headers = {"apikey": service_key}
        if not service_key.startswith("sb_secret_"):
            # Legacy service_role keys are JWTs; opaque secret keys are not.
            self.headers["Authorization"] = f"Bearer {service_key}"
        self.client = requests.Session()

    def check_bucket(self, minimum_file_size: int, *, timeout: tuple[float, float] = (5, 15)) -> None:
        """Verify that the configured bucket exists, is private and accepts evidence files."""
        try:
            response = self.client.get(
                f"{self.storage_base}/bucket/{quote(self.bucket, safe='')}",
                headers=self.headers, timeout=timeout,
            )
            response.raise_for_status()
            details = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise StorageError("Не удалось проверить bucket. Проверьте URL, ключ и имя bucket.") from exc
        if not isinstance(details, dict) or details.get("id") != self.bucket:
            raise StorageError("Storage вернул неожиданные сведения о bucket.")
        if details.get("public") is not False:
            raise StorageError("Bucket должен быть Private (public=false).")
        limit = details.get("file_size_limit")
        if limit is not None and (type(limit) is not int or limit < minimum_file_size):
            raise StorageError("Лимит файла в bucket должен быть не меньше 16 МБ.")
        if details.get("allowed_mime_types"):
            raise StorageError("Снимите ограничения MIME в bucket: файлы сохраняются как application/octet-stream.")

    def _url(self, key: str, authenticated: bool = False) -> str:
        prefix = "/authenticated" if authenticated else ""
        return f"{self.base}{prefix}/{quote(self.bucket, safe='')}/{quote(key, safe='/')}"

    def upload(self, key: str, content: bytes, content_type: str) -> None:
        try:
            response = self.client.post(
                self._url(key), data=content, timeout=request_timeout(),
                headers={**self.headers, "Content-Type": content_type, "x-upsert": "false"},
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise StorageError("Не удалось сохранить файл в защищённом хранилище.") from exc

    def download(self, key: str, max_bytes: int) -> bytes:
        try:
            with self.client.get(self._url(key, authenticated=True), headers=self.headers,
                                 stream=True, timeout=request_timeout()) as response:
                if response_is_not_found(response):
                    raise StorageNotFound("Файл отсутствует в хранилище.")
                response.raise_for_status()
                chunks = []
                size = 0
                for chunk in response.iter_content(chunk_size=65536):
                    request_timeout()
                    size += len(chunk)
                    if size > max_bytes:
                        raise StorageIntegrityError("Размер файла в хранилище превышает допустимый предел.")
                    chunks.append(chunk)
                return b"".join(chunks)
        except requests.RequestException as exc:
            raise StorageError("Не удалось получить файл из хранилища.") from exc

    def delete(self, key: str) -> None:
        try:
            response = self.client.delete(
                self._url(key), headers=self.headers, timeout=request_timeout())
            if response_is_not_found(response):
                return
            response.raise_for_status()
        except requests.RequestException as exc:
            raise StorageError("Не удалось очистить незавершённую загрузку.") from exc
