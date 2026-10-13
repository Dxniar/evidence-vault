"""Dependency probes and offline verification of exported evidence manifests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic

import click
from flask import Blueprint, Flask, current_app, jsonify
from sqlalchemy import text

from models import db

MINIMUM_BUCKET_FILE_SIZE = 16 * 1024 * 1024
READINESS_CACHE_SECONDS = 15
MANIFEST_SIZE_LIMIT = 16 * 1024 * 1024
HASH_PATTERN = re.compile(r"[a-fA-F0-9]{64}\Z")


@dataclass
class ReadinessCache:
    lock: threading.Lock = field(default_factory=threading.Lock)
    expires_at: float = 0
    services: dict[str, bool] | None = None


def _database_ready() -> bool:
    try:
        with db.engine.connect() as connection:
            if connection.dialect.name == "postgresql":
                connection.exec_driver_sql("SET LOCAL statement_timeout = '2000ms'")
            return connection.execute(text("SELECT 1")).scalar_one() == 1
    except Exception as exc:
        # Driver exceptions can contain connection strings. Do not log their text.
        current_app.logger.warning("Database readiness probe failed (%s).", type(exc).__name__)
        return False


def _storage_ready() -> bool:
    try:
        current_app.extensions["evidence_storage"].check_bucket(
            MINIMUM_BUCKET_FILE_SIZE, timeout=(2, 3))
        return True
    except Exception as exc:
        current_app.logger.warning("Storage readiness probe failed (%s).", type(exc).__name__)
        return False


operations = Blueprint("operations", __name__)


@operations.get("/readyz")
def readyz():
    cache: ReadinessCache = current_app.extensions["evidence_readiness"]
    with cache.lock:
        if cache.services is None or monotonic() >= cache.expires_at:
            cache.services = {"database": _database_ready(), "storage": _storage_ready()}
            # Both successful and failed checks are cached after they complete.
            cache.expires_at = monotonic() + READINESS_CACHE_SECONDS
        services = dict(cache.services)
    ready = all(services.values())
    response = jsonify(status="ready" if ready else "unavailable", services=services)
    response.status_code = 200 if ready else 503
    response.headers["Cache-Control"] = "no-store"
    return response


class ManifestVerificationError(ValueError):
    """A malformed manifest or an exported file that does not match it."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestVerificationError("Манифест содержит повторяющиеся поля JSON.")
        result[key] = value
    return result


def _reject_non_json_number(value):
    raise ManifestVerificationError("Манифест содержит число вне формата JSON.")


def _read_manifest(path: Path) -> list[dict]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MANIFEST_SIZE_LIMIT + 1)
        if len(raw) > MANIFEST_SIZE_LIMIT:
            raise ManifestVerificationError("Размер JSON-манифеста превышает 16 МБ.")
        manifest = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                              parse_constant=_reject_non_json_number)
    except ManifestVerificationError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ManifestVerificationError("Не удалось прочитать корректный JSON-манифест.") from exc
    if not isinstance(manifest, dict) or type(manifest.get("format_version")) is not int or manifest["format_version"] != 1:
        raise ManifestVerificationError("Нужен манифест формата format_version=1.")
    evidence = manifest.get("evidence")
    if not isinstance(evidence, list):
        raise ManifestVerificationError("Поле evidence должно содержать список материалов.")
    ids, names = set(), set()
    for index, entry in enumerate(evidence, start=1):
        if not isinstance(entry, dict):
            raise ManifestVerificationError(f"Материал № {index}: требуется объект JSON.")
        evidence_id, size = entry.get("id"), entry.get("size_bytes")
        if type(evidence_id) is not int or evidence_id <= 0:
            raise ManifestVerificationError(f"Материал № {index}: некорректный id.")
        if type(size) is not int or size < 0:
            raise ManifestVerificationError(f"Материал #{evidence_id}: некорректный размер файла.")
        digest, original_name, name = entry.get("sha256"), entry.get("original_name"), entry.get("export_name")
        if not isinstance(digest, str) or HASH_PATTERN.fullmatch(digest) is None:
            raise ManifestVerificationError(f"Материал #{evidence_id}: некорректный SHA-256.")
        if not isinstance(original_name, str) or not original_name.strip():
            raise ManifestVerificationError(f"Материал #{evidence_id}: отсутствует исходное имя.")
        if (not isinstance(name, str) or not 1 <= len(name) <= 255
                or not name.startswith(f"{evidence_id}_") or name.endswith((" ", "."))
                or any(ord(char) < 32 or 127 <= ord(char) <= 159 or char in '/\\:<>"|?*' for char in name)):
            raise ManifestVerificationError(f"Материал #{evidence_id}: небезопасное имя export_name.")
        if evidence_id in ids or name.casefold() in names:
            raise ManifestVerificationError("Манифест содержит повторяющиеся id или имена файлов.")
        ids.add(evidence_id)
        names.add(name.casefold())
    return evidence


def verify_manifest_files(manifest_path: Path, files_dir: Path) -> int:
    """Verify bytes against a manifest; this does not authenticate its author."""
    evidence = _read_manifest(manifest_path)
    try:
        root = files_dir.resolve(strict=True)
        if not root.is_dir():
            raise OSError("not a directory")
    except (OSError, RuntimeError) as exc:
        raise ManifestVerificationError("Каталог с экспортированными файлами недоступен.") from exc
    errors = []
    for entry in evidence:
        evidence_id = entry["id"]
        path = root / entry["export_name"]
        try:
            if path.is_symlink() or path.resolve(strict=True).parent != root:
                raise ManifestVerificationError(f"Материал #{evidence_id}: ссылка или выход за каталог запрещены.")
            # O_NOFOLLOW additionally prevents symlink replacement on platforms that support it.
            flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(os.open(path, flags), "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise ManifestVerificationError(f"Материал #{evidence_id}: требуется обычный файл.")
                if metadata.st_size != entry["size_bytes"]:
                    raise ManifestVerificationError(f"Материал #{evidence_id}: размер файла не совпадает.")
                digest, size = hashlib.sha256(), 0
                while True:
                    chunk = stream.read(min(1024 * 1024, entry["size_bytes"] - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > entry["size_bytes"]:
                        raise ManifestVerificationError(f"Материал #{evidence_id}: размер файла не совпадает.")
                    digest.update(chunk)
                if size != entry["size_bytes"]:
                    raise ManifestVerificationError(f"Материал #{evidence_id}: размер файла не совпадает.")
                if digest.hexdigest() != entry["sha256"].lower():
                    raise ManifestVerificationError(f"Материал #{evidence_id}: SHA-256 не совпадает.")
        except ManifestVerificationError as exc:
            errors.append(str(exc))
        except OSError:
            errors.append(f"Материал #{evidence_id}: файл отсутствует или недоступен.")
    if errors:
        raise ManifestVerificationError("\n".join(errors))
    return len(evidence)


@click.command("verify-manifest")
@click.option("--manifest", "manifest_path", required=True, type=click.Path(path_type=Path, dir_okay=False))
@click.option("--files-dir", required=True, type=click.Path(path_type=Path, file_okay=False))
def verify_manifest_command(manifest_path: Path, files_dir: Path):
    """Check exported evidence files offline against their JSON manifest."""
    try:
        count = verify_manifest_files(manifest_path, files_dir)
    except ManifestVerificationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Проверка пройдена: {count} файлов, размеры и SHA-256 совпадают.")
    click.echo("Совпадение не подтверждает подлинность или автора самого манифеста.")


def register_operations(app: Flask) -> None:
    # State belongs to each application and worker; registration does not touch dependencies.
    app.extensions["evidence_readiness"] = ReadinessCache()
    app.register_blueprint(operations)
    app.cli.add_command(verify_manifest_command)


if __name__ == "__main__":
    verify_manifest_command()
