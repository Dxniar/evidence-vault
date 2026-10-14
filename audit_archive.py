"""Role-restricted journal exports and bounded, independently verifiable backups.

The archive contains audit rows only. SHA-256 detects changed bytes; it is not a
digital signature or proof of the identity of an archive's author.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
import zipfile
import zlib
from datetime import datetime, timezone
from time import monotonic

from flask import Blueprint, abort, current_app, flash, g, redirect, request, send_file, url_for
from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import contains_eager

from models import AuditLog, User, db, utc_now
from storage import StorageError, StorageIntegrityError, storage_deadline

FORMAT = "evidence-vault.audit-backup"
FORMAT_VERSION = 1
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_RECORDS = 100_000
MAX_CSV_BYTES = 16 * 1024 * 1024
SEVERITIES = frozenset({"info", "success", "warning", "danger"})
BACKUP_EVENT = "AUDIT_BACKUP_CREATED"
FIELDS = ("id", "user_id", "event_type", "description", "severity", "ip_address",
          "created_at", "actor_name", "actor_email", "case_id", "evidence_id", "details_json")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_KEY = re.compile(r"^audit-backups/[a-f0-9]{32}\.zip$")
_HASH = re.compile(r"^[a-f0-9]{64}$")


class AuditArchiveError(ValueError):
    """The complete archive cannot safely be created or validated."""


def iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def audit_query(q: str = "", severity: str = "all"):
    """The UI and export share the same literal search and visibility policy."""
    from app import audit_visibility_filter, escape_search
    query = (select(AuditLog).outerjoin(User, AuditLog.user_id == User.id)
             .options(contains_eager(AuditLog.user)).where(audit_visibility_filter())
             .order_by(AuditLog.id.desc()))
    search = q.strip()[:200]
    if search:
        pattern = "%" + escape_search(search) + "%"
        query = query.where(or_(AuditLog.description.ilike(pattern, escape="\\"),
                                AuditLog.event_type.ilike(pattern, escape="\\"),
                                func.coalesce(AuditLog.actor_name, User.name).ilike(pattern, escape="\\"),
                                func.coalesce(AuditLog.actor_email, User.email).ilike(pattern, escape="\\")))
    if severity in SEVERITIES:
        query = query.where(AuditLog.severity == severity)
    return query


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def event_record(event: AuditLog) -> dict:
    row = {key: getattr(event, key) for key in FIELDS}
    row["created_at"] = iso_utc(event.created_at)
    return row


def _integer(value, *, minimum=0) -> bool:
    return type(value) is int and minimum <= value <= 2 ** 63 - 1


def _valid_date(value) -> bool:
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _validate_record(row: dict) -> None:
    if not isinstance(row, dict) or set(row) != set(FIELDS):
        raise AuditArchiveError("Неверная структура записи журнала.")
    if not _integer(row["id"], minimum=1) or not _valid_date(row["created_at"]):
        raise AuditArchiveError("Неверный идентификатор или время записи.")
    for key in ("user_id", "case_id", "evidence_id"):
        if row[key] is not None and not _integer(row[key], minimum=1):
            raise AuditArchiveError("Неверная ссылка в записи журнала.")
    for key, length, nullable in (("event_type", 64, False), ("description", None, False),
                                  ("severity", 10, False), ("ip_address", 64, True),
                                  ("actor_name", 120, True), ("actor_email", 254, True),
                                  ("details_json", None, True)):
        value = row[key]
        if nullable and value is None:
            continue
        if not isinstance(value, str) or "\x00" in value or (length and len(value) > length):
            raise AuditArchiveError("Неверное поле записи журнала.")
    if not row["event_type"] or row["severity"] not in SEVERITIES:
        raise AuditArchiveError("Неверный тип или уровень события.")


def build_backup(rows, *, snapshot_max_id: int, created_by: dict, created_at=None) -> tuple[bytes, dict]:
    """Consume an ascending snapshot, rejecting oversize output without truncation."""
    journal = io.BytesIO()
    count, previous_id = 0, 0
    for event in rows:
        row = event_record(event)
        _validate_record(row)
        if row["id"] <= previous_id or row["id"] > snapshot_max_id:
            raise AuditArchiveError("Нарушен порядок снимка журнала.")
        previous_id = row["id"]
        count += 1
        line = _json(row) + b"\n"
        if count > MAX_RECORDS or journal.tell() + len(line) > MAX_UNCOMPRESSED_BYTES:
            raise AuditArchiveError("Полная копия превышает лимит: 100 000 событий или 64 МБ. Ничего не усечено.")
        journal.write(line)
    if previous_id != snapshot_max_id:
        raise AuditArchiveError("Снимок журнала неполон; повторите создание копии.")
    payload = journal.getvalue()
    manifest = {
        "format": FORMAT, "format_version": FORMAT_VERSION,
        "created_at": iso_utc(created_at or utc_now()), "created_by": created_by,
        "snapshot_max_id": snapshot_max_id, "record_count": count,
        "journal_sha256": hashlib.sha256(payload).hexdigest(), "journal_bytes": len(payload),
    }
    manifest_bytes = _json(manifest) + b"\n"
    if len(manifest_bytes) > MAX_MANIFEST_BYTES or len(payload) + len(manifest_bytes) > MAX_UNCOMPRESSED_BYTES:
        raise AuditArchiveError("Полная копия превышает лимит 64 МБ; ничего не усечено.")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("journal.jsonl", payload)
        archive.writestr("manifest.json", manifest_bytes)
    content = output.getvalue()
    if len(content) > MAX_ARCHIVE_BYTES:
        raise AuditArchiveError("Сжатая копия превышает лимит 16 МБ; ничего не усечено.")
    return content, manifest


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditArchiveError("Повторяющееся поле JSON.")
        result[key] = value
    return result


def _parse_json(data: bytes):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json,
                          parse_constant=lambda _value: (_ for _ in ()).throw(AuditArchiveError("Некорректное число JSON.")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AuditArchiveError("Не удалось прочитать JSON резервной копии.") from exc


def read_verified_backup(data: bytes) -> tuple[dict, list[dict]]:
    """Offline reader: bounded ZIP, exact schemas, SHA-256, IDs, UTC and counts."""
    if not isinstance(data, bytes) or len(data) > MAX_ARCHIVE_BYTES:
        raise AuditArchiveError("Архив превышает лимит 16 МБ.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if (len(members) != 2 or {item.filename for item in members} != {"journal.jsonl", "manifest.json"}
                    or any(item.flag_bits & 1 or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                           or item.is_dir() for item in members)
                    or sum(item.file_size for item in members) > MAX_UNCOMPRESSED_BYTES):
                raise AuditArchiveError("Неверный состав или превышен размер распакованной копии.")
            if archive.getinfo("manifest.json").file_size > MAX_MANIFEST_BYTES:
                raise AuditArchiveError("Манифест превышает допустимый размер.")
            manifest = _parse_json(archive.read("manifest.json"))
            payload = archive.read("journal.jsonl")
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, NotImplementedError, zlib.error) as exc:
        raise AuditArchiveError("Повреждённый или неподдерживаемый ZIP-архив.") from exc
    expected_keys = {"format", "format_version", "created_at", "created_by", "snapshot_max_id",
                     "record_count", "journal_sha256", "journal_bytes"}
    if (not isinstance(manifest, dict) or set(manifest) != expected_keys
            or manifest["format"] != FORMAT or type(manifest["format_version"]) is not int
            or manifest["format_version"] != FORMAT_VERSION or not _valid_date(manifest["created_at"])
            or not _integer(manifest["snapshot_max_id"]) or not _integer(manifest["record_count"])
            or manifest["record_count"] > MAX_RECORDS or not _integer(manifest["journal_bytes"])
            or not isinstance(manifest["journal_sha256"], str) or not _HASH.fullmatch(manifest["journal_sha256"])):
        raise AuditArchiveError("Неверный формат манифеста резервной копии.")
    author = manifest["created_by"]
    if (not isinstance(author, dict) or set(author) != {"id", "name"}
            or not _integer(author["id"], minimum=1) or not isinstance(author["name"], str)
            or len(author["name"]) > 120 or "\x00" in author["name"]):
        raise AuditArchiveError("Неверные сведения об авторе копии.")
    if (len(payload) != manifest["journal_bytes"]
            or hashlib.sha256(payload).hexdigest() != manifest["journal_sha256"]):
        raise AuditArchiveError("SHA-256 журнала не совпадает; копия повреждена.")
    if payload and not payload.endswith(b"\n"):
        raise AuditArchiveError("Неполная последняя запись журнала.")
    records, previous_id = [], 0
    for line in payload.splitlines():
        row = _parse_json(line)
        _validate_record(row)
        if row["id"] <= previous_id or row["id"] > manifest["snapshot_max_id"] or len(records) >= MAX_RECORDS:
            raise AuditArchiveError("Неверный порядок или число записей журнала.")
        previous_id = row["id"]
        records.append(row)
    if len(records) != manifest["record_count"] or previous_id != manifest["snapshot_max_id"]:
        raise AuditArchiveError("Количество записей или граница снимка не совпадает.")
    return manifest, records


def verify_backup(data: bytes) -> dict:
    manifest, records = read_verified_backup(data)
    return {"manifest": manifest, "records": records}


def _require_roles(*roles) -> None:
    from app import session_matches_user
    if not g.user or g.user.role not in roles:
        abort(403)
    db.session.refresh(g.user, with_for_update=True)
    if not session_matches_user(g.user) or g.user.role not in roles:
        abort(403)


def _catalog_metadata(event: AuditLog) -> dict | None:
    try:
        metadata = json.loads(event.details_json or "null")
        if (not isinstance(metadata, dict) or metadata.get("format_version") != FORMAT_VERSION
                or not isinstance(metadata.get("storage_key"), str) or not _KEY.fullmatch(metadata["storage_key"])
                or not _integer(metadata.get("record_count")) or not _integer(metadata.get("snapshot_max_id"))
                or not _integer(metadata.get("size_bytes"), minimum=1) or metadata["size_bytes"] > MAX_ARCHIVE_BYTES
                or not _valid_date(metadata.get("created_at"))
                or any(not isinstance(metadata.get(key), str) or not _HASH.fullmatch(metadata[key])
                       for key in ("archive_sha256", "journal_sha256"))):
            return None
        return metadata
    except (ValueError, TypeError, RecursionError):
        return None


def backup_catalog(limit=10, offset=0) -> list[dict]:
    if not g.user or g.user.role != "admin":
        abort(403)
    result = []
    for event in db.session.scalars(select(AuditLog).where(AuditLog.event_type == BACKUP_EVENT)
                                    .order_by(AuditLog.id.desc()).limit(max(1, min(int(limit), 100)))
                                    .offset(max(0, int(offset)))):
        metadata = _catalog_metadata(event)
        if metadata:
            result.append({"event_id": event.id, "created_at": event.created_at,
                           "actor_name": event.actor_name or "—", "metadata": metadata})
    return result


def _spreadsheet_text(value) -> str:
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r", "\n") or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def register_audit_archive(app) -> None:
    from app import append_event, login_required, storage
    blueprint = Blueprint("audit_archive", __name__)

    @blueprint.post("/audit/export")
    @login_required
    def export_csv():
        _require_roles("admin", "auditor")
        search = request.form.get("q", "").strip()[:200]
        severity = request.form.get("severity", "all")
        severity = severity if severity in SEVERITIES else "all"
        cutoff = db.session.scalar(select(func.max(AuditLog.id))) or 0
        output = io.StringIO(newline="")
        writer = csv.writer(output, delimiter=";", lineterminator="\r\n")
        writer.writerow(("ID", "Время (UTC)", "Тип события", "Уровень", "Пользователь", "Email",
                         "IP", "ID пользователя", "ID дела", "ID доказательства", "Описание", "Детали JSON"))
        count, byte_count = 0, len(output.getvalue().encode("utf-8-sig"))
        query = audit_query(search, severity).where(AuditLog.id <= cutoff).execution_options(yield_per=500)
        for event in db.session.scalars(query):
            row = (event.id, iso_utc(event.created_at), event.event_type, event.severity, event.name,
                   event.email, event.ip_address, event.user_id, event.case_id, event.evidence_id,
                   event.description, event.details_json)
            line = io.StringIO(newline="")
            csv.writer(line, delimiter=";", lineterminator="\r\n").writerow(map(_spreadsheet_text, row))
            text = line.getvalue()
            count += 1
            byte_count += len(text.encode("utf-8"))
            if count > MAX_RECORDS or byte_count > MAX_CSV_BYTES:
                abort(413, "Полный экспорт превышает лимит 100 000 событий или 16 МБ. Уточните фильтры; ничего не усечено.")
            output.write(text)
        payload = output.getvalue().encode("utf-8-sig")
        _require_roles("admin", "auditor")
        append_event("AUDIT_EXPORTED", f"Экспортировано событий журнала: {count}",
                     details={"record_count": count, "snapshot_max_id": cutoff, "severity": severity,
                              "search_applied": bool(search), "sha256": hashlib.sha256(payload).hexdigest()})
        db.session.commit()
        return send_file(io.BytesIO(payload), mimetype="text/csv; charset=utf-8", as_attachment=True,
                         download_name=f"audit-{utc_now():%Y%m%d-%H%M%S}.csv", max_age=0)

    @blueprint.post("/audit/backups")
    @login_required
    def create_backup():
        _require_roles("admin")
        key = "audit-backups/" + uuid.uuid4().hex + ".zip"
        upload_attempted, commit_started, recovered = False, False, False
        try:
            cutoff = db.session.scalar(select(func.max(AuditLog.id))) or 0
            actor = {"id": g.user.id, "name": g.user.name}
            rows = db.session.scalars(select(AuditLog).where(AuditLog.id <= cutoff)
                                      .order_by(AuditLog.id).execution_options(yield_per=500))
            content, manifest = build_backup(rows, snapshot_max_id=cutoff, created_by=actor)
            # Complete the source read before network I/O. No session lock is
            # held while Storage uploads or verifies its readback.
            db.session.rollback()
            with storage_deadline(monotonic() + 60):
                upload_attempted = True
                storage().upload(key, content, "application/octet-stream")
                readback = storage().download(key, MAX_ARCHIVE_BYTES)
            if readback != content:
                raise StorageIntegrityError("Хранилище не подтвердило резервную копию.")
            _require_roles("admin")
            metadata = {"storage_key": key, "archive_sha256": hashlib.sha256(content).hexdigest(),
                        "size_bytes": len(content), "journal_sha256": manifest["journal_sha256"],
                        "record_count": manifest["record_count"], "snapshot_max_id": cutoff,
                        "created_at": manifest["created_at"], "format_version": FORMAT_VERSION}
            append_event(BACKUP_EVENT, f"Создана резервная копия журнала: {manifest['record_count']} событий",
                         "success", details=metadata)
            commit_started = True
            db.session.commit()
        except (AuditArchiveError, StorageError, SQLAlchemyError) as exc:
            db.session.rollback()
            current_app.logger.warning("Audit backup failed: %s", type(exc).__name__)
            # A connection can fail after PostgreSQL committed. Never delete a
            # stored object that a committed catalogue event already references.
            known_not_committed = not commit_started
            if commit_started:
                try:
                    candidates = db.session.scalars(select(AuditLog).where(
                        AuditLog.event_type == BACKUP_EVENT, AuditLog.details_json.contains(key)))
                    recovered = any((_catalog_metadata(item) or {}).get("storage_key") == key for item in candidates)
                    known_not_committed = not recovered
                except SQLAlchemyError:
                    db.session.rollback()
                    current_app.logger.warning("Audit backup commit status unavailable; retain stored object for reconciliation.")
            if upload_attempted and known_not_committed:
                _cleanup(key)
            if isinstance(exc, AuditArchiveError):
                abort(413, str(exc))
            if not recovered:
                abort(503, "Не удалось подтвердить сохранение резервной копии. Обновите каталог перед повтором.")
        except BaseException:
            db.session.rollback()
            if upload_attempted and not commit_started:
                _cleanup(key)
            raise
        flash("Резервная копия журнала сохранена в закрытом хранилище.", "success")
        return redirect(url_for("audit"))

    def _cleanup(key):
        try:
            with storage_deadline(monotonic() + 10):
                storage().delete(key)
        except StorageError:
            current_app.logger.warning("Audit backup cleanup failed; check orphaned backup objects.")

    @blueprint.post("/audit/backups/<int:event_id>/download")
    @login_required
    def download_backup(event_id):
        _require_roles("admin")
        event = db.session.scalar(select(AuditLog).where(AuditLog.id == event_id, AuditLog.event_type == BACKUP_EVENT))
        metadata = _catalog_metadata(event) if event else None
        if metadata is None:
            abort(404)
        # The immutable catalogue snapshot is plain data. Release the user lock
        # for the network read, then revalidate and lock immediately before audit.
        db.session.rollback()
        try:
            with storage_deadline(monotonic() + 60):
                content = storage().download(metadata["storage_key"], MAX_ARCHIVE_BYTES)
            if (len(content) != metadata["size_bytes"]
                    or hashlib.sha256(content).hexdigest() != metadata["archive_sha256"]):
                raise AuditArchiveError("Контрольная сумма резервной копии не совпадает.")
            manifest, _records = read_verified_backup(content)
            if any(manifest[key] != metadata[key] for key in
                   ("record_count", "snapshot_max_id", "created_at", "journal_sha256", "format_version")):
                raise AuditArchiveError("Метаданные резервной копии не совпадают с каталогом.")
            _require_roles("admin")
            append_event("AUDIT_BACKUP_DOWNLOADED", "Подготовлена выдача резервной копии журнала",
                         details={"backup_event_id": event_id, "record_count": metadata["record_count"],
                                  "journal_sha256": metadata["journal_sha256"]})
            db.session.commit()
        except (AuditArchiveError, StorageError) as exc:
            db.session.rollback()
            current_app.logger.warning("Audit backup read failed: %s", type(exc).__name__)
            abort(503, "Копия недоступна или не прошла проверку целостности. Файл не выдан.")
        return send_file(io.BytesIO(content), mimetype="application/zip", as_attachment=True,
                         download_name=f"audit-backup-{event_id}.zip", max_age=0)

    app.register_blueprint(blueprint)
