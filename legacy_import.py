"""One-time import from the original SQLite project into Postgres and private Storage."""

import hashlib
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import click
from sqlalchemy import func, select, text

from models import AuditLog, Case, Evidence, User, db


def parsed_time(value):
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def register_cli(app):
    @app.cli.command("import-legacy")
    @click.option("--sqlite-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
    @click.option("--uploads-dir", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
    @click.option("--admin-email", help="Сделать существующего пользователя администратором, если в старой базе его нет.")
    def import_legacy(sqlite_file: Path, uploads_dir: Path, admin_email: str | None):
        """Import old data once into an empty, migrated database."""
        if db.session.scalar(select(func.count(User.id))) or db.session.scalar(select(func.count(Case.id))):
            raise click.ClickException("Целевая база должна быть пустой. Сначала сделайте резервную копию.")
        uploaded_keys = []
        with closing(sqlite3.connect(f"file:{sqlite_file.resolve()}?mode=ro", uri=True)) as old:
            old.row_factory = sqlite3.Row
            users = old.execute("SELECT * FROM users ORDER BY id").fetchall()
            cases = old.execute("SELECT * FROM cases ORDER BY id").fetchall()
            evidence = old.execute("SELECT * FROM evidence ORDER BY id").fetchall()
            logs = old.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
        if users and not any(item["role"] == "admin" for item in users):
            if not admin_email or not any(item["email"].lower() == admin_email.lower() for item in users):
                raise click.ClickException("В старой базе нет администратора. Укажите --admin-email с адресом существующего пользователя.")

        # Validate everything before any external write.
        for item in evidence:
            path = uploads_dir / Path(item["stored_name"]).name
            if not path.is_file() or path.stat().st_size != item["size_bytes"]:
                raise click.ClickException(f"Нет исходного файла или размер неверен: evidence #{item['id']}")
            if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
                raise click.ClickException(f"Контрольная сумма не совпала: evidence #{item['id']}")

        from flask import current_app
        bucket = current_app.extensions["evidence_storage"]
        try:
            for item in users:
                if item["role"] not in {"admin", "investigator", "auditor"}:
                    raise click.ClickException(f"Неизвестная роль у пользователя #{item['id']}")
                db.session.add(User(id=item["id"], name=item["name"], email=item["email"].lower(),
                                    password_hash=item["password_hash"], totp_secret=item["totp_secret"],
                                    totp_enabled=bool(item["totp_enabled"]),
                                    role="admin" if admin_email and item["email"].lower() == admin_email.lower() else item["role"],
                                    failed_attempts=item["failed_attempts"],
                                    locked_until=parsed_time(item["locked_until"]),
                                    last_login=parsed_time(item["last_login"]),
                                    created_at=parsed_time(item["created_at"])))
            db.session.flush()
            for item in cases:
                db.session.add(Case(id=item["id"], case_number=item["case_number"], title=item["title"],
                                    description=item["description"] or "", status=item["status"],
                                    priority=item["priority"], owner_id=item["owner_id"],
                                    created_at=parsed_time(item["created_at"]),
                                    updated_at=parsed_time(item["updated_at"])))
            db.session.flush()
            for item in evidence:
                path = uploads_dir / Path(item["stored_name"]).name
                extension = path.suffix.lower()
                key = f"legacy/{item['id']}/{uuid.uuid4().hex}{extension}"
                bucket.upload(key, path.read_bytes(), "application/octet-stream")
                uploaded_keys.append(key)
                db.session.add(Evidence(id=item["id"], case_id=item["case_id"],
                                        uploaded_by=item["uploaded_by"], original_name=item["original_name"],
                                        stored_name=key, mime_type=item["mime_type"],
                                        size_bytes=item["size_bytes"], sha256=item["sha256"],
                                        description=item["description"] or "",
                                        integrity_status=item["integrity_status"],
                                        last_verified_at=parsed_time(item["last_verified_at"]),
                                        created_at=parsed_time(item["created_at"])))
            for item in logs:
                db.session.add(AuditLog(id=item["id"], user_id=item["user_id"],
                                        event_type=item["event_type"], description=item["description"],
                                        severity=item["severity"], ip_address=item["ip_address"],
                                        created_at=parsed_time(item["created_at"])))
            db.session.flush()
            if db.engine.dialect.name == "postgresql":
                # Explicit imported IDs need their sequences advanced before new inserts.
                for table in ("users", "cases", "evidence", "audit_logs"):
                    db.session.execute(text(
                        f"SELECT setval(pg_get_serial_sequence('public.{table}', 'id'), "
                        f"COALESCE((SELECT MAX(id) FROM public.{table}), 1), "
                        f"(SELECT COUNT(*) > 0 FROM public.{table}))"))
            db.session.commit()
        except Exception:
            db.session.rollback()
            for key in reversed(uploaded_keys):
                try:
                    bucket.delete(key)
                except Exception:
                    app.logger.exception("Не удалось удалить незавершённый импорт: %s", key)
            raise
        click.echo(f"Перенесено: пользователей {len(users)}, дел {len(cases)}, "
                   f"файлов {len(evidence)}, событий {len(logs)}. Секрет Flask не переносился.")
