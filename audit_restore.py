"""Offline verification and insert-only recovery of an audit backup.

Recovery never clears or merges an existing journal. Restore the related users,
cases and evidence first, using their original IDs, and run this administrative
command against an empty journal in a maintenance window.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import click
from sqlalchemy import func, insert, select, text

from audit_archive import read_verified_backup
from models import AuditLog, Case, Evidence, User, db, utc_now


MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_RESTORED_ID = 2_147_483_645
RESTORE_EVENT = "AUDIT_BACKUP_RESTORED"


class AuditRestoreError(ValueError):
    """Recovery was refused without replacing the current journal."""


def _file_bytes(path: Path) -> bytes:
    # The reader also bounds decompressed ZIP entries; bound the input before
    # allocating memory for a local file supplied to the CLI.
    with path.open("rb") as source:
        content = source.read(MAX_ARCHIVE_BYTES + 1)
    if len(content) > MAX_ARCHIVE_BYTES:
        raise AuditRestoreError("Архив превышает допустимый размер 16 МиБ.")
    return content


def _check_recoverable_ids(manifest: dict, rows: list[dict]) -> int:
    maximum = rows[-1]["id"] if rows else 0
    # AuditLog uses PostgreSQL INTEGER. Leave room for the recovery event and
    # the next normal INSERT; do not silently truncate or renumber source IDs.
    if maximum > MAX_RESTORED_ID or manifest["snapshot_max_id"] > MAX_RESTORED_ID:
        raise AuditRestoreError("Идентификаторы архива исчерпывают диапазон журнала INTEGER.")
    return maximum


def _lock_empty_journal(connection) -> None:
    if connection.dialect.name == "postgresql":
        connection.execute(text("SET LOCAL lock_timeout = '5s'"))
        connection.execute(text("LOCK TABLE audit_logs IN SHARE ROW EXCLUSIVE MODE"))
    elif connection.dialect.name == "sqlite":
        # SQLite starts a write transaction before inspecting the table, so a
        # concurrent writer cannot populate it between the check and INSERT.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        raise AuditRestoreError("Восстановление поддерживает PostgreSQL и SQLite.")
    if connection.scalar(select(AuditLog.id).limit(1)) is not None:
        raise AuditRestoreError("Журнал не пуст. Восстановление ничего не изменило.")


def _require_references(connection, rows: list[dict]) -> None:
    for field, table in (("user_id", User.__table__), ("case_id", Case.__table__),
                         ("evidence_id", Evidence.__table__)):
        required = sorted({row[field] for row in rows if row[field] is not None})
        for offset in range(0, len(required), 500):
            chunk = required[offset:offset + 500]
            existing = set(connection.scalars(select(table.c.id).where(table.c.id.in_(chunk))))
            if existing != set(chunk):
                missing = sorted(set(chunk) - existing)
                raise AuditRestoreError(
                    f"Не найдены исходные записи {table.name}: {', '.join(map(str, missing[:10]))}. "
                    "Сначала восстановите связанные данные с исходными идентификаторами.")


def _restart_postgres_sequence(connection, next_id: int) -> None:
    if connection.dialect.name != "postgresql":
        return
    sequence = connection.execute(text("""
        SELECT n.nspname AS schema_name, c.relname AS sequence_name
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.oid = pg_get_serial_sequence('audit_logs', 'id')::regclass
    """)).mappings().one_or_none()
    if sequence is None:
        raise AuditRestoreError("Не найдена последовательность идентификаторов журнала PostgreSQL.")
    preparer = connection.dialect.identifier_preparer
    qualified = (preparer.quote_schema(sequence["schema_name"]) + "." +
                 preparer.quote(sequence["sequence_name"]))
    # ALTER ... RESTART is transactional, unlike setval(): a failed restore
    # rolls back both the imported rows and sequence position.
    connection.execute(text(f"ALTER SEQUENCE {qualified} RESTART WITH {int(next_id)}"))


def restore_backup(content: bytes, actor_email: str, *, engine=None) -> dict:
    """Validate fully, then restore once in a single database transaction."""
    manifest, rows = read_verified_backup(content)
    maximum = _check_recoverable_ids(manifest, rows)
    actor_email = actor_email.strip().lower()
    if not actor_email:
        raise AuditRestoreError("Укажите почту существующего администратора.")
    engine = engine if engine is not None else db.engine
    event_id = maximum + 1
    with engine.begin() as connection:
        _lock_empty_journal(connection)
        actor = connection.execute(select(User.id, User.name, User.email).where(
            func.lower(User.email) == actor_email, User.role == "admin",
            User.is_active.is_(True))).mappings().one_or_none()
        if actor is None:
            raise AuditRestoreError("Нужен существующий активный администратор; учётные записи не создаются.")
        _require_references(connection, rows)
        for offset in range(0, len(rows), 500):
            restored = [{**row, "created_at": datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))}
                        for row in rows[offset:offset + 500]]
            connection.execute(insert(AuditLog.__table__), restored)
        connection.execute(insert(AuditLog.__table__).values(
            id=event_id, user_id=actor["id"], event_type=RESTORE_EVENT,
            description=f"Журнал восстановлен из проверенной резервной копии: событий {len(rows)}.",
            severity="success", ip_address="CLI", created_at=utc_now(),
            actor_name=actor["name"], actor_email=actor["email"],
            case_id=None, evidence_id=None, details_json=json.dumps({
                "record_count": len(rows), "snapshot_max_id": manifest["snapshot_max_id"],
                "journal_sha256": manifest["journal_sha256"],
                "archive_created_at": manifest["created_at"],
                "format_version": manifest["format_version"],
            }, ensure_ascii=False, separators=(",", ":"))))
        _restart_postgres_sequence(connection, event_id + 1)
    return {"record_count": len(rows), "restored_event_id": event_id,
            "journal_sha256": manifest["journal_sha256"]}


@click.command("audit-verify-backup")
@click.option("--file", "archive_file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
def verify_backup_command(archive_file: Path) -> None:
    """Check an audit ZIP offline, without a Flask factory or database settings."""
    try:
        manifest, rows = read_verified_backup(_file_bytes(archive_file))
        _check_recoverable_ids(manifest, rows)
    except (OSError, ValueError) as error:
        raise click.ClickException(str(error)) from error
    click.echo(f"Архив проверен: событий {len(rows)}, версия {manifest['format_version']}.")
    click.echo(f"SHA-256 журнала: {manifest['journal_sha256']}")


def register_restore(app) -> None:
    app.cli.add_command(verify_backup_command)

    @app.cli.command("audit-restore-backup")
    @click.option("--file", "archive_file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
    @click.option("--actor-email", required=True, help="Почта существующего активного администратора.")
    @click.option("--confirm-empty", is_flag=True, help="Подтверждаю восстановление только в пустой журнал.")
    def restore_command(archive_file: Path, actor_email: str, confirm_empty: bool) -> None:
        """Restore only an empty journal; preserve source IDs, timestamps and links."""
        if not confirm_empty:
            raise click.ClickException("Требуется --confirm-empty. Существующий журнал никогда не очищается.")
        try:
            result = restore_backup(_file_bytes(archive_file), actor_email)
        except (OSError, ValueError) as error:
            raise click.ClickException(str(error)) from error
        except Exception as error:
            # SQL exception strings may contain row values and connection
            # details. Keep the CLI diagnostic bounded and secret-free.
            app.logger.error("Audit recovery rolled back: %s", type(error).__name__)
            raise click.ClickException("Восстановление отменено из-за ошибки базы; изменения не сохранены.") from error
        click.echo(f"Восстановлено событий: {result['record_count']}. "
                   f"Событие восстановления: {result['restored_event_id']}.")


if __name__ == "__main__":
    verify_backup_command()
