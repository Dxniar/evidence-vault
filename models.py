from __future__ import annotations

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, Index, MetaData, UniqueConstraint, event, inspect, text
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
db = SQLAlchemy(metadata=MetaData(naming_convention=convention))


class Record:
    def __getitem__(self, key: str):
        return getattr(self, key)


class User(Record, db.Model):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin', 'investigator', 'auditor')", name="valid_role"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    has_local_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    google_sub: Mapped[str | None] = mapped_column(String(255), unique=True)
    google_invite_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    totp_secret: Mapped[str] = mapped_column(String(64), nullable=False)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_totp_step: Mapped[int | None] = mapped_column(BigInteger)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="investigator")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    session_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Case(Record, db.Model):
    __tablename__ = "cases"
    __table_args__ = (
        CheckConstraint("priority IN ('low', 'normal', 'high')", name="valid_priority"),
        CheckConstraint("status IN ('active', 'closed')", name="valid_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_number: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    reference_number: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    priority: Mapped[str] = mapped_column(String(10), default="normal", nullable=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False)
    owner: Mapped[User] = relationship(foreign_keys=[owner_id])
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    closure_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)


class CaseMember(Record, db.Model):
    __tablename__ = "case_members"
    __table_args__ = (
        UniqueConstraint("case_id", "user_id", name="uq_case_members_case_user"),
        CheckConstraint("permission IN ('viewer', 'editor')", name="valid_permission"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="RESTRICT"), index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False)
    permission: Mapped[str] = mapped_column(String(10), nullable=False, default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    case: Mapped[Case] = relationship(foreign_keys=[case_id])
    user: Mapped[User] = relationship(foreign_keys=[user_id])


class Evidence(Record, db.Model):
    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint("integrity_status IN ('verified', 'modified', 'missing')", name="valid_integrity_status"),
        CheckConstraint("observed_integrity_status IN ('verified', 'modified', 'missing')",
                        name="valid_observed_integrity_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="RESTRICT"), index=True, nullable=False)
    uploaded_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    integrity_status: Mapped[str] = mapped_column(String(20), default="verified", nullable=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_integrity_status: Mapped[str | None] = mapped_column(String(20))
    observed_integrity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    case: Mapped[Case] = relationship()
    source_label: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    source_reference: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    acquisition_method: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    acquired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_sha256: Mapped[str | None] = mapped_column(String(64))
    custodian_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    custodian: Mapped[User | None] = relationship(foreign_keys=[custodian_id])

    @property
    def current_integrity_status(self) -> str | None:
        if self.observed_integrity_status is not None:
            return self.observed_integrity_status
        return self.integrity_status if self.last_verified_at is not None or self.integrity_status != "verified" else None

    @property
    def integrity_checked_at(self) -> datetime | None:
        return self.observed_integrity_at or self.last_verified_at


class EvidenceTransfer(Record, db.Model):
    __tablename__ = "evidence_transfers"
    __table_args__ = (
        CheckConstraint("status IN ('pending', 'accepted', 'cancelled')", name="valid_status"),
        CheckConstraint("from_user_id <> to_user_id", name="different_custodians"),
        Index("uq_evidence_transfers_pending", "evidence_id", unique=True,
              postgresql_where=text("status = 'pending'"), sqlite_where=text("status = 'pending'")),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id", ondelete="RESTRICT"), index=True, nullable=False)
    from_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    to_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False)
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    status: Mapped[str] = mapped_column(String(10), default="pending", nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence: Mapped[Evidence] = relationship(foreign_keys=[evidence_id])
    from_user: Mapped[User] = relationship(foreign_keys=[from_user_id])
    to_user: Mapped[User] = relationship(foreign_keys=[to_user_id])
    requester: Mapped[User] = relationship(foreign_keys=[requested_by])


class AuditLog(Record, db.Model):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), default="info", nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    user: Mapped[User | None] = relationship()
    actor_name: Mapped[str | None] = mapped_column(String(120))
    actor_email: Mapped[str | None] = mapped_column(String(254))
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id", ondelete="RESTRICT"), index=True)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="RESTRICT"), index=True)
    details_json: Mapped[str | None] = mapped_column(Text)

    @property
    def name(self) -> str:
        return self.actor_name or (self.user.name if self.user else "—")

    @property
    def email(self) -> str:
        return self.actor_email or (self.user.email if self.user else "—")


@event.listens_for(Session, "before_flush")
def protect_evidence_records(session, _flush_context, _instances):
    """Guard accidental ORM edits; PostgreSQL triggers also cover direct SQL."""
    for record in session.deleted:
        if isinstance(record, (AuditLog, Evidence)):
            raise ValueError("История событий и оригиналы доказательств не удаляются.")
    for record in session.dirty:
        if not inspect(record).persistent:
            continue
        if isinstance(record, AuditLog) and session.is_modified(record, include_collections=False):
            raise ValueError("Сохранённое событие не изменяется.")
        if isinstance(record, Evidence):
            immutable = ("case_id", "uploaded_by", "original_name", "stored_name",
                         "mime_type", "size_bytes", "sha256", "created_at")
            if any(inspect(record).attrs[name].history.has_changes() for name in immutable):
                raise ValueError("Исходные сведения о файле не изменяются.")
