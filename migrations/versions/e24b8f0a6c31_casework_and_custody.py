"""Case collaboration, provenance, custody receipts and protected audit records.

Revision ID: e24b8f0a6c31
Revises: d91a3b6c8e20
"""
from alembic import op
import sqlalchemy as sa

revision = "e24b8f0a6c31"
down_revision = "d91a3b6c8e20"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("cases") as batch:
        batch.add_column(sa.Column("reference_number", sa.String(80), nullable=False, server_default=""))
        batch.add_column(sa.Column("closed_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("closed_by", sa.Integer()))
        batch.add_column(sa.Column("closure_reason", sa.Text(), nullable=False, server_default=""))
        batch.create_foreign_key("fk_cases_closed_by_users", "users", ["closed_by"], ["id"], ondelete="RESTRICT")
    op.create_table("case_members",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("permission", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("case_id", "user_id", name="uq_case_members_case_user"),
        sa.CheckConstraint("permission IN ('viewer', 'editor')", name="valid_permission"))
    op.create_index("ix_case_members_case_id", "case_members", ["case_id"])
    op.create_index("ix_case_members_user_id", "case_members", ["user_id"])
    with op.batch_alter_table("evidence") as batch:
        batch.add_column(sa.Column("source_label", sa.String(500), nullable=False, server_default=""))
        batch.add_column(sa.Column("source_reference", sa.String(200), nullable=False, server_default=""))
        batch.add_column(sa.Column("acquisition_method", sa.String(300), nullable=False, server_default=""))
        batch.add_column(sa.Column("acquired_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("source_sha256", sa.String(64)))
        batch.add_column(sa.Column("custodian_id", sa.Integer()))
        batch.create_foreign_key("fk_evidence_custodian_id_users", "users", ["custodian_id"], ["id"], ondelete="RESTRICT")
        batch.create_index("ix_evidence_custodian_id", ["custodian_id"])
    op.create_table("evidence_transfers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("from_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("to_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("requested_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('pending', 'accepted', 'cancelled')", name="valid_status"),
        sa.CheckConstraint("from_user_id <> to_user_id", name="different_custodians"))
    op.create_index("ix_evidence_transfers_evidence_id", "evidence_transfers", ["evidence_id"])
    op.create_index("ix_evidence_transfers_to_user_id", "evidence_transfers", ["to_user_id"])
    op.create_index("uq_evidence_transfers_pending", "evidence_transfers", ["evidence_id"], unique=True,
        postgresql_where=sa.text("status = 'pending'"), sqlite_where=sa.text("status = 'pending'"))
    with op.batch_alter_table("audit_logs") as batch:
        batch.add_column(sa.Column("actor_name", sa.String(120)))
        batch.add_column(sa.Column("actor_email", sa.String(254)))
        batch.add_column(sa.Column("case_id", sa.Integer()))
        batch.add_column(sa.Column("evidence_id", sa.Integer()))
        batch.add_column(sa.Column("details_json", sa.Text()))
        batch.create_foreign_key("fk_audit_logs_case_id_cases", "cases", ["case_id"], ["id"], ondelete="RESTRICT")
        batch.create_foreign_key("fk_audit_logs_evidence_id_evidence", "evidence", ["evidence_id"], ["id"], ondelete="RESTRICT")
        batch.create_index("ix_audit_logs_case_id", ["case_id"])
        batch.create_index("ix_audit_logs_evidence_id", ["evidence_id"])
    # Historical provenance and custodians stay unknown. Existing data is retained.
    if op.get_bind().dialect.name == "postgresql":
        for table in ("case_members", "evidence_transfers"):
            op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"REVOKE ALL ON public.{table} FROM anon, authenticated, service_role")
            op.execute(f"REVOKE ALL ON SEQUENCE public.{table}_id_seq FROM anon, authenticated, service_role")
        op.execute("""
            CREATE FUNCTION public.ev_audit_insert_only() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'Saved audit events cannot be changed or deleted'
                    USING ERRCODE = '55000';
            END; $$
        """)
        op.execute("""
            CREATE TRIGGER ev_audit_insert_only BEFORE UPDATE OR DELETE ON public.audit_logs
            FOR EACH ROW EXECUTE FUNCTION public.ev_audit_insert_only()
        """)
        op.execute("""
            CREATE FUNCTION public.ev_evidence_identity_guard() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'Original evidence records cannot be deleted' USING ERRCODE = '55000';
                END IF;
                IF ROW(NEW.case_id, NEW.uploaded_by, NEW.original_name, NEW.stored_name,
                       NEW.mime_type, NEW.size_bytes, NEW.sha256, NEW.created_at)
                   IS DISTINCT FROM
                   ROW(OLD.case_id, OLD.uploaded_by, OLD.original_name, OLD.stored_name,
                       OLD.mime_type, OLD.size_bytes, OLD.sha256, OLD.created_at) THEN
                    RAISE EXCEPTION 'Original evidence identity cannot be changed' USING ERRCODE = '55000';
                END IF;
                RETURN NEW;
            END; $$
        """)
        op.execute("""
            CREATE TRIGGER ev_evidence_identity_guard BEFORE UPDATE OR DELETE ON public.evidence
            FOR EACH ROW EXECUTE FUNCTION public.ev_evidence_identity_guard()
        """)


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER ev_evidence_identity_guard ON public.evidence")
        op.execute("DROP FUNCTION public.ev_evidence_identity_guard()")
        op.execute("DROP TRIGGER ev_audit_insert_only ON public.audit_logs")
        op.execute("DROP FUNCTION public.ev_audit_insert_only()")
    with op.batch_alter_table("audit_logs") as batch:
        batch.drop_constraint("fk_audit_logs_evidence_id_evidence", type_="foreignkey")
        batch.drop_constraint("fk_audit_logs_case_id_cases", type_="foreignkey")
        batch.drop_index("ix_audit_logs_case_id")
        batch.drop_index("ix_audit_logs_evidence_id")
        for name in ("details_json", "evidence_id", "case_id", "actor_email", "actor_name"):
            batch.drop_column(name)
    op.drop_table("evidence_transfers")
    op.drop_table("case_members")
    with op.batch_alter_table("evidence") as batch:
        batch.drop_index("ix_evidence_custodian_id")
        batch.drop_constraint("fk_evidence_custodian_id_users", type_="foreignkey")
        for name in ("custodian_id", "source_sha256", "acquired_at", "acquisition_method", "source_reference", "source_label"):
            batch.drop_column(name)
    with op.batch_alter_table("cases") as batch:
        batch.drop_constraint("fk_cases_closed_by_users", type_="foreignkey")
        for name in ("closure_reason", "closed_by", "closed_at", "reference_number"):
            batch.drop_column(name)
