"""Keep the latest integrity observation independently of manual verification.

Revision ID: d91a3b6c8e20
Revises: c83f4e7a0d12
"""

from alembic import op
import sqlalchemy as sa


revision = "d91a3b6c8e20"
down_revision = "c83f4e7a0d12"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("evidence") as batch_op:
        batch_op.add_column(sa.Column("observed_integrity_status", sa.String(20), nullable=True))
        batch_op.add_column(sa.Column("observed_integrity_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.create_check_constraint(op.f("ck_evidence_valid_observed_integrity_status"),
            "observed_integrity_status IN ('verified', 'modified', 'missing')")


def downgrade():
    with op.batch_alter_table("evidence") as batch_op:
        batch_op.drop_constraint(op.f("ck_evidence_valid_observed_integrity_status"), type_="check")
        batch_op.drop_column("observed_integrity_at")
        batch_op.drop_column("observed_integrity_status")
