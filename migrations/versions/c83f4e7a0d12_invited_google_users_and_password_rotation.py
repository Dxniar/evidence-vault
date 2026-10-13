"""Allow preapproved Google-only users and first-login password rotation.

Revision ID: c83f4e7a0d12
Revises: 4b66cb87e4c2
"""

from alembic import op
import sqlalchemy as sa


revision = "c83f4e7a0d12"
down_revision = "4b66cb87e4c2"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("has_local_password", sa.Boolean(),
                                      nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column("must_change_password", sa.Boolean(),
                                      nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("google_invite_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("google_invite_expires_at")
        batch_op.drop_column("must_change_password")
        batch_op.drop_column("has_local_password")
