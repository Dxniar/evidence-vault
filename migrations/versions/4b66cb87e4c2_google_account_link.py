"""Add a stable Google identity to existing users.

Revision ID: 4b66cb87e4c2
Revises: 7ec93bba54e5
"""

from alembic import op
import sqlalchemy as sa


revision = "4b66cb87e4c2"
down_revision = "7ec93bba54e5"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("google_sub", sa.String(length=255), nullable=True))
        batch_op.create_unique_constraint("uq_users_google_sub", ["google_sub"])


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("uq_users_google_sub", type_="unique")
        batch_op.drop_column("google_sub")
