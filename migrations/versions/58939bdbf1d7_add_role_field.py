"""Add role field

Revision ID: 58939bdbf1d7
Revises: b50263b37f36
Create Date: 2025-07-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '58939bdbf1d7'
down_revision = 'b50263b37f36'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role', sa.String(length=10), nullable=False, server_default='user'))
    op.execute("UPDATE user SET role='user' WHERE role IS NULL")
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('role', server_default=None)


def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('role')
