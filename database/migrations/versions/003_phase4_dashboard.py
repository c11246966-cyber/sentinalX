"""003_phase4_dashboard

Revision ID: 003_phase4_dashboard
Revises: 002_phase3_pipeline
Create Date: 2026-09-28 17:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '003_phase4_dashboard'
down_revision: Union[str, None] = '002_phase3_pipeline'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('alerts') as batch_op:
        batch_op.add_column(sa.Column('analyst_notes', sa.Text(), nullable=True))

    with op.batch_alter_table('incidents') as batch_op:
        batch_op.add_column(sa.Column('analyst_notes', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('incidents') as batch_op:
        batch_op.drop_column('analyst_notes')

    with op.batch_alter_table('alerts') as batch_op:
        batch_op.drop_column('analyst_notes')
