"""004_phase5_threat_intel

Revision ID: 004_phase5_threat_intel
Revises: 003_phase4_dashboard
Create Date: 2026-09-29 17:20:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '004_phase5_threat_intel'
down_revision: Union[str, None] = '003_phase4_dashboard'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('threat_intelligence') as batch_op:
        batch_op.add_column(sa.Column('severity', sa.String(length=20), server_default='LOW', nullable=False))
        batch_op.add_column(sa.Column('tags', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('source', sa.String(length=100), server_default='threat_intel', nullable=True))
        batch_op.add_column(sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True))

    with op.batch_alter_table('alerts') as batch_op:
        batch_op.add_column(sa.Column('threat_intel_context', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('risk_adjustment_reason', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('alerts') as batch_op:
        batch_op.drop_column('risk_adjustment_reason')
        batch_op.drop_column('threat_intel_context')

    with op.batch_alter_table('threat_intelligence') as batch_op:
        batch_op.drop_column('updated_at')
        batch_op.drop_column('source')
        batch_op.drop_column('tags')
        batch_op.drop_column('severity')
