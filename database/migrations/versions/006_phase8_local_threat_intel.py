"""006_phase8_local_threat_intel

Revision ID: 006_phase8_local_threat_intel
Revises: 005_phase6_collectors
Create Date: 2026-10-01 12:00:00.000000

"""
from typing import Sequence, Union
try:
    from alembic import op
    import sqlalchemy as sa
except ImportError:
    op = None
    sa = None

# revision identifiers, used by Alembic.
revision: str = '006_phase8_local_threat_intel'
down_revision: Union[str, None] = '005_phase6_collectors'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if op is None:
        return
    with op.batch_alter_table('threat_intelligence') as batch_op:
        batch_op.add_column(sa.Column('threat_category', sa.String(length=100), server_default='General Threat', nullable=True))
        batch_op.add_column(sa.Column('description', sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column('matching_reason', sa.String(length=500), nullable=True))


def downgrade() -> None:
    if op is None:
        return
    with op.batch_alter_table('threat_intelligence') as batch_op:
        batch_op.drop_column('matching_reason')
        batch_op.drop_column('description')
        batch_op.drop_column('threat_category')
