"""005_phase6_collectors

Revision ID: 005_phase6_collectors
Revises: 004_phase5_threat_intel
Create Date: 2026-09-29 17:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '005_phase6_collectors'
down_revision: Union[str, None] = '004_phase5_threat_intel'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'collectors',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('collector_id', sa.String(length=64), nullable=False, unique=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('operating_system', sa.String(length=100), server_default='Windows', nullable=False),
        sa.Column('agent_version', sa.String(length=50), server_default='1.0.0', nullable=False),
        sa.Column('status', sa.String(length=20), server_default='ONLINE', nullable=False),
        sa.Column('api_key_hash', sa.String(length=128), nullable=False),
        sa.Column('registered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('alert_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )
    op.create_index('ix_collectors_collector_id', 'collectors', ['collector_id'])
    op.create_index('ix_collectors_hostname', 'collectors', ['hostname'])
    op.create_index('ix_collectors_status', 'collectors', ['status'])
    op.create_index('ix_collectors_last_seen', 'collectors', ['last_seen'])


def downgrade() -> None:
    op.drop_index('ix_collectors_last_seen', table_name='collectors')
    op.drop_index('ix_collectors_status', table_name='collectors')
    op.drop_index('ix_collectors_hostname', table_name='collectors')
    op.drop_index('ix_collectors_collector_id', table_name='collectors')
    op.drop_table('collectors')
