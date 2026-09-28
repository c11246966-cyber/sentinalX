"""002_phase3_pipeline

Revision ID: 002_phase3_pipeline
Revises: 001_initial_schema
Create Date: 2026-09-28 17:05:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_phase3_pipeline'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new Phase 3 columns to events table if not already present
    with op.batch_alter_table('events') as batch_op:
        batch_op.add_column(sa.Column('event_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('protocol', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('hostname', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('raw_event', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('normalized_event', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('mitre_technique', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('status', sa.String(length=30), server_default='PROCESSED', nullable=True))

    # Add indexes for fast querying and correlation
    op.create_index(op.f('ix_events_event_id'), 'events', ['event_id'], unique=True)
    op.create_index(op.f('ix_events_hostname'), 'events', ['hostname'], unique=False)
    op.create_index(op.f('ix_events_mitre_technique'), 'events', ['mitre_technique'], unique=False)
    op.create_index('idx_events_hostname_timestamp', 'events', ['hostname', 'timestamp'])
    op.create_index('idx_events_username_timestamp', 'events', ['username', 'timestamp'])


def downgrade() -> None:
    op.drop_index('idx_events_username_timestamp', table_name='events')
    op.drop_index('idx_events_hostname_timestamp', table_name='events')
    op.drop_index(op.f('ix_events_mitre_technique'), table_name='events')
    op.drop_index(op.f('ix_events_hostname'), table_name='events')
    op.drop_index(op.f('ix_events_event_id'), table_name='events')

    with op.batch_alter_table('events') as batch_op:
        batch_op.drop_column('status')
        batch_op.drop_column('mitre_technique')
        batch_op.drop_column('normalized_event')
        batch_op.drop_column('raw_event')
        batch_op.drop_column('hostname')
        batch_op.drop_column('protocol')
        batch_op.drop_column('event_id')
