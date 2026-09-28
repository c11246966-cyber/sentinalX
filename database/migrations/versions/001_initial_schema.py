"""001_initial_schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-09-28 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False, server_default='viewer'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # 2. hosts table
    op.create_table(
        'hosts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('operating_system', sa.String(length=100), nullable=False),
        sa.Column('agent_version', sa.String(length=50), nullable=False, server_default='1.0.0'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='ONLINE'),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_hosts_id'), 'hosts', ['id'], unique=False)
    op.create_index(op.f('ix_hosts_hostname'), 'hosts', ['hostname'], unique=True)
    op.create_index(op.f('ix_hosts_ip_address'), 'hosts', ['ip_address'], unique=False)
    op.create_index(op.f('ix_hosts_status'), 'hosts', ['status'], unique=False)

    # 3. detection_rules table
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=150), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('rule_type', sa.String(length=50), nullable=False, server_default='threshold'),
        sa.Column('rule_definition', sa.JSON(), nullable=False),
        sa.Column('mitre_tactic', sa.String(length=100), nullable=True),
        sa.Column('mitre_technique', sa.String(length=100), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_detection_rules_id'), 'detection_rules', ['id'], unique=False)
    op.create_index(op.f('ix_detection_rules_name'), 'detection_rules', ['name'], unique=True)
    op.create_index(op.f('ix_detection_rules_category'), 'detection_rules', ['category'], unique=False)
    op.create_index(op.f('ix_detection_rules_enabled'), 'detection_rules', ['enabled'], unique=False)

    # 4. threat_intelligence table
    op.create_table(
        'threat_intelligence',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('indicator', sa.String(length=255), nullable=False),
        sa.Column('indicator_type', sa.String(length=30), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False, server_default='internal'),
        sa.Column('reputation', sa.String(length=30), nullable=False, server_default='unknown'),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('raw_response', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_intelligence_id'), 'threat_intelligence', ['id'], unique=False)
    op.create_index(op.f('ix_threat_intelligence_indicator'), 'threat_intelligence', ['indicator'], unique=True)
    op.create_index(op.f('ix_threat_intelligence_indicator_type'), 'threat_intelligence', ['indicator_type'], unique=False)
    op.create_index('idx_intel_indicator_lookup', 'threat_intelligence', ['indicator', 'indicator_type'])

    # 5. incidents table
    op.create_table(
        'incidents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='NEW'),
        sa.Column('assigned_to', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incidents_id'), 'incidents', ['id'], unique=False)
    op.create_index(op.f('ix_incidents_title'), 'incidents', ['title'], unique=False)
    op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)

    # 6. events table
    op.create_table(
        'events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('host_id', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='INFORMATIONAL'),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('destination_ip', sa.String(length=45), nullable=True),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('destination_port', sa.Integer(), nullable=True),
        sa.Column('username', sa.String(length=100), nullable=True),
        sa.Column('process_name', sa.String(length=255), nullable=True),
        sa.Column('command_line', sa.Text(), nullable=True),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('raw_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_events_id'), 'events', ['id'], unique=False)
    op.create_index(op.f('ix_events_host_id'), 'events', ['host_id'], unique=False)
    op.create_index(op.f('ix_events_timestamp'), 'events', ['timestamp'], unique=False)
    op.create_index(op.f('ix_events_event_type'), 'events', ['event_type'], unique=False)
    op.create_index(op.f('ix_events_source_ip'), 'events', ['source_ip'], unique=False)
    op.create_index(op.f('ix_events_destination_ip'), 'events', ['destination_ip'], unique=False)
    op.create_index(op.f('ix_events_username'), 'events', ['username'], unique=False)
    op.create_index('idx_events_type_timestamp', 'events', ['event_type', 'timestamp'])
    op.create_index('idx_events_source_ip_timestamp', 'events', ['source_ip', 'timestamp'])

    # 7. alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('event_id', sa.Integer(), nullable=True),
        sa.Column('rule_id', sa.Integer(), nullable=True),
        sa.Column('incident_id', sa.Integer(), nullable=True),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='NEW'),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('destination_ip', sa.String(length=45), nullable=True),
        sa.Column('mitre_tactic', sa.String(length=100), nullable=True),
        sa.Column('mitre_technique', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['event_id'], ['events.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['rule_id'], ['detection_rules.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_id'), 'alerts', ['id'], unique=False)
    op.create_index(op.f('ix_alerts_event_id'), 'alerts', ['event_id'], unique=False)
    op.create_index(op.f('ix_alerts_rule_id'), 'alerts', ['rule_id'], unique=False)
    op.create_index(op.f('ix_alerts_incident_id'), 'alerts', ['incident_id'], unique=False)
    op.create_index(op.f('ix_alerts_title'), 'alerts', ['title'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)
    op.create_index(op.f('ix_alerts_risk_score'), 'alerts', ['risk_score'], unique=False)
    op.create_index(op.f('ix_alerts_created_at'), 'alerts', ['created_at'], unique=False)
    op.create_index('idx_alerts_status_severity', 'alerts', ['status', 'severity'])
    op.create_index('idx_alerts_risk_score_desc', 'alerts', [sa.text('risk_score DESC')])

    # 8. audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_id', sa.String(length=100), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_timestamp'), 'audit_logs', ['timestamp'], unique=False)
    op.create_index('idx_audit_action_timestamp', 'audit_logs', ['action', sa.text('timestamp DESC')])


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('alerts')
    op.drop_table('events')
    op.drop_table('incidents')
    op.drop_table('threat_intelligence')
    op.drop_table('detection_rules')
    op.drop_table('hosts')
    op.drop_table('users')
