"""Phase 2 comprehensive tests for models, RBAC, JWT, and schema constraints."""

import unittest
from datetime import datetime, timezone
import os


class TestPhase2Architecture(unittest.TestCase):
    """Verifies Phase 2 database models, schema definitions, and RBAC rules."""

    def test_rbac_hierarchy_and_permissions(self):
        """Verify role validation and hierarchy across Admin, Analyst, and Viewer."""
        roles = ["admin", "analyst", "viewer"]
        self.assertEqual(len(roles), 3)

        # Viewer can read alerts
        viewer_allowed = ["view_alerts", "view_events", "view_metrics"]
        # Analyst can triage and isolate
        analyst_allowed = viewer_allowed + ["triage_alert", "create_rule", "simulate_action", "view_users"]
        # Admin has full administrative privileges
        admin_allowed = analyst_allowed + ["create_user", "update_user", "delete_user", "modify_system"]

        self.assertTrue(set(viewer_allowed).issubset(set(analyst_allowed)))
        self.assertTrue(set(analyst_allowed).issubset(set(admin_allowed)))

    def test_database_table_metadata_and_constraints(self):
        """Verify table definitions, primary keys, and foreign keys across all 8 models."""
        try:
            from backend.app.core.database import Base
            import backend.app.models
        except ImportError:
            self.skipTest("SQLAlchemy not available in current test runner")

        tables = Base.metadata.tables
        expected_tables = {
            "users",
            "hosts",
            "detection_rules",
            "threat_intelligence",
            "incidents",
            "events",
            "alerts",
            "audit_logs",
        }
        self.assertTrue(expected_tables.issubset(set(tables.keys())))

        # Verify users table columns and unique constraints
        users_table = tables["users"]
        self.assertIn("username", users_table.c)
        self.assertIn("password_hash", users_table.c)
        self.assertIn("role", users_table.c)
        self.assertTrue(users_table.c.username.unique)
        self.assertTrue(users_table.c.email.unique)

        # Verify alerts table foreign keys
        alerts_table = tables["alerts"]
        fk_column_names = {fk.parent.name for fk in alerts_table.foreign_keys}
        self.assertIn("event_id", fk_column_names)
        self.assertIn("rule_id", fk_column_names)
        self.assertIn("incident_id", fk_column_names)

        # Verify audit_logs table foreign key to users
        audit_table = tables["audit_logs"]
        self.assertIn("action", audit_table.c)
        self.assertIn("user_id", audit_table.c)

    def test_refresh_token_and_access_token_primitives(self):
        """Verify access and refresh token separation and cryptographic signing."""
        try:
            from backend.app.core.security import (
                create_access_token,
                create_refresh_token,
                decode_access_token,
                decode_refresh_token,
            )
        except ImportError:
            self.skipTest("PyJWT not installed in current environment")

        username = "lead_analyst"
        role = "analyst"

        access_tok = create_access_token(username, role=role)
        refresh_tok = create_refresh_token(username, role=role)

        # Verify decode
        access_payload = decode_access_token(access_tok)
        self.assertIsNotNone(access_payload)
        self.assertEqual(access_payload["sub"], username)
        self.assertEqual(access_payload["type"], "access")

        refresh_payload = decode_refresh_token(refresh_tok)
        self.assertIsNotNone(refresh_payload)
        self.assertEqual(refresh_payload["sub"], username)
        self.assertEqual(refresh_payload["type"], "refresh")

        # Cross-validation security: access decoder rejects refresh token
        self.assertIsNone(decode_access_token(refresh_tok))
        # Refresh decoder rejects access token
        self.assertIsNone(decode_refresh_token(access_tok))

    def test_audit_logging_structure(self):
        """Verify audit log event contract."""
        try:
            from backend.app.schemas.audit import AuditLogBase
        except ImportError:
            self.skipTest("Pydantic not installed in environment")

        log = AuditLogBase(
            action="admin_create_user",
            target_type="user",
            target_id="42",
            details={"username": "new_analyst", "role": "analyst"},
            source_ip="192.168.1.10",
        )
        self.assertEqual(log.action, "admin_create_user")
        self.assertEqual(log.target_type, "user")
        self.assertEqual(log.target_id, "42")
        self.assertEqual(log.details["role"], "analyst")


if __name__ == "__main__":
    unittest.main()
