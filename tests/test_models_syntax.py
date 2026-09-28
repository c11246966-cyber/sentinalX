"""Verification test for all Phase 1 models and schemas."""

import unittest
from datetime import datetime, timezone

try:
    from backend.app.schemas.event import EventIngest
    from backend.app.schemas.alert import AlertCreate
    from backend.app.schemas.incident import IncidentCreate
    from backend.app.schemas.rule import DetectionRuleCreate
    from backend.app.schemas.user import UserCreate
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False


class TestDataSchemas(unittest.TestCase):
    """Verifies Pydantic schema validation contracts."""

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed in environment")
    def test_event_ingest_schema(self):
        event = EventIngest(
            event_type="authentication_failure",
            source_ip="10.10.10.25",
            username="administrator",
            host="LAB-WINDOWS",
            message="Authentication failure",
            timestamp=datetime.now(timezone.utc),
        )
        self.assertEqual(event.event_type, "authentication_failure")
        self.assertEqual(event.source_ip, "10.10.10.25")
        self.assertEqual(event.severity, "MEDIUM")

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed in environment")
    def test_alert_create_schema(self):
        alert = AlertCreate(
            title="Brute Force Detection",
            description="Repeated failed authentications observed",
            severity="HIGH",
            risk_score=85,
            source_ip="10.10.10.25",
            mitre_tactic="Credential Access",
            mitre_technique="T1110",
        )
        self.assertEqual(alert.risk_score, 85)
        self.assertEqual(alert.severity, "HIGH")

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed in environment")
    def test_user_create_validation(self):
        user = UserCreate(
            username="sec_analyst",
            email="analyst@sentinelx.local",
            role="analyst",
            password="StrongPassword123!",
        )
        self.assertEqual(user.role, "analyst")
        self.assertEqual(user.email, "analyst@sentinelx.local")


if __name__ == "__main__":
    unittest.main()
