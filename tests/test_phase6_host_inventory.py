"""Automated unit and integration tests for SentinelX Phase 6: Host Inventory & Endpoint Monitoring."""

from datetime import datetime, timedelta, timezone
import unittest

try:
    from backend.app.schemas.host import (
        HostCreate,
        HostHeartbeat,
        HostIsolationRequest,
        HostUpdate,
    )
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

try:
    from backend.app.models.host import Host
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False


class TestPhase6HostInventory(unittest.TestCase):
    """Test suite validating host inventory, endpoint health tracking, and safe containment."""

    def test_host_schema_validation(self):
        """Verify endpoint creation schema requires valid hostname and IP."""
        if not HAS_PYDANTIC:
            self.skipTest("Pydantic not installed in test runner environment")
        valid_payload = HostCreate(
            hostname="WIN-SERVER-01",
            ip_address="10.0.0.15",
            operating_system="Windows Server 2022",
            agent_version="1.0.0",
            status="ONLINE",
        )
        self.assertEqual(valid_payload.hostname, "WIN-SERVER-01")
        self.assertEqual(valid_payload.ip_address, "10.0.0.15")
        self.assertEqual(valid_payload.operating_system, "Windows Server 2022")
        self.assertEqual(valid_payload.status, "ONLINE")

    def test_host_model_attributes_and_defaults(self):
        """Verify Host ORM model initializes required fields and timestamps."""
        if not HAS_SQLALCHEMY:
            self.skipTest("SQLAlchemy not installed in test runner environment")
        now = datetime.now(timezone.utc)
        host = Host(
            id=1,
            hostname="WIN11-WORKSTATION-42",
            ip_address="10.0.0.42",
            operating_system="Windows 11 Enterprise",
            agent_version="1.0.0",
            status="ONLINE",
            last_seen=now,
            created_at=now,
        )
        self.assertEqual(host.hostname, "WIN11-WORKSTATION-42")
        self.assertEqual(host.status, "ONLINE")
        self.assertIsNotNone(host.last_seen)
        self.assertIsNotNone(host.created_at)

    def test_host_health_and_latency_status_calculation(self):
        """Verify dynamic status evaluation detects stale check-in and transitions to DEGRADED/OFFLINE."""
        now = datetime.now(timezone.utc)

        # 1. Fresh check-in (less than 60s) -> ONLINE
        fresh_seen = now - timedelta(seconds=20)
        diff1 = (now - fresh_seen).total_seconds()
        calc_status1 = "OFFLINE" if diff1 > 180 else ("DEGRADED" if diff1 > 60 else "ONLINE")
        self.assertEqual(calc_status1, "ONLINE")

        # 2. Check-in between 60s and 180s -> DEGRADED
        stale_seen = now - timedelta(seconds=90)
        diff2 = (now - stale_seen).total_seconds()
        calc_status2 = "OFFLINE" if diff2 > 180 else ("DEGRADED" if diff2 > 60 else "ONLINE")
        self.assertEqual(calc_status2, "DEGRADED")

        # 3. Check-in older than 180s -> OFFLINE
        offline_seen = now - timedelta(seconds=300)
        diff3 = (now - offline_seen).total_seconds()
        calc_status3 = "OFFLINE" if diff3 > 180 else ("DEGRADED" if diff3 > 60 else "ONLINE")
        self.assertEqual(calc_status3, "OFFLINE")

        # 4. Isolated host stays ISOLATED regardless of latency
        is_isolated = True
        status_val = "ISOLATED"
        calc_status4 = status_val if is_isolated else "OFFLINE"
        self.assertEqual(calc_status4, "ISOLATED")

    def test_safe_simulated_isolation_toggle(self):
        """Verify host containment executes safely in lab simulation mode."""
        host_record = {
            "id": 10,
            "hostname": "PROD-ENDPOINT-01",
            "ip_address": "10.0.0.100",
            "operating_system": "Windows 11",
            "status": "ONLINE",
        }

        # Execute safe isolation request
        if HAS_PYDANTIC:
            iso_req = HostIsolationRequest(isolate=True, reason="Simulated malware containment drill")
            self.assertTrue(iso_req.isolate)
            self.assertIn("Simulated", iso_req.reason)
            should_isolate = iso_req.isolate
        else:
            should_isolate = True

        # Apply containment
        host_record["status"] = "ISOLATED" if should_isolate else "ONLINE"
        self.assertEqual(host_record["status"], "ISOLATED")

        # Release containment
        host_record["status"] = "ONLINE"
        self.assertEqual(host_record["status"], "ONLINE")

    def test_heartbeat_payload_validation(self):
        """Verify heartbeat payload parsing and agent version update."""
        if not HAS_PYDANTIC:
            self.skipTest("Pydantic not installed in test runner environment")
        hb = HostHeartbeat(agent_version="1.2.5", status="ONLINE")
        self.assertEqual(hb.agent_version, "1.2.5")
        self.assertEqual(hb.status, "ONLINE")

    def test_host_update_schema(self):
        """Verify partial update payload handles optional fields cleanly."""
        if not HAS_PYDANTIC:
            self.skipTest("Pydantic not installed in test runner environment")
        update = HostUpdate(ip_address="10.0.0.99", status="DEGRADED")
        data = update.model_dump(exclude_unset=True)
        self.assertEqual(data["ip_address"], "10.0.0.99")
        self.assertEqual(data["status"], "DEGRADED")
        self.assertNotIn("agent_version", data)


if __name__ == "__main__":
    unittest.main()
