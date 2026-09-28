"""Unit tests for collectors and response action framework."""

import unittest
from backend.app.collectors.windows import WindowsCollector
from backend.app.collectors.linux import LinuxCollector
from backend.app.collectors.network import NetworkCollector
from backend.app.response.actions import ResponseActionHandler
from backend.app.response.firewall import FirewallAdapter
from backend.app.services.intel_service import ThreatIntelService


class TestCollectorsAndResponse(unittest.TestCase):
    """Test telemetry ingestion normalization and safe response actions."""

    def test_threat_intel_graceful_fallback_without_keys(self):
        """Verify threat intelligence gracefully falls back without requiring API keys."""
        res = ThreatIntelService.enrich_indicator("10.0.0.1", "ip")
        self.assertEqual(res["indicator"], "10.0.0.1")
        self.assertEqual(res["reputation"], "clean")
        self.assertIn("internal", res["active_providers"])

        public_res = ThreatIntelService.enrich_indicator("198.51.100.4", "ip")
        self.assertEqual(public_res["reputation"], "unknown")
        self.assertEqual(public_res["status"], "no_external_match")

    def test_windows_collector_normalization(self):
        raw = {"EventID": 4625, "TargetUserName": "Administrator", "IpAddress": "10.0.0.5"}
        event = WindowsCollector.normalize_event(raw)
        self.assertEqual(event["source"], "windows-agent")
        self.assertEqual(event["event_type"], "windows_security")
        self.assertEqual(event["raw_data"]["EventID"], 4625)

    def test_linux_collector_normalization(self):
        raw = {"service": "sshd", "status": "Failed password", "src_ip": "192.168.1.50"}
        event = LinuxCollector.normalize_event(raw)
        self.assertEqual(event["source"], "linux-agent")
        self.assertEqual(event["event_type"], "linux_auth")

    def test_network_collector_normalization(self):
        raw = {"proto": "TCP", "src_port": 443, "dst_port": 58922, "bytes": 10240}
        event = NetworkCollector.normalize_event(raw)
        self.assertEqual(event["source"], "network")
        self.assertEqual(event["event_type"], "network_flow")

    def test_simulated_response_ip_block(self):
        result = ResponseActionHandler.simulate_ip_block("198.51.100.23", operator_id=101)
        self.assertEqual(result["status"], "simulated")
        self.assertEqual(result["target"], "198.51.100.23")
        self.assertEqual(result["operator_id"], 101)

    def test_simulated_response_host_isolation(self):
        result = ResponseActionHandler.simulate_host_isolation("WORKSTATION-09", operator_id=101)
        self.assertEqual(result["status"], "simulated")
        self.assertEqual(result["target"], "WORKSTATION-09")

    def test_firewall_safety_default(self):
        """Verify firewall adapter refuses real modifications when disabled (safe mode)."""
        adapter = FirewallAdapter(enabled=False)
        result = adapter.block_ip("203.0.113.1")
        self.assertFalse(result["success"])
        self.assertIn("disabled by default", result["reason"])


if __name__ == "__main__":
    unittest.main()
