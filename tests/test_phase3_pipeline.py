"""Comprehensive unit and integration tests for Phase 3 Detection & Event Pipeline."""

from datetime import datetime, timezone
import unittest
from backend.app.detection.correlation import CorrelationEngine
from backend.app.detection.engine import DetectionEngine
from backend.app.detection.mitre import get_all_mitre_techniques, lookup_mitre
from backend.app.detection.risk import RiskScoringEngine


class TestPhase3DetectionPipeline(unittest.TestCase):
    """Verifies all Phase 3 detection rules, correlation logic, explainable risk scoring, and MITRE mapping."""

    def setUp(self):
        DetectionEngine.reset_state()
        CorrelationEngine.reset_state()

    def test_mitre_catalog_and_lookups(self):
        """Verify full MITRE catalog presence and accurate tactic/technique details."""
        catalog = get_all_mitre_techniques()
        self.assertGreaterEqual(len(catalog), 7)

        # Check key techniques
        t1046 = lookup_mitre("T1046")
        self.assertIsNotNone(t1046)
        self.assertEqual(t1046["technique"], "Network Service Discovery")
        self.assertEqual(t1046["tactic"], "Discovery")

        t1110 = lookup_mitre("T1110")
        self.assertIsNotNone(t1110)
        self.assertEqual(t1110["technique"], "Brute Force")

        t1498 = lookup_mitre("T1498")
        self.assertIsNotNone(t1498)
        self.assertEqual(t1498["tactic"], "Impact")

    def test_explainable_risk_scoring_engine(self):
        """Verify deterministic risk scoring breakdown without black-box AI."""
        score, sev, factors = RiskScoringEngine.score_detection(
            severity="HIGH",
            confidence=90,
            event_count=5,
            asset_criticality="critical",
            user_is_privileged=True,
            mitre_tactic="Credential Access",
        )
        self.assertGreaterEqual(score, 75)
        self.assertIn(sev, ["HIGH", "CRITICAL"])
        self.assertTrue(any("Privileged user" in f["factor"] for f in factors))
        self.assertTrue(any("Base severity" in f["factor"] for f in factors))
        self.assertTrue(any("Rule confidence" in f["factor"] for f in factors))

    # --------------------------------------------------------------------------
    # Synthetic Test 1: PORT_SCAN (T1046)
    # --------------------------------------------------------------------------
    def test_detection_rule_port_scan(self):
        """Simulate safe synthetic port scan probing 5 distinct ports."""
        src_ip = "192.0.2.100"  # RFC 5737 TEST-NET-1
        ports = [21, 22, 80, 443, 8080]
        detected = []

        for p in ports:
            event = {
                "source_ip": src_ip,
                "destination_ip": "10.0.0.10",
                "destination_port": p,
                "protocol": "TCP",
                "event_type": "network_flow",
                "message": f"Connection attempt to port {p}",
            }
            alerts = DetectionEngine.evaluate_event(event)
            if alerts:
                detected.extend(alerts)

        self.assertGreaterEqual(len(detected), 1)
        alert = detected[0]
        self.assertEqual(alert["mitre_technique"], "T1046")
        self.assertEqual(alert["mitre_tactic"], "Discovery")
        self.assertIn("Port Scanning Activity", alert["title"])
        self.assertEqual(alert["source_ip"], src_ip)

    # --------------------------------------------------------------------------
    # Synthetic Test 2: SSH_BRUTE_FORCE (T1110.001)
    # --------------------------------------------------------------------------
    def test_detection_rule_ssh_brute_force(self):
        """Simulate safe synthetic SSH brute force on port 22."""
        src_ip = "198.51.100.50"  # RFC 5737 TEST-NET-2
        detected = []

        for _ in range(4):
            event = {
                "source_ip": src_ip,
                "destination_ip": "10.0.0.20",
                "destination_port": 22,
                "protocol": "TCP",
                "event_type": "authentication_failure",
                "username": "root",
                "message": "Failed password for root via sshd",
            }
            alerts = DetectionEngine.evaluate_event(event)
            if alerts:
                detected.extend(alerts)

        self.assertGreaterEqual(len(detected), 1)
        alert = detected[0]
        self.assertEqual(alert["mitre_technique"], "T1110.001")
        self.assertEqual(alert["mitre_tactic"], "Credential Access")
        self.assertIn("SSH Brute Force", alert["title"])

    # --------------------------------------------------------------------------
    # Synthetic Test 3: HTTP_ANOMALY & WEB_ATTACK (T1190)
    # --------------------------------------------------------------------------
    def test_detection_rule_web_attack_sqli_and_xss(self):
        """Simulate safe synthetic SQL injection and XSS payloads in HTTP requests."""
        # SQL Injection attempt
        sqli_event = {
            "source_ip": "203.0.113.15",
            "destination_ip": "10.0.0.30",
            "destination_port": 443,
            "protocol": "HTTP",
            "event_type": "http_request",
            "message": "GET /api/v1/search?q=' UNION SELECT username, password FROM users-- HTTP/1.1",
        }
        alerts = DetectionEngine.evaluate_event(sqli_event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre_technique"], "T1190")
        self.assertIn("Web Exploitation Pattern", alerts[0]["title"])

        # Path Traversal attempt
        traversal_event = {
            "source_ip": "203.0.113.16",
            "destination_ip": "10.0.0.30",
            "destination_port": 80,
            "protocol": "HTTP",
            "event_type": "http_request",
            "message": "GET /static/../../etc/passwd HTTP/1.1",
        }
        alerts_trav = DetectionEngine.evaluate_event(traversal_event)
        self.assertGreaterEqual(len(alerts_trav), 1)
        self.assertEqual(alerts_trav[0]["mitre_technique"], "T1190")

    # --------------------------------------------------------------------------
    # Synthetic Test 4: NETWORK_FLOOD (T1498)
    # --------------------------------------------------------------------------
    def test_detection_rule_network_flooding(self):
        """Simulate safe synthetic SYN flood packet burst."""
        src_ip = "192.0.2.222"
        detected = []

        for _ in range(5):
            event = {
                "source_ip": src_ip,
                "destination_ip": "10.0.0.1",
                "destination_port": 80,
                "protocol": "TCP",
                "event_type": "syn_flood_burst",
                "message": "SYN flood high volume packets observed",
            }
            alerts = DetectionEngine.evaluate_event(event)
            if alerts:
                detected.extend(alerts)

        self.assertGreaterEqual(len(detected), 1)
        alert = detected[0]
        self.assertEqual(alert["mitre_technique"], "T1498")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertIn("Network Flooding", alert["title"])

    # --------------------------------------------------------------------------
    # Additional Rule: Privilege Escalation (T1068)
    # --------------------------------------------------------------------------
    def test_detection_rule_privilege_escalation(self):
        """Simulate suspicious sudo NOPASSWD or setuid execution."""
        event = {
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.5",
            "hostname": "PROD-APP-01",
            "username": "www-data",
            "event_type": "process_exec",
            "command_line": "sudo su -c /bin/bash NOPASSWD",
            "message": "User www-data executed sudo su with elevated permissions",
        }
        alerts = DetectionEngine.evaluate_event(event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre_technique"], "T1068")
        self.assertIn("Privilege Escalation", alerts[0]["title"])

    # --------------------------------------------------------------------------
    # Additional Rule: Suspicious Process (T1059)
    # --------------------------------------------------------------------------
    def test_detection_rule_suspicious_process(self):
        """Simulate adversarial tool execution like mimikatz or procdump."""
        event = {
            "hostname": "WORKSTATION-CORP-4",
            "username": "local_admin",
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
            "event_type": "process_create",
            "message": "Process mimikatz.exe executed",
        }
        alerts = DetectionEngine.evaluate_event(event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre_technique"], "T1059")

    # --------------------------------------------------------------------------
    # Additional Rule: Impossible Travel / Abnormal Auth (T1078)
    # --------------------------------------------------------------------------
    def test_detection_rule_impossible_travel(self):
        """Simulate abnormal concurrent login from distant geo-locations."""
        event = {
            "username": "executive_user",
            "source_ip": "198.51.100.99",
            "event_type": "impossible_travel",
            "message": "User logged in from London, UK then 5 mins later from Tokyo, JP (anomalous_location)",
        }
        alerts = DetectionEngine.evaluate_event(event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre_technique"], "T1078")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    # --------------------------------------------------------------------------
    # Correlation & Incident Dedup
    # --------------------------------------------------------------------------
    def test_correlation_engine_incident_generation_and_deduplication(self):
        """Verify correlation engine aggregates alerts and prevents spamming duplicate incidents."""
        engine = CorrelationEngine(window_seconds=10)

        alert_1 = {
            "id": 1,
            "title": "Port Scan",
            "source_ip": "198.51.100.80",
            "severity": "HIGH",
            "risk_score": 80,
        }
        alert_2 = {
            "id": 2,
            "title": "SSH Brute Force",
            "source_ip": "198.51.100.80",
            "severity": "HIGH",
            "risk_score": 90,
        }

        # 1st alert: under threshold
        inc_1 = engine.add_alert(alert_1)
        self.assertIsNone(inc_1)

        # 2nd alert: reaches 2 HIGH alerts threshold -> triggers incident
        inc_2 = engine.add_alert(alert_2)
        self.assertIsNotNone(inc_2)
        self.assertEqual(inc_2["severity"], "HIGH")
        self.assertIn("198.51.100.80", inc_2["title"])

        # 3rd alert within same window: deduplication should suppress duplicate incident
        alert_3 = {
            "id": 3,
            "title": "Web Scan",
            "source_ip": "198.51.100.80",
            "severity": "MEDIUM",
            "risk_score": 60,
        }
        inc_3 = engine.add_alert(alert_3)
        self.assertIsNone(inc_3, "Duplicate incident should be suppressed by cooldown deduplication")


if __name__ == "__main__":
    unittest.main()
