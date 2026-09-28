"""Unit tests for configuration, risk scoring calculation, and MITRE mapping."""

import unittest
from backend.app.detection.risk import RiskScoringEngine
from backend.app.detection.mitre import lookup_mitre

try:
    from backend.app.core.config import Settings
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False


class TestSentinelXCore(unittest.TestCase):
    """Core configuration and algorithmic unit tests."""

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed in current environment")
    def test_settings_initialization(self):
        """Verify default settings instantiation and type parsing."""
        settings = Settings(
            ENVIRONMENT="testing",
            SECRET_KEY="a" * 32,
            CORS_ORIGINS="http://localhost:3000,http://127.0.0.1:3000",
        )
        self.assertEqual(settings.ENVIRONMENT, "testing")
        self.assertIn("http://localhost:3000", settings.CORS_ORIGINS)
        self.assertIn("http://127.0.0.1:3000", settings.CORS_ORIGINS)
        self.assertEqual(settings.API_V1_STR, "/api/v1")
        self.assertTrue(len(settings.SECRET_KEY) >= 32)
        # Verify optional integrations default to None / empty with no errors
        self.assertIsNone(settings.REDIS_PASSWORD)
        self.assertIsNone(settings.VIRUSTOTAL_API_KEY)
        self.assertIsNone(settings.ABUSEIPDB_API_KEY)
        self.assertIsNone(settings.ALIENVAULT_OTX_KEY)
        self.assertEqual(settings.REDIS_URL, "redis://redis:6379/0")

    def test_risk_scoring_bounds_and_severity(self):
        """Test risk score calculation logic, clamping between 0 and 100."""
        # Low risk
        score, severity = RiskScoringEngine.calculate_score([{"factor": "auth_failure", "points": 20}])
        self.assertEqual(score, 20)
        self.assertEqual(severity, "INFORMATIONAL")

        # Medium risk
        score, severity = RiskScoringEngine.calculate_score([
            {"factor": "auth_failure", "points": 30},
            {"factor": "port_scan", "points": 30},
        ])
        self.assertEqual(score, 60)
        self.assertEqual(severity, "MEDIUM")

        # Critical risk clamped at 100
        score, severity = RiskScoringEngine.calculate_score([
            {"factor": "root_compromise", "points": 60},
            {"factor": "c2_beacon", "points": 60},
        ])
        self.assertEqual(score, 100)
        self.assertEqual(severity, "CRITICAL")

    def test_mitre_mapping_known_techniques(self):
        """Verify MITRE lookup table maps accurate technique IDs and tactics."""
        mapping = lookup_mitre("T1110")
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping["technique"], "Brute Force")
        self.assertEqual(mapping["tactic"], "Credential Access")

        mapping_invalid = lookup_mitre("NONEXISTENT_9999")
        self.assertIsNone(mapping_invalid)


if __name__ == "__main__":
    unittest.main()
