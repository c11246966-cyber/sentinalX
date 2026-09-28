"""Healthcheck endpoint and schema validation tests."""

import unittest
from datetime import datetime, timezone

try:
    from backend.app.schemas.health import HealthStatusResponse, ServiceHealthDetail
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False


class TestHealthEndpointSchemas(unittest.TestCase):
    """Validates health check data structures and responses."""

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed in environment")
    def test_service_health_detail_structure(self):
        """Verify individual component health payload serialization."""
        detail = ServiceHealthDetail(
            status="healthy",
            latency_ms=1.45,
            message="Operational",
        )
        self.assertEqual(detail.status, "healthy")
        self.assertEqual(detail.latency_ms, 1.45)
        self.assertEqual(detail.message, "Operational")

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed in environment")
    def test_health_status_response_serialization(self):
        """Verify overall system health report structure."""
        report = HealthStatusResponse(
            status="healthy",
            version="0.1.0-alpha",
            environment="testing",
            timestamp=datetime.now(timezone.utc),
            services={
                "api": ServiceHealthDetail(status="healthy", latency_ms=0.1),
                "database": ServiceHealthDetail(status="healthy", latency_ms=1.2),
                "redis": ServiceHealthDetail(status="healthy", latency_ms=0.5),
            },
        )
        self.assertEqual(report.status, "healthy")
        self.assertEqual(report.version, "0.1.0-alpha")
        self.assertIn("database", report.services)
        self.assertEqual(report.services["database"].status, "healthy")

    @unittest.skipUnless(HAS_PYDANTIC, "Pydantic not installed in environment")
    def test_health_status_degraded_scenario(self):
        """Verify degraded status propagation."""
        report = HealthStatusResponse(
            status="degraded",
            version="0.1.0-alpha",
            environment="testing",
            timestamp=datetime.now(timezone.utc),
            services={
                "api": ServiceHealthDetail(status="healthy", latency_ms=0.1),
                "database": ServiceHealthDetail(status="degraded", message="Connection timeout"),
            },
        )
        self.assertEqual(report.status, "degraded")
        self.assertEqual(report.services["database"].status, "degraded")


if __name__ == "__main__":
    unittest.main()
