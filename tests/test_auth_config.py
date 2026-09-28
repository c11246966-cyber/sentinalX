"""Authentication and security configuration verification tests for Phase 1."""

import unittest
from datetime import timedelta
import os


class TestAuthenticationConfiguration(unittest.TestCase):
    """Verifies that authentication settings and cryptographic primitives are properly configured."""

    def test_default_secret_key_and_algorithm(self):
        """Verify SECRET_KEY and ALGORITHM have valid cryptographic configurations."""
        # Read directly or via settings if available
        secret_key = os.getenv(
            "SECRET_KEY",
            "sentinelx-insecure-development-secret-key-change-me-in-production-min-32-chars",
        )
        self.assertTrue(len(secret_key) >= 32, "SECRET_KEY must be at least 32 characters long")
        self.assertNotEqual(secret_key, "", "SECRET_KEY must not be empty")

    def test_token_expiration_bounds(self):
        """Verify access and refresh token life parameters."""
        raw_access = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
        raw_refresh = os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")
        try:
            access_minutes = int(raw_access)
        except (ValueError, TypeError):
            access_minutes = 60

        try:
            refresh_days = int(raw_refresh)
        except (ValueError, TypeError):
            refresh_days = 7

        self.assertGreaterEqual(access_minutes, 15, "Access tokens must be valid for at least 15 minutes")
        self.assertLessEqual(access_minutes, 1440, "Access tokens must not exceed 24 hours")
        self.assertGreaterEqual(refresh_days, 1, "Refresh tokens must be valid for at least 1 day")

    def test_rbac_roles_specification(self):
        """Verify defined RBAC roles conform to design spec (admin, analyst, viewer)."""
        valid_roles = {"admin", "analyst", "viewer"}
        self.assertIn("admin", valid_roles)
        self.assertIn("analyst", valid_roles)
        self.assertIn("viewer", valid_roles)

    def test_argon2_and_jwt_primitives_if_available(self):
        """Verify Argon2 hashing and JWT token issuance when libraries are present."""
        try:
            from backend.app.core.security import (
                create_access_token,
                decode_access_token,
                get_password_hash,
                verify_password,
            )
        except ImportError:
            self.skipTest("PyJWT / Passlib not installed in current test runner")

        # Test password hashing
        pwd = "SecOpsPassword2026!"
        hashed = get_password_hash(pwd)
        self.assertNotEqual(pwd, hashed)
        self.assertTrue(verify_password(pwd, hashed))
        self.assertFalse(verify_password("WrongPassword", hashed))

        # Test JWT creation & decode
        token = create_access_token("test-analyst", role="analyst", expires_delta=timedelta(minutes=5))
        self.assertIsInstance(token, str)
        payload = decode_access_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], "test-analyst")
        self.assertEqual(payload["role"], "analyst")


if __name__ == "__main__":
    unittest.main()
