"""Pytest fixtures and test environment configuration."""

import os
import pytest
from typing import Generator

# Set test environment flags
os.environ["ENVIRONMENT"] = "testing"
os.environ["DEBUG"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key-32-characters-minimum-for-testing"


@pytest.fixture(scope="session")
def test_settings():
    """Returns application test settings instance."""
    from backend.app.core.config import settings
    return settings
