"""Configuration manager for SentinelX Windows Endpoint Collector."""

import os
from typing import Any, Dict, Optional


class WindowsCollectorConfig:
    """Manages agent configuration via environment variables with safe defaults."""

    def __init__(self) -> None:
        self.server_url: str = os.getenv("SENTINELX_SERVER_URL", "http://localhost:3000").rstrip("/")
        self.collector_id: str = os.getenv("SENTINELX_COLLECTOR_ID", "win-standalone-01")
        self.api_key: str = os.getenv("SENTINELX_API_KEY", "")
        self.heartbeat_interval: float = float(os.getenv("SENTINELX_HEARTBEAT_INTERVAL", "30.0"))
        self.poll_interval: float = float(os.getenv("SENTINELX_POLL_INTERVAL", "5.0"))
        self.batch_size: int = int(os.getenv("SENTINELX_BATCH_SIZE", "25"))
        self.buffer_max_size: int = int(os.getenv("SENTINELX_BUFFER_MAX_SIZE", "500"))
        self.request_timeout: float = float(os.getenv("SENTINELX_REQUEST_TIMEOUT", "10.0"))
        self.test_mode: bool = os.getenv("SENTINELX_TEST_MODE", "false").lower() in ("true", "1", "yes")

    def is_configured(self) -> bool:
        """Check if minimum required credentials and endpoint are present."""
        return bool(self.server_url and self.collector_id)

    def get_ingest_url(self) -> str:
        return f"{self.server_url}/api/v1/events/ingest"

    def get_heartbeat_url(self) -> str:
        return f"{self.server_url}/api/v1/collectors/{self.collector_id}/heartbeat"

    def get_register_url(self) -> str:
        return f"{self.server_url}/api/v1/collectors/register"

    def safe_dict(self) -> Dict[str, Any]:
        """Safe configuration summary without revealing API secrets."""
        return {
            "server_url": self.server_url,
            "collector_id": self.collector_id,
            "has_api_key": bool(self.api_key),
            "heartbeat_interval": self.heartbeat_interval,
            "poll_interval": self.poll_interval,
            "batch_size": self.batch_size,
            "buffer_max_size": self.buffer_max_size,
            "request_timeout": self.request_timeout,
            "test_mode": self.test_mode,
        }
