"""Abstract base class and contract for Threat Intelligence Providers."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional
from backend.app.core.logging import logger


class BaseThreatIntelProvider(ABC):
    """Base provider interface for external and internal threat intelligence feeds.
    
    Guarantees:
    - Zero secret leakage in logs or exceptions
    - Graceful degradation when API keys are unconfigured
    - Bounded execution with timeout limits
    - Rate limit awareness and non-blocking failure
    """

    def __init__(self, name: str, supported_types: List[str], timeout: float = 5.0) -> None:
        self.name = name
        self.supported_types = supported_types
        self.timeout = timeout
        self._rate_limited_until: float = 0.0

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the provider has valid API credentials configured."""
        pass

    def is_available(self) -> bool:
        """Returns True if the provider is configured and not currently rate-limited."""
        if not self.is_configured():
            return False
        if time.time() < self._rate_limited_until:
            return False
        return True

    def mark_rate_limited(self, duration_seconds: float = 60.0) -> None:
        """Temporarily mark provider as rate-limited to avoid hammering."""
        self._rate_limited_until = time.time() + duration_seconds
        logger.warning(f"Threat intelligence provider '{self.name}' rate-limited for {duration_seconds}s.")

    def safe_metadata(self) -> Dict[str, Any]:
        """Return safe provider status metadata without any credentials."""
        configured = self.is_configured()
        is_external = self.name != "internal"
        if not is_external:
            status_str = "operational"
            name_str = "Internal Curated Feed"
        elif not configured:
            status_str = "unconfigured"
            name_str = self.name
        elif time.time() < self._rate_limited_until:
            status_str = "rate_limited"
            name_str = self.name
        else:
            status_str = "operational"
            name_str = self.name

        return {
            "name": name_str,
            "provider_id": self.name,
            "configured": configured,
            "external": is_external,
            "status": status_str,
            "available": self.is_available(),
            "supported_types": self.supported_types,
            "rate_limited": time.time() < self._rate_limited_until,
        }

    @abstractmethod
    async def enrich(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query the provider for reputation data.
        
        Must return normalized dictionary:
        {
            "provider": self.name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": "clean" | "suspicious" | "malicious" | "unknown",
            "confidence": 0-100,
            "severity": "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "tags": ["scanner", "c2", ...],
            "first_seen": datetime,
            "last_seen": datetime,
            "source": self.name,
            "raw_provider_metadata": {...safe fields...}
        }
        """
        pass
