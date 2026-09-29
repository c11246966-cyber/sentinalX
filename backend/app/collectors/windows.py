"""Windows Event Log Collector Interface for Phase 6."""

from typing import Any, Dict
from collectors.windows.normalizer import WindowsEventNormalizer


class WindowsCollector:
    """Parses and normalizes Windows Event Log telemetry."""

    @staticmethod
    def normalize_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert raw Event ID (4624, 4625, 4688, etc.) into SentinelX schema."""
        return WindowsEventNormalizer.normalize_event(raw_event)

