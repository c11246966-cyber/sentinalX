"""SentinelX Windows Endpoint Telemetry Collector Package."""

from collectors.windows.config import WindowsCollectorConfig
from collectors.windows.normalizer import WindowsEventNormalizer
from collectors.windows.sender import WindowsEventSender
from collectors.windows.health import get_host_telemetry

__all__ = [
    "WindowsCollectorConfig",
    "WindowsEventNormalizer",
    "WindowsEventSender",
    "get_host_telemetry",
]
