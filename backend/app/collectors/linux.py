"""Linux Syslog / Auditd Collector Interface (Scheduled for Phase 9)."""

from typing import Any, Dict


class LinuxCollector:
    """Parses Linux auth.log, journald, and auditd events."""

    @staticmethod
    def normalize_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert raw Linux auth event into SentinelX schema."""
        return {
            "source": "linux-agent",
            "event_type": "linux_auth",
            "raw_data": raw_event,
        }
