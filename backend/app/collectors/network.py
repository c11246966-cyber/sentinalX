"""Network telemetry and flow collector interface."""

from typing import Any, Dict


class NetworkCollector:
    """Parses network flow logs (NetFlow, Suricata, Zeek)."""

    @staticmethod
    def normalize_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source": "network",
            "event_type": "network_flow",
            "raw_data": raw_event,
        }
