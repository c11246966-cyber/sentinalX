"""Firewall integration interface with strict confirmation controls."""

from typing import Any, Dict


class FirewallAdapter:
    """Interface for real firewall integration. Requires explicit admin authorization."""

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    def block_ip(self, ip_address: str) -> Dict[str, Any]:
        if not self.enabled:
            return {
                "success": False,
                "reason": "Firewall modifications are disabled by default in laboratory mode.",
            }
        return {"success": True, "blocked": ip_address}
