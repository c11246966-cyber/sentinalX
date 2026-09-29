"""Windows Event Log telemetry normalization and security sanitization."""

from datetime import datetime, timezone
import re
from typing import Any, Dict, Optional

# Regex patterns to sanitize sensitive credentials if accidentally present in command lines
SENSITIVE_ARGS_REGEX = re.compile(r"(-p|-password|/p|/password|--pass|--password)\s+([^\s]+)", re.IGNORECASE)


class WindowsEventNormalizer:
    """Transforms raw Windows Security, PowerShell, Defender, and Network events into SentinelX schema."""

    EVENT_ID_MAP = {
        4624: ("windows_successful_logon", "INFORMATIONAL", "T1078"),
        4625: ("windows_failed_logon", "MEDIUM", "T1110.001"),
        4672: ("windows_privileged_logon", "LOW", "T1078.002"),
        4688: ("windows_process_creation", "LOW", "T1059.003"),
        4720: ("windows_account_created", "LOW", "T1136.001"),
        4738: ("windows_account_modified", "LOW", "T1098"),
        4104: ("windows_powershell", "MEDIUM", "T1059.001"),
        4103: ("windows_powershell", "LOW", "T1059.001"),
        1116: ("windows_defender", "HIGH", "T1562.001"),
        1117: ("windows_defender", "HIGH", "T1562.001"),
        5001: ("windows_defender", "CRITICAL", "T1562.001"),
        5156: ("windows_network", "LOW", "T1071"),
    }

    @classmethod
    def sanitize_command_line(cls, cmd: Optional[str]) -> Optional[str]:
        """Scrub potential cleartext password arguments from process execution lines."""
        if not cmd:
            return cmd
        return SENSITIVE_ARGS_REGEX.sub(r"\1 [REDACTED]", cmd)

    @classmethod
    def normalize_event(
        cls,
        raw_event: Dict[str, Any],
        default_hostname: str = "WINDOWS-HOST",
        is_test_mode: bool = False,
    ) -> Dict[str, Any]:
        """Convert a Windows event dict into a standard SentinelX Event schema."""
        event_id = int(raw_event.get("event_id", 0))
        mapping = cls.EVENT_ID_MAP.get(event_id, ("windows_security", "LOW", None))
        canonical_type, default_sev, default_mitre = mapping

        timestamp = raw_event.get("timestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        hostname = raw_event.get("hostname") or default_hostname
        username = raw_event.get("username")
        source_ip = raw_event.get("source_ip")
        destination_ip = raw_event.get("destination_ip")
        source_port = raw_event.get("source_port")
        destination_port = raw_event.get("destination_port")
        protocol = raw_event.get("protocol") or "TCP"
        process_name = raw_event.get("process_name")
        command_line = cls.sanitize_command_line(raw_event.get("command_line"))
        message = raw_event.get("message") or f"Windows Event ID {event_id} ({canonical_type}) on {hostname}"
        severity = raw_event.get("severity") or default_sev
        mitre_technique = raw_event.get("mitre_technique") or default_mitre

        # Specific event enrichment
        if event_id == 4625 and not message.startswith("Windows Event ID 4625"):
            message = f"Failed logon attempt (Event ID 4625) for account '{username or 'unknown'}' on {hostname}"
        elif event_id == 4624 and not message.startswith("Windows Event ID 4624"):
            message = f"Successful logon (Event ID 4624) for account '{username or 'unknown'}' on {hostname}"

        source_label = "windows_collector_test" if is_test_mode else "windows_collector"

        return {
            "source": source_label,
            "event_type": canonical_type,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": int(source_port) if source_port else None,
            "destination_port": int(destination_port) if destination_port else None,
            "protocol": protocol,
            "severity": severity,
            "username": username,
            "hostname": hostname,
            "process_name": process_name,
            "command_line": command_line,
            "message": message,
            "mitre_technique": mitre_technique,
            "metadata": {
                "event_id": event_id,
                "provider_name": raw_event.get("provider_name", "Microsoft-Windows-Security-Auditing"),
                "task_category": raw_event.get("task_category", "Logon"),
                "is_test_mode": is_test_mode,
            },
        }
