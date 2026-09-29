"""Real-time rule-based detection engine for Phase 3."""

from collections import defaultdict
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from backend.app.core.logging import logger
from backend.app.detection.mitre import lookup_mitre
from backend.app.detection.risk import RiskScoringEngine

# Rate and threshold tracking state (IP/host -> timestamp entries)
_STATE_PORT_SCANS: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
_STATE_SSH_FAILURES: Dict[str, List[float]] = defaultdict(list)
_STATE_AUTH_FAILURES: Dict[str, List[float]] = defaultdict(list)
_STATE_HTTP_REQUESTS: Dict[str, List[float]] = defaultdict(list)
_STATE_PACKET_BURSTS: Dict[str, List[float]] = defaultdict(list)
_STATE_WIN_FAILED_LOGONS: Dict[str, List[float]] = defaultdict(list)
_STATE_RECENT_FAILED_USERS: Dict[str, float] = {}


class DetectionEngine:
    """Evaluates telemetry against Phase 3 defensive detection rules:
    
    1. Port scanning (T1046)
    2. SSH brute force (T1110.001)
    3. Repeated authentication failures (T1110)
    4. Suspicious HTTP requests (T1190)
    5. Web attack patterns (SQLi, XSS, Path Traversal) (T1190)
    6. Network flooding (T1498)
    7. Privilege escalation indicators (T1068)
    8. Suspicious process execution (T1059)
    9. Impossible/abnormal authentication patterns (T1078)
    """

    SUSPICIOUS_PROCESSES = {
        "mimikatz", "procdump", "nc", "ncat", "netcat", "socat",
        "certutil", "vssadmin", "powershell -enc", "bash -i", "/dev/tcp",
    }

    WEB_ATTACK_PATTERNS = [
        re.compile(r"(\bUNION\b\s+\bSELECT\b|SELECT\s+.*\s+FROM|\bOR\b\s+['\d]=['\d]|--\s*$|')", re.IGNORECASE),
        re.compile(r"(<script\b|javascript:|onerror\s*=|onload\s*=)", re.IGNORECASE),
        re.compile(r"(\.\./\.\./|etc/passwd|windows/win\.ini)", re.IGNORECASE),
    ]

    PRIV_ESC_KEYWORDS = [
        "sudo su", "NOPASSWD", "chmod 4777", "chmod +s", "setuid",
        "token::elevate", "pkill -9 securityd", "adduser.*sudo",
    ]

    @classmethod
    def evaluate_event(cls, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run all Phase 3 detection analyzers over a normalized event."""
        alerts: List[Dict[str, Any]] = []
        now = time.time()

        src_ip = event.get("source_ip") or "unknown"
        dst_ip = event.get("destination_ip") or "unknown"
        dst_port = event.get("destination_port")
        proto = (event.get("protocol") or "").upper()
        event_type = (event.get("event_type") or "").lower()
        msg = event.get("message") or ""
        proc = (event.get("process_name") or "").lower()
        cmd = (event.get("command_line") or "").lower()
        username = (event.get("username") or "").lower()
        host = event.get("hostname") or "unknown"

        # ----------------------------------------------------------------------
        # 1. Port Scanning Detection (T1046)
        # Threshold: >= 4 distinct destination ports accessed within 15 seconds
        # ----------------------------------------------------------------------
        if dst_port is not None:
            history = _STATE_PORT_SCANS[src_ip]
            history = [(ts, p) for ts, p in history if now - ts <= 15.0]
            history.append((now, dst_port))
            _STATE_PORT_SCANS[src_ip] = history

            unique_ports = len({p for _, p in history})
            if unique_ports >= 4:
                mitre_info = lookup_mitre("T1046") or {}
                score, sev, factors = RiskScoringEngine.score_detection(
                    severity="HIGH",
                    confidence=90,
                    event_count=len(history),
                    asset_criticality="medium",
                    mitre_tactic=mitre_info.get("tactic", "Discovery"),
                )
                alerts.append({
                    "title": f"Port Scanning Activity Detected from {src_ip}",
                    "description": f"Source {src_ip} probed {unique_ports} distinct destination ports on {dst_ip} within 15s window.",
                    "severity": sev,
                    "risk_score": score,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "mitre_technique": "T1046",
                    "mitre_tactic": mitre_info.get("tactic", "Discovery"),
                    "rule_category": "network",
                    "status": "NEW",
                })

        # ----------------------------------------------------------------------
        # 2. SSH Brute Force (T1110.001)
        # Threshold: >= 3 SSH authentication failures or port 22 probes within 30s
        # ----------------------------------------------------------------------
        is_ssh_event = dst_port == 22 or "ssh" in event_type or "ssh" in msg.lower()
        if is_ssh_event and ("fail" in event_type or "fail" in msg.lower() or "auth" in event_type):
            ssh_history = [ts for ts in _STATE_SSH_FAILURES[src_ip] if now - ts <= 30.0]
            ssh_history.append(now)
            _STATE_SSH_FAILURES[src_ip] = ssh_history

            if len(ssh_history) >= 3:
                mitre_info = lookup_mitre("T1110.001") or {}
                score, sev, _ = RiskScoringEngine.score_detection(
                    severity="HIGH",
                    confidence=95,
                    event_count=len(ssh_history),
                    asset_criticality="high",
                    user_is_privileged=(username in ["root", "admin", "administrator"]),
                    mitre_tactic=mitre_info.get("tactic", "Credential Access"),
                )
                alerts.append({
                    "title": f"SSH Brute Force Attack from {src_ip}",
                    "description": f"Detected {len(ssh_history)} failed SSH authentication attempts on {dst_ip} (targeted user: '{username or 'root'}').",
                    "severity": sev,
                    "risk_score": score,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "mitre_technique": "T1110.001",
                    "mitre_tactic": mitre_info.get("tactic", "Credential Access"),
                    "rule_category": "authentication",
                    "status": "NEW",
                })

        # ----------------------------------------------------------------------
        # 3. Repeated Authentication Failures (T1110)
        # Threshold: >= 3 non-SSH auth failures across services within 30s
        # ----------------------------------------------------------------------
        if ("auth" in event_type or "login" in event_type) and ("fail" in event_type or "fail" in msg.lower() or "invalid" in msg.lower()):
            auth_history = [ts for ts in _STATE_AUTH_FAILURES[src_ip] if now - ts <= 30.0]
            auth_history.append(now)
            _STATE_AUTH_FAILURES[src_ip] = auth_history

            if len(auth_history) >= 3:
                mitre_info = lookup_mitre("T1110") or {}
                score, sev, _ = RiskScoringEngine.score_detection(
                    severity="MEDIUM",
                    confidence=85,
                    event_count=len(auth_history),
                    asset_criticality="medium",
                    user_is_privileged=(username in ["root", "admin", "administrator"]),
                    mitre_tactic=mitre_info.get("tactic", "Credential Access"),
                )
                alerts.append({
                    "title": f"Repeated Authentication Failures ({src_ip})",
                    "description": f"{len(auth_history)} consecutive login failures detected targeting user '{username}'.",
                    "severity": sev,
                    "risk_score": score,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "mitre_technique": "T1110",
                    "mitre_tactic": mitre_info.get("tactic", "Credential Access"),
                    "rule_category": "authentication",
                    "status": "NEW",
                })

        # ----------------------------------------------------------------------
        # 4 & 5. Web Attack Patterns & Suspicious HTTP Requests (T1190)
        # Detects SQL injection, XSS, Path Traversal in URI/payload/message
        # ----------------------------------------------------------------------
        full_text = f"{msg} {cmd}".strip()
        matched_web_pattern = None
        for pattern in cls.WEB_ATTACK_PATTERNS:
            if pattern.search(full_text):
                matched_web_pattern = pattern.pattern
                break

        if matched_web_pattern or "sqli" in event_type or "xss" in event_type or "traversal" in event_type:
            mitre_info = lookup_mitre("T1190") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="HIGH",
                confidence=95,
                event_count=1,
                asset_criticality="high",
                mitre_tactic=mitre_info.get("tactic", "Initial Access"),
            )
            alerts.append({
                "title": f"Web Exploitation Pattern Observed from {src_ip}",
                "description": f"Identified suspicious web payload / attack signature in HTTP request directed at {dst_ip}.",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1190",
                "mitre_tactic": mitre_info.get("tactic", "Initial Access"),
                "rule_category": "web",
                "status": "NEW",
            })

        # ----------------------------------------------------------------------
        # 6. Network Flooding / DoS (T1498)
        # Threshold: >= 5 rapid requests/packets within 5s
        # ----------------------------------------------------------------------
        if "flood" in event_type or "syn" in event_type or "ddos" in event_type or "burst" in event_type:
            burst_history = [ts for ts in _STATE_PACKET_BURSTS[src_ip] if now - ts <= 5.0]
            burst_history.append(now)
            _STATE_PACKET_BURSTS[src_ip] = burst_history

            if len(burst_history) >= 4 or "flood" in event_type:
                mitre_info = lookup_mitre("T1498") or {}
                score, sev, _ = RiskScoringEngine.score_detection(
                    severity="CRITICAL",
                    confidence=95,
                    event_count=len(burst_history),
                    asset_criticality="high",
                    mitre_tactic=mitre_info.get("tactic", "Impact"),
                )
                alerts.append({
                    "title": f"Network Flooding / Denial-of-Service Attack from {src_ip}",
                    "description": f"High volume burst detected: {len(burst_history)} rapid packets/requests targeting {dst_ip}:{dst_port or 'all'}.",
                    "severity": sev,
                    "risk_score": score,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "mitre_technique": "T1498",
                    "mitre_tactic": mitre_info.get("tactic", "Impact"),
                    "rule_category": "network",
                    "status": "NEW",
                })

        # ----------------------------------------------------------------------
        # 7. Privilege Escalation Indicators (T1068)
        # ----------------------------------------------------------------------
        matched_priv = any(k.lower() in full_text for k in cls.PRIV_ESC_KEYWORDS)
        if matched_priv or "privilege_escalation" in event_type or "priv_esc" in event_type:
            mitre_info = lookup_mitre("T1068") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="HIGH",
                confidence=90,
                event_count=1,
                asset_criticality="critical",
                user_is_privileged=True,
                mitre_tactic=mitre_info.get("tactic", "Privilege Escalation"),
            )
            alerts.append({
                "title": f"Privilege Escalation Activity on {host}",
                "description": f"User '{username}' attempted elevated or unauthorized execution: '{msg or cmd}'.",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1068",
                "mitre_tactic": mitre_info.get("tactic", "Privilege Escalation"),
                "rule_category": "process",
                "status": "NEW",
            })

        # ----------------------------------------------------------------------
        # 8. Suspicious Process Execution (T1059)
        # ----------------------------------------------------------------------
        matched_proc = any(sp in proc or sp in cmd for sp in cls.SUSPICIOUS_PROCESSES)
        if matched_proc or "suspicious_process" in event_type:
            mitre_info = lookup_mitre("T1059") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="HIGH",
                confidence=95,
                event_count=1,
                asset_criticality="high",
                mitre_tactic=mitre_info.get("tactic", "Execution"),
            )
            alerts.append({
                "title": f"Suspicious Process Execution Detected ({proc or cmd})",
                "description": f"Host {host} spawned potentially adversarial tool/binary: '{cmd or proc}'.",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1059",
                "mitre_tactic": mitre_info.get("tactic", "Execution"),
                "rule_category": "process",
                "status": "NEW",
            })

        # ----------------------------------------------------------------------
        # 9. Impossible/Abnormal Authentication Patterns (T1078)
        # ----------------------------------------------------------------------
        if "impossible_travel" in event_type or "abnormal_auth" in event_type or "anomalous_location" in msg.lower():
            mitre_info = lookup_mitre("T1078") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="CRITICAL",
                confidence=90,
                event_count=1,
                asset_criticality="high",
                user_is_privileged=(username in ["root", "admin", "administrator"]),
                mitre_tactic=mitre_info.get("tactic", "Initial Access"),
            )
            alerts.append({
                "title": f"Impossible Travel / Abnormal Authentication for {username or 'account'}",
                "description": f"Account '{username}' observed authenticating from disjointed geolocations in an unfeasible timeframe ({msg}).",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1078",
                "mitre_tactic": mitre_info.get("tactic", "Initial Access"),
                "rule_category": "authentication",
                "status": "NEW",
            })

        # ----------------------------------------------------------------------
        # 10. Windows Repeated Failed Authentication (Event ID 4625, T1110.001)
        # Threshold: >= 3 failed logons on a Windows host/account within 60s
        # ----------------------------------------------------------------------
        is_win_failed_logon = (
            event_type in ("windows_failed_logon", "windows_security", "failed_logon", "windows_security_log")
            and ("4625" in msg or "4625" in str(event.get("metadata", {}).get("event_id", "")) or "failed logon" in msg.lower() or "logon failure" in msg.lower())
        ) or event_type == "windows_failed_logon"

        if is_win_failed_logon:
            key = f"{host}:{username or 'unknown'}"
            fails = _STATE_WIN_FAILED_LOGONS[key]
            fails = [ts for ts in fails if now - ts <= 60.0]
            fails.append(now)
            _STATE_WIN_FAILED_LOGONS[key] = fails
            _STATE_RECENT_FAILED_USERS[key] = now

            if len(fails) >= 3:
                mitre_info = lookup_mitre("T1110.001") or {}
                score, sev, _ = RiskScoringEngine.score_detection(
                    severity="HIGH",
                    confidence=90,
                    event_count=len(fails),
                    asset_criticality="medium",
                    user_is_privileged=(username in ["administrator", "admin", "system"]),
                    mitre_tactic=mitre_info.get("tactic", "Credential Access"),
                )
                alerts.append({
                    "title": f"Windows Brute Force / Repeated Failed Logons on {host} ({username})",
                    "description": f"Host {host} encountered {len(fails)} consecutive failed logon events (Event ID 4625) for account '{username}' within 60s.",
                    "severity": sev,
                    "risk_score": score,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "mitre_technique": "T1110.001",
                    "mitre_tactic": mitre_info.get("tactic", "Credential Access"),
                    "rule_category": "authentication",
                    "status": "NEW",
                })

        # ----------------------------------------------------------------------
        # 11. Windows Successful Logon After Multiple Failures (Event ID 4624, T1078)
        # ----------------------------------------------------------------------
        is_win_success_logon = (
            event_type in ("windows_successful_logon", "windows_security", "successful_logon", "windows_security_log")
            and ("4624" in msg or "4624" in str(event.get("metadata", {}).get("event_id", "")) or "successful logon" in msg.lower())
        ) or event_type == "windows_successful_logon"

        if is_win_success_logon:
            key = f"{host}:{username or 'unknown'}"
            last_fail_ts = _STATE_RECENT_FAILED_USERS.get(key, 0)
            if now - last_fail_ts <= 120.0 and len(_STATE_WIN_FAILED_LOGONS.get(key, [])) >= 2:
                mitre_info = lookup_mitre("T1078") or {}
                score, sev, _ = RiskScoringEngine.score_detection(
                    severity="HIGH",
                    confidence=85,
                    event_count=1,
                    asset_criticality="high",
                    user_is_privileged=(username in ["administrator", "admin"]),
                    mitre_tactic=mitre_info.get("tactic", "Initial Access"),
                )
                alerts.append({
                    "title": f"Windows Successful Logon After Failures on {host} ({username})",
                    "description": f"Account '{username}' successfully logged in (Event ID 4624) on {host} immediately following multiple authentication failures.",
                    "severity": sev,
                    "risk_score": score,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "mitre_technique": "T1078",
                    "mitre_tactic": mitre_info.get("tactic", "Initial Access"),
                    "rule_category": "authentication",
                    "status": "NEW",
                })
                # Reset failure state on success
                _STATE_RECENT_FAILED_USERS.pop(key, None)

        # ----------------------------------------------------------------------
        # 12. Suspicious PowerShell ScriptBlock / Encoded Execution (Event ID 4104/4103, T1059.001)
        # ----------------------------------------------------------------------
        raw_cmd = f"{cmd} {msg}".lower()
        has_ps_indicators = (
            "4104" in msg
            or "4103" in msg
            or "powershell" in proc
            or "powershell" in event_type
            or event_type == "windows_powershell"
        ) and any(
            kw in raw_cmd
            for kw in [
                "downloadstring",
                "iex ",
                "invoke-expression",
                "-enc ",
                "-encodedcommand",
                "executionpolicy bypass",
                "bypass -noprofile",
                "webclient",
                "bitstransfer",
            ]
        )

        if has_ps_indicators or event_type == "windows_powershell_suspicious":
            mitre_info = lookup_mitre("T1059.001") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="HIGH",
                confidence=92,
                event_count=1,
                asset_criticality="high",
                mitre_tactic=mitre_info.get("tactic", "Execution"),
            )
            alerts.append({
                "title": f"Suspicious PowerShell Execution on {host}",
                "description": f"PowerShell execution metadata on {host} indicates obfuscation or remote download cradle: '{cmd or msg[:120]}'.",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1059.001",
                "mitre_tactic": mitre_info.get("tactic", "Execution"),
                "rule_category": "process",
                "status": "NEW",
            })

        # ----------------------------------------------------------------------
        # 13. Suspicious Windows Process Execution (Event ID 4688, T1059.003 / T1490 / T1003)
        # ----------------------------------------------------------------------
        if "vssadmin" in raw_cmd and ("delete" in raw_cmd or "shadows" in raw_cmd):
            mitre_info = lookup_mitre("T1490") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="CRITICAL",
                confidence=95,
                event_count=1,
                asset_criticality="critical",
                mitre_tactic=mitre_info.get("tactic", "Impact"),
            )
            alerts.append({
                "title": f"Shadow Copy Deletion / Recovery Inhibition on {host}",
                "description": f"Host {host} executed command inhibiting volume shadow copies (ransomware precursor): '{cmd or msg}'.",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1490",
                "mitre_tactic": mitre_info.get("tactic", "Impact"),
                "rule_category": "process",
                "status": "NEW",
            })
        elif "certutil" in raw_cmd and ("-urlcache" in raw_cmd or "-split" in raw_cmd or "http" in raw_cmd):
            mitre_info = lookup_mitre("T1059.003") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="HIGH",
                confidence=90,
                event_count=1,
                asset_criticality="medium",
                mitre_tactic=mitre_info.get("tactic", "Execution"),
            )
            alerts.append({
                "title": f"Suspicious CertUtil Ingress Download on {host}",
                "description": f"Host {host} invoked certutil for external payload retrieval: '{cmd or msg}'.",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1059.003",
                "mitre_tactic": mitre_info.get("tactic", "Execution"),
                "rule_category": "process",
                "status": "NEW",
            })
        elif "whoami /priv" in raw_cmd or "nltest /dclist" in raw_cmd:
            mitre_info = lookup_mitre("T1059.003") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="MEDIUM",
                confidence=80,
                event_count=1,
                asset_criticality="medium",
                mitre_tactic=mitre_info.get("tactic", "Discovery"),
            )
            alerts.append({
                "title": f"Adversarial Privilege/Domain Reconnaissance on {host}",
                "description": f"Host {host} executed enumeration utility: '{cmd or msg}'.",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1059.003",
                "mitre_tactic": "Discovery",
                "rule_category": "process",
                "status": "NEW",
            })

        # ----------------------------------------------------------------------
        # 14. Windows Defender Threat Detection or Tampering (Event ID 1116/1117/5001, T1562.001)
        # ----------------------------------------------------------------------
        is_defender_event = (
            "defender" in event_type
            or "1116" in msg
            or "1117" in msg
            or "5001" in msg
            or event_type == "windows_defender"
            or "defender" in msg.lower()
        )
        if is_defender_event:
            mitre_info = lookup_mitre("T1562.001") or {}
            is_tamper = "disabled" in msg.lower() or "5001" in msg or "tamper" in msg.lower()
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="CRITICAL" if is_tamper else "HIGH",
                confidence=95,
                event_count=1,
                asset_criticality="high",
                mitre_tactic=mitre_info.get("tactic", "Defense Evasion"),
            )
            alerts.append({
                "title": f"Windows Defender Security Alert on {host}: {'Tampering Detected' if is_tamper else 'Malware Quarantined'}",
                "description": f"Windows Defender on {host} generated security signal: {msg}.",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1562.001",
                "mitre_tactic": mitre_info.get("tactic", "Defense Evasion"),
                "rule_category": "system",
                "status": "NEW",
            })

        # ----------------------------------------------------------------------
        # 15. Unexpected Privileged Account Activity (Event ID 4672, T1078.002)
        # ----------------------------------------------------------------------
        if "4672" in msg or event_type == "windows_privileged_logon":
            mitre_info = lookup_mitre("T1078.002") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="MEDIUM",
                confidence=80,
                event_count=1,
                asset_criticality="high",
                user_is_privileged=True,
                mitre_tactic=mitre_info.get("tactic", "Defense Evasion"),
            )
            alerts.append({
                "title": f"Special Privileges Assigned to Account '{username}' on {host}",
                "description": f"Host {host} assigned administrator / special privileges (Event ID 4672) to user '{username}'.",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1078.002",
                "mitre_tactic": mitre_info.get("tactic", "Defense Evasion"),
                "rule_category": "authentication",
                "status": "NEW",
            })

        # ----------------------------------------------------------------------
        # 16. Suspicious Windows Network Outbound Connection (Event ID 5156, T1071)
        # ----------------------------------------------------------------------
        if ("5156" in msg or event_type == "windows_network") and dst_port in (4444, 1337, 8888, 31337, 6667):
            mitre_info = lookup_mitre("T1071") or {}
            score, sev, _ = RiskScoringEngine.score_detection(
                severity="HIGH",
                confidence=90,
                event_count=1,
                asset_criticality="high",
                mitre_tactic=mitre_info.get("tactic", "Command and Control"),
            )
            alerts.append({
                "title": f"Suspicious Outbound Network Connection from {host} to {dst_ip}:{dst_port}",
                "description": f"Host {host} established outbound connection to high-risk destination port {dst_port} ({dst_ip}).",
                "severity": sev,
                "risk_score": score,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "mitre_technique": "T1071",
                "mitre_tactic": mitre_info.get("tactic", "Command and Control"),
                "rule_category": "network",
                "status": "NEW",
            })

        return alerts

    @classmethod
    def reset_state(cls):
        """Reset internal detection tracking windows (for testing)."""
        _STATE_PORT_SCANS.clear()
        _STATE_SSH_FAILURES.clear()
        _STATE_AUTH_FAILURES.clear()
        _STATE_HTTP_REQUESTS.clear()
        _STATE_PACKET_BURSTS.clear()
        _STATE_WIN_FAILED_LOGONS.clear()
        _STATE_RECENT_FAILED_USERS.clear()

