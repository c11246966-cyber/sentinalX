"""MITRE ATT&CK enterprise matrix mapping catalog."""

from typing import Dict, List, Optional

MITRE_TACTICS_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1046": {
        "id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on hosts over the network, scanning ports and banners.",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1110": {
        "id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords or hashes are unknown.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1110.001": {
        "id": "T1110.001",
        "technique": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may systematically guess passwords to authenticate against accounts on SSH, RDP, or web services.",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1110.003": {
        "id": "T1110.003",
        "technique": "Password Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt a small number of commonly used passwords against many different accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "T1078": {
        "id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts for impossible travel or abnormal logins.",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1190": {
        "id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing web apps (SQLi, path traversal, command injection).",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1059": {
        "id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (bash, sh, PowerShell) to execute arbitrary commands.",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1498": {
        "id": "T1498",
        "technique": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform network flooding (SYN flood, UDP blast) to exhaust bandwidth and target resources.",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "T1068": {
        "id": "T1068",
        "technique": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities or misconfigurations (sudo, SUID) to elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    "T1053": {
        "id": "T1053",
        "technique": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling systems to facilitate initial or recurring execution of malicious code.",
        "url": "https://attack.mitre.org/techniques/T1053/",
    },
    "T1059.001": {
        "id": "T1059.001",
        "technique": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution, download cradles, and memory injection.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.003": {
        "id": "T1059.003",
        "technique": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse the Windows command shell (cmd.exe) to execute utility commands and discovery tools.",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "T1490": {
        "id": "T1490",
        "technique": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or disable system recovery files and shadow copies (vssadmin delete shadows, wbadmin).",
        "url": "https://attack.mitre.org/techniques/T1490/",
    },
    "T1003": {
        "id": "T1003",
        "technique": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from the operating system memory, SAM database, or LSA secrets.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1562.001": {
        "id": "T1562.001",
        "technique": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disable or modify defensive tools such as Windows Defender or Antivirus to evade detection.",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
    "T1078.002": {
        "id": "T1078.002",
        "technique": "Valid Accounts: Domain Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of domain accounts to gain access and assign elevated privileges.",
        "url": "https://attack.mitre.org/techniques/T1078/002/",
    },
    "T1071": {
        "id": "T1071",
        "technique": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection and egress filter restrictions.",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
}


def lookup_mitre(technique_id: str) -> Optional[Dict[str, str]]:
    """Lookup technique and tactic info for a validated MITRE technique ID."""
    return MITRE_TACTICS_TECHNIQUES.get(technique_id)


def get_all_mitre_techniques() -> List[Dict[str, str]]:
    """Retrieve full catalog of mapped MITRE ATT&CK techniques."""
    return list(MITRE_TACTICS_TECHNIQUES.values())
