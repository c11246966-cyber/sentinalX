# SentinelX Detection Rules & MITRE ATT&CK Catalog

The SentinelX Detection Engine is planned for Phase 4. All rules avoid hardcoded constants by storing configurable thresholds in JSON rule definitions.

## Planned Initial Rule Catalog

| Rule ID | Name | Category | MITRE Technique | Technique ID |
|---|---|---|---|---|
| RULE-001 | Multiple Authentication Failures | Authentication | Brute Force | T1110 |
| RULE-002 | Successful Login After Repeated Failures | Authentication | Valid Accounts | T1078 |
| RULE-003 | Suspicious Privileged Authentication | Authentication | Valid Accounts | T1078.002 |
| RULE-004 | Port Scan Pattern | Network | Network Service Discovery | T1046 |
| RULE-005 | Abnormal Connection Burst | Network | Denial of Service / C2 | T1499 / T1071 |
| RULE-006 | Suspicious Process Execution | Process | Command and Scripting | T1059 |
| RULE-007 | Suspicious Command Line Telemetry | Process | Command and Scripting | T1059 |
| RULE-008 | Web Authentication Anomaly | Web | Exploit Public-Facing App | T1190 |
| RULE-009 | Abnormal HTTP Request Rate | Web | Network Denial of Service | T1498 |
| RULE-010 | Threat Intelligence Indicator Match | Threat Intel | Indicator Match | Multi |

## Rule Definition Format Specification

```json
{
  "id": "RULE-001",
  "name": "Multiple Authentication Failures",
  "description": "Detects repeated failed logins from a single source within a sliding time window.",
  "category": "authentication",
  "severity": "HIGH",
  "rule_type": "threshold",
  "mitre_tactic": "Credential Access",
  "mitre_technique": "T1110",
  "enabled": true,
  "rule_definition": {
    "event_type": "authentication_failure",
    "group_by": ["source_ip", "username"],
    "threshold_count": 5,
    "time_window_seconds": 120,
    "base_risk_score": 70
  }
}
```
