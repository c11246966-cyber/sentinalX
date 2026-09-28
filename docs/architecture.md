# SentinelX Architecture & System Design

## 1. High-Level Architecture

SentinelX is designed as a modular, defensive security operations and detection platform following modern SOC/SIEM principles:

```
+-------------------------------------------------------------------+
|                        Telemetry Sources                          |
|  [Windows Agent]      [Linux Auditd/Syslog]      [Network/Firewall] |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|               Event Ingestion API (POST /api/events)               |
|      Input Validation (Pydantic) & Rate Limiting & Auth           |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                         Event Normalizer                          |
|     Converts OS/source formats to unified SentinelX schema        |
|     Preserves original raw event telemetry alongside metadata     |
+-------------------------------------------------------------------+
                                  |
                   +--------------+--------------+
                   |                             |
                   v                             v
+------------------------------------+  +----------------------------+
|         Event Storage              |  |      Detection Engine      |
|  PostgreSQL 16 Partitioned Storage |  |  Configurable Rule Engine  |
+------------------------------------+  +----------------------------+
                                                 |
                                                 v
                                        +----------------------------+
                                        |    Correlation Engine      |
                                        |  Time-window multi-event   |
                                        |  (IP, Host, User grouping) |
                                        +----------------------------+
                                                 |
                                                 v
                                        +----------------------------+
                                        |     Risk Scoring Engine    |
                                        |  Explainable 0-100 scale   |
                                        |  Aggregated factor points  |
                                        +----------------------------+
                                                 |
                                                 v
                                        +----------------------------+
                                        |  Threat Intel Enrichment   |
                                        |  IP / Hash / Domain lookup |
                                        +----------------------------+
                                                 |
                                                 v
                                        +----------------------------+
                                        |        Alert Engine        |
                                        |  State: NEW -> RESOLVED    |
                                        +----------------------------+
                                                 |
                                                 v
                                        +----------------------------+
                                        |    Incident Management     |
                                        |  Analyst triage & notes    |
                                        +----------------------------+
                                                 |
                         +-----------------------+-----------------------+
                         |                                               |
                         v                                               v
+------------------------------------+          +------------------------------------+
|         SOC Web Dashboard          |          |      Controlled Response Engine    |
|   React + TypeScript + Tailwind    |          |  Safe simulated actions (lab mode) |
|   Real-time WebSocket Streams      |          |  Mandatory audit trail logging     |
+------------------------------------+          +------------------------------------+
```

## 2. Component Responsibilities

1. **Collectors**: Lightweight agents capturing operating system authentication, process execution, and network telemetry.
2. **Ingestion API**: High-throughput FastAPI endpoints with asynchronous request processing.
3. **Storage**: PostgreSQL with structured JSON columns for raw payloads and indexed fields for query speed.
4. **Cache & Broker**: Redis 7 for active session storage, rate limiting, and pub/sub message dispatching.
5. **Detection & Correlation**: Stateful evaluation against sliding time windows.
6. **Frontend**: Dark-mode SOC analyst dashboard featuring real-time telemetry streaming and incident triage workflows.
