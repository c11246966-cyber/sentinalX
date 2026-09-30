# SentinelX — AI-Powered SOC & Threat Detection Platform

SentinelX is an enterprise-grade defensive Security Operations Center (SOC) and SIEM monitoring platform engineered for authorized laboratory environments, detection engineering, and incident response automation.

---

## 1. Project Overview & Architecture

SentinelX ingests raw telemetry from Windows and Linux endpoints, normalizes security events, evaluates detection rules against sliding time windows, correlates multi-event threat chains, calculates explainable 0–100 risk scores, enriches indicators with threat intelligence, and streams real-time alerts to a dark-mode SOC dashboard.

### Telemetry & Detection Pipeline

```
Collectors (Windows Event Log / Linux Syslog / Network)
                   │
                   ▼
       Event Ingestion API (POST /api/events)
                   │
                   ▼
            Event Normalizer
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
  Event Storage       Detection Engine (Rules 001–010)
  (PostgreSQL 16)            │
                             ▼
                     Correlation Engine
                             │
                             ▼
                    Risk Scoring (0–100)
                             │
                             ▼
                 Threat Intelligence Enrichment
                             │
                             ▼
                      Alert Engine
                             │
                             ▼
                    Incident Management
                             │
         ┌───────────────────┴───────────────────┐
         ▼                                       ▼
  SOC Web Dashboard                     Safe Controlled Response
  (React / WebSockets)                  (Simulated Lab Containment)
```

---

## 2. Technology Stack

- **Backend**: Python 3.12+, FastAPI, SQLAlchemy 2.0 (Async), Alembic, Pydantic v2, PostgreSQL 16, Redis 7, WebSockets, Pytest
- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS, Lucide Icons
- **Deployment**: Docker, Docker Compose (multi-stage builds)
- **Security**: Argon2id password hashing, JWT authentication, Role-Based Access Control (Admin, Analyst, Viewer), HTTP Security Headers (CSP, HSTS, X-Frame-Options: DENY, X-Content-Type-Options: nosniff), strict input validation

---

## 3. Repository Structure

```
sentinelx/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI application entrypoint & lifespan
│   │   ├── api/                     # Modular API routers
│   │   │   ├── health.py            # Health-check endpoint (/health & /api/v1/health)
│   │   │   ├── auth.py              # Authentication & JWT endpoints (Phase 2)
│   │   │   ├── alerts.py            # Alert triage & state endpoints (Phase 4)
│   │   │   ├── events.py            # Event ingestion endpoints (Phase 3)
│   │   │   ├── hosts.py             # Host inventory endpoints (Phase 6)
│   │   │   ├── incidents.py         # Incident management endpoints (Phase 5)
│   │   │   ├── rules.py             # Detection rule management endpoints (Phase 4)
│   │   │   ├── threat_intel.py      # Threat intelligence lookups (Phase 8)
│   │   │   └── websocket.py         # Real-time WebSocket event broadcaster (Phase 7)
│   │   ├── core/                    # Core system infrastructure
│   │   │   ├── config.py            # Pydantic BaseSettings & environment loader
│   │   │   ├── database.py          # SQLAlchemy 2.0 async engine & sessionmaker
│   │   │   ├── redis.py             # Redis client & connection pool manager
│   │   │   ├── logging.py           # Structured JSON logger
│   │   │   └── security.py          # Argon2id password hashing & JWT token handling
│   │   ├── models/                  # SQLAlchemy 2.0 ORM database models
│   │   │   ├── user.py              # Users & RBAC roles
│   │   │   ├── host.py              # Endpoint inventory & agent status
│   │   │   ├── event.py             # Partitioned security event storage
│   │   │   ├── alert.py             # Detection alerts & risk factors
│   │   │   ├── incident.py          # Aggregated security incidents
│   │   │   ├── rule.py              # Configurable detection rules
│   │   │   ├── threat_intel.py      # Cached threat intelligence indicators
│   │   │   └── audit.py             # Immutable administrative audit logs
│   │   ├── schemas/                 # Pydantic request/response schemas
│   │   │   ├── health.py            # Health status schema
│   │   │   ├── user.py              # User & JWT schemas
│   │   │   ├── event.py             # Normalized event ingestion schema
│   │   │   ├── alert.py             # Alert lifecycle schema
│   │   │   ├── incident.py          # Incident tracking schema
│   │   │   ├── rule.py              # Rule definition schema
│   │   │   └── threat_intel.py      # Indicator lookup schema
│   │   ├── detection/               # Detection & analytical engines
│   │   │   ├── engine.py            # Detection rule evaluator
│   │   │   ├── correlation.py       # Multi-event correlation engine
│   │   │   ├── risk.py              # Explainable 0–100 risk scoring engine
│   │   │   └── mitre.py             # MITRE ATT&CK enterprise mapping
│   │   ├── collectors/              # Telemetry normalizers
│   │   │   ├── windows.py           # Windows Event Log normalizer
│   │   │   ├── linux.py             # Linux auditd/syslog normalizer
│   │   │   └── network.py           # Network flow normalizer
│   │   ├── response/                # Response action framework
│   │   │   ├── actions.py           # Safe lab-simulated response actions
│   │   │   └── firewall.py          # Defensive firewall adapter with safety locks
│   │   └── services/                # Domain business logic services
│   │       ├── alert_service.py
│   │       ├── incident_service.py
│   │       ├── intel_service.py
│   │       └── event_service.py
│   └── requirements.txt             # Pinned backend dependencies
├── collectors/                      # Host agent source directories
│   ├── windows-agent/
│   └── linux-agent/
├── database/
│   └── migrations/                  # Alembic database migrations
├── docker/
│   ├── Dockerfile.backend           # Hardened multi-stage Python 3.12 image
│   └── Dockerfile.frontend          # Hardened multi-stage Node/Nginx image
├── docs/                            # Architectural documentation
│   ├── architecture.md
│   ├── api.md
│   ├── detection-rules.md
│   ├── deployment.md
│   ├── security.md
│   └── testing.md
├── rules/                           # Detection rule definitions
│   ├── authentication/
│   ├── network/
│   ├── process/
│   └── web/
├── src/                             # React SOC Frontend (TypeScript & Tailwind)
│   ├── components/
│   │   ├── Header.tsx               # Status bar with live health ping
│   │   ├── Sidebar.tsx              # SOC navigation & phase badges
│   │   ├── StatusBadge.tsx          # Real-time state indicators
│   │   ├── ServiceTopology.tsx      # Infrastructure status & latency grid
│   │   ├── ArchitecturePipeline.tsx # 10-stage detection pipeline flow
│   │   ├── HealthChecker.tsx        # Interactive diagnostic terminal
│   │   └── PhaseRoadmap.tsx         # Phased deliverables tracker
│   ├── pages/
│   │   └── DashboardOverview.tsx    # Primary SOC overview page
│   ├── services/
│   │   └── api.ts                   # API client with health diagnostics
│   ├── types/
│   │   └── index.ts                 # Shared TypeScript interfaces
│   ├── App.tsx                      # Main application view
│   └── main.tsx                     # DOM mounting point
├── tests/                           # Automated test suite
│   ├── conftest.py                  # Pytest fixtures & environment setup
│   ├── test_config.py               # Settings, risk scoring & MITRE tests
│   ├── test_health.py               # Healthcheck serialization tests
│   ├── test_models_syntax.py        # Schema contracts validation
│   └── test_collectors_and_response.py # Normalizers & safe response tests
├── docker-compose.yml               # Multi-container orchestration
├── .env.example                     # Environment configuration template
├── .gitignore                       # Git ignore rules
└── README.md                        # Master documentation
```

---

## 4. Setup & Running Instructions

### Method A: Docker Compose (Recommended)

1. **Configure Environment**:
   ```bash
   cp .env.example .env
   ```

2. **Start All Services**:
   ```bash
   docker compose up --build -d
   ```

3. **Verify Service Health**:
   ```bash
   docker compose ps
   curl -s http://localhost:8000/health
   ```

4. **Access Applications**:
   - SOC Web Dashboard: [http://localhost:3000](http://localhost:3000)
   - Interactive OpenAPI Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
   - Redoc Specification: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

### Method B: Local Development (Without Docker)

#### 1. Backend (FastAPI)
```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Start backend server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Frontend (React / Vite)
```bash
npm install
npm run dev
```

---

## 5. Automated Testing

### Run backend tests:
```bash
# Standard unittest (runs with zero extra dependencies):
python3 -m unittest discover tests -v

# Or using pytest:
pytest -v tests/
```

### Run frontend type verification and build:
```bash
npm run lint
npm run build
```

---

## 6. Expected Health-Check Response

### Endpoint: `GET /health` or `GET /api/v1/health`

```json
{
  "status": "healthy",
  "version": "0.1.0-alpha",
  "environment": "development",
  "timestamp": "2026-09-28T16:20:00.123456Z",
  "services": {
    "api": {
      "status": "healthy",
      "latency_ms": 0.05,
      "message": "FastAPI core dispatcher active"
    },
    "database": {
      "status": "healthy",
      "latency_ms": 2.14,
      "message": "PostgreSQL connection verified (sentinelx_db)"
    },
    "redis": {
      "status": "healthy",
      "latency_ms": 0.88,
      "message": "Redis cache and pub/sub operational"
    }
  }
}
```

---

## 7. Security Considerations & Lab-Only Warning

> ⚠️ **DEFENSIVE LABORATORY WARNING**
> SentinelX includes capabilities for endpoint isolation and IP blocking. In the default configuration:
> - All response actions execute in **SAFE LAB SIMULATION MODE**.
> - Real firewall modification requires explicit administrative authorization and a verified allowlist.
> - Destructive operations are strictly prohibited by default.
> - An immutable audit log record is generated for every action taken by an operator.

---

## 8. Phase 5: Threat Intelligence & Indicator Enrichment

### Architecture Overview

SentinelX Phase 5 adds a modular Threat Intelligence and Indicator Enrichment layer that correlates external intelligence feeds and local curated IOC catalogs with incoming security events and alerts:

```
Security Event (Source IP, Dest IP, Domain, Hash, URL)
       │
       ▼
Detection Engine (Rules 001–010 triggered)
       │
       ▼
Indicator Extraction & SSRF Validation
       │
       ▼
Threat Intelligence Manager
 ┌─────┼────────────────────────────┬────────────────────────────┐
 ▼     ▼                            ▼                            ▼
Redis Cache (TTL)    VirusTotal v3         AbuseIPDB v2          AlienVault OTX
       │             (Hash/IP/Domain/URL)  (IPv4/IPv6)           (Pulses/Threats)
       ▼
Multi-Provider Consensus & Normalization
       │
       ▼
Explainable Risk Adjuster (Deterministic [0-100] Scoring)
       │
       ▼
Enriched Alert + Updated Incident Correlation
       │
       ▼
Real-Time SOC Dashboard (SSE / Threat Intelligence Dossier)
```

### Supported Threat Intelligence Providers

1. **VirusTotal (v3 API)**: Enriches IPv4, domains, URLs, and file hashes (MD5, SHA1, SHA256). Normalizes detection engine ratios into malicious, suspicious, or clean verdicts.
2. **AbuseIPDB (v2 API)**: Enriches IPv4 and IPv6 addresses. Extracts abuse confidence scores, reports, and threat categories (brute force, port scan, DDoS, web attacks).
3. **AlienVault OTX**: Enriches IPv4, IPv6, domains, URLs, and hashes against threat exchange pulses, malware families, and adversary tracking.
4. **Internal Curated Feed**: Built-in baseline provider providing RFC1918 private network classification, loopback identification, and curated IOC test signatures for deterministic laboratory testing.

### Provider Credentials & Graceful Degradation

- All provider API keys MUST come strictly from environment variables (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`).
- Keys are never hardcoded, never logged, and never returned to the frontend or API callers.
- If an API key is missing or invalid, the provider **gracefully disables itself** (`configured: false`), reporting safe metadata without crashing or halting event ingestion.

### SSRF Protection & Safe Handling

- **Private Network Isolation**: Threat queries targeting RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), link-local (`169.254.0.0/16`), or cloud metadata endpoints (`metadata.google.internal`) are intercepted and resolved internally to prevent SSRF vulnerabilities and internal telemetry leakage.
- **No Remote Code Execution**: Indicators are treated as passive data. SentinelX never executes binaries, visits malicious links, or executes indicator strings as shell commands.

### Redis Caching Strategy

- Threat intelligence lookups are cached in Redis under `sentinelx:intel:{type}:{indicator}` with a configurable TTL (default: 3600 seconds / 1 hour).
- If Redis is unavailable or unconfigured, queries seamlessly fall back to an in-memory cache with bounded LRU eviction (max 1000 items).
- Rate limits (HTTP 429) trigger a 60-second backoff window during which external API calls are throttled and fallback indicators are returned.

### Deterministic Risk Scoring Formula

Threat intelligence influences risk scores in a strictly deterministic, bounded (0–100), and explainable manner:
- **Malicious Reputation**: Base addition of +15 to +25 points (scaled by provider confidence).
- **Multi-Provider Consensus**: +10 bonus points when 2 or more independent providers confirm malicious status.
- **High-Impact Threat Tags**: +5 bonus points for critical tags (`c2`, `ransomware`, `botnet`, `tor_exit_node`, `exploit`).
- **Verified Benign**: -5 points reduction for verified clean infrastructure (when base severity is below HIGH).
- **Bounded Clamping**: Final risk score is clamped between 0 and 100. A single provider response cannot automatically turn an alert to CRITICAL unless the score reaches 90+.
- **Audit Explanation**: Every adjustment records a line-item rationale stored in `risk_adjustment_reason`.

### Threat Intelligence REST APIs

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `GET` | `/api/v1/threat-intel/providers` | Viewer+ | Safe provider status metadata (no secrets returned) |
| `POST` | `/api/v1/threat-intel/enrich` | Analyst+ | On-demand IOC enrichment with audit logging |
| `GET` | `/api/v1/threat-intel/indicators` | Viewer+ | Filterable catalog of enriched threat indicators |
| `GET` | `/api/v1/threat-intel/indicators/{indicator}` | Viewer+ | Retrieve full intelligence dossier for an IOC |
| `GET` | `/api/v1/threat-intel/indicators/{indicator}/related-alerts` | Viewer+ | Active alerts mapped to this indicator |
| `GET` | `/api/v1/threat-intel/indicators/{indicator}/related-incidents` | Viewer+ | Correlated incidents containing this indicator |

---

## 9. Phase 6: Host Inventory & Endpoint Monitoring

### Architecture & Capabilities

SentinelX Phase 6 implements centralized host inventory management, endpoint status tracking, agent heartbeat monitoring, and safe simulated containment controls:

```
Managed Endpoints (Windows Server, Windows 11, Ubuntu, RHEL, macOS)
       │
       ▼ (Periodic Heartbeat & Ingest)
Host Inventory Dispatcher (FastAPI /api/v1/hosts)
 ┌─────┼────────────────────────────┬────────────────────────────┐
 ▼     ▼                            ▼                            ▼
Host DB Registry      Agent Health Tracker         Simulated Containment        Telemetry Correlation
(PostgreSQL 16)       (ONLINE / DEGRADED / OFFLINE) (Safe Lab Isolation)         (Correlated Alerts & Events)
       │
       ▼
SOC Dashboard (Real-Time Endpoint Console & Host Details Drawer)
```

### Dynamic Endpoint Health Statuses

- **ONLINE**: Agent check-in heartbeat received within the last 60 seconds.
- **DEGRADED**: Check-in received between 60 and 180 seconds ago (potential network latency or agent delay).
- **OFFLINE**: No check-in received for greater than 180 seconds.
- **ISOLATED**: Endpoint isolated via safe laboratory containment simulation mode.

### Safe Simulated Containment (Isolation)

- Host containment actions execute strictly in **SAFE LAB SIMULATION MODE**.
- Physical firewall rules and kernel tables are never tampered with by default.
- Setting an endpoint to `ISOLATED` dynamically updates calculated risk to 90+, tags associated telemetry, and records an immutable record in the security audit log (`host_isolate` / `host_unisolate`).

### Host Inventory REST APIs

| Method | Endpoint | RBAC Role | Description |
|---|---|---|---|
| `GET` | `/api/v1/hosts` | Viewer+ | List monitored endpoints with status, OS, and search filters |
| `POST` | `/api/v1/hosts` | Analyst+ | Register an endpoint or provision an agent in inventory |
| `GET` | `/api/v1/hosts/{host_id}` | Viewer+ | Get complete endpoint profile, recent events, and risk |
| `PATCH` | `/api/v1/hosts/{host_id}` | Analyst+ | Update endpoint metadata, network IP, or status |
| `POST` | `/api/v1/hosts/{host_id}/heartbeat` | Public/Agent | Update endpoint check-in timestamp and agent version |
| `POST` | `/api/v1/hosts/{host_id}/isolate` | Analyst+ | Safe simulated host containment / isolation toggle |
| `DELETE` | `/api/v1/hosts/{host_id}` | Admin | Decommission and remove an endpoint from inventory |


