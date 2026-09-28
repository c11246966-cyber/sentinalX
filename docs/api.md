# SentinelX API Reference Specification

## Base URLs
- Local Development: `http://localhost:8000/api/v1`
- OpenAPI Documentation: `http://localhost:8000/docs`
- Redoc Documentation: `http://localhost:8000/redoc`

## Endpoints Overview

| Method | Endpoint | Description | Phase |
|---|---|---|---|
| `GET` | `/health` | Platform & dependency health status | Phase 1 |
| `GET` | `/api/v1/health` | Service health with latency & diagnostics | Phase 1 |
| `POST` | `/api/v1/auth/login` | Issue JWT access token (Argon2 check) | Phase 2 |
| `GET` | `/api/v1/events` | Query ingested security events | Phase 3 |
| `POST` | `/api/v1/events` | Ingest normalized or raw telemetry | Phase 3 |
| `GET` | `/api/v1/alerts` | Filter and list detection alerts | Phase 4 |
| `GET` | `/api/v1/alerts/{id}` | Retrieve individual alert & risk breakdown | Phase 4 |
| `PATCH` | `/api/v1/alerts/{id}` | Transition alert status (TRIAGED, RESOLVED) | Phase 4 |
| `GET` | `/api/v1/incidents` | List correlated incidents | Phase 5 |
| `POST` | `/api/v1/incidents` | Create or aggregate an incident | Phase 5 |
| `GET` | `/api/v1/incidents/{id}` | Full incident timeline & related alerts | Phase 5 |
| `PATCH` | `/api/v1/incidents/{id}` | Update incident status & analyst assignments | Phase 5 |
| `GET` | `/api/v1/hosts` | List monitored endpoints and agent status | Phase 6 |
| `GET` | `/api/v1/rules` | List detection rules catalog | Phase 4 |
| `POST` | `/api/v1/rules` | Create custom detection rule (Admin only) | Phase 4 |
| `PATCH` | `/api/v1/rules/{id}` | Enable/disable or tune rule thresholds | Phase 4 |
| `GET` | `/api/v1/threat-intel/{indicator}` | Reputation query for IP, hash, or domain | Phase 8 |
| `GET` | `/api/v1/audit-logs` | Retrieve immutable administrative audit trail | Phase 2 |
| `WS` | `/api/v1/ws/events` | Real-time WebSocket event & alert feed | Phase 7 |

## Health Check Schema Example

```json
{
  "status": "healthy",
  "version": "0.1.0-alpha",
  "environment": "development",
  "timestamp": "2026-09-28T16:20:00.000000Z",
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
