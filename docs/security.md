# SentinelX Defensive Security & Hardening Architecture

## 1. Security Principles

SentinelX adheres to defense-in-depth principles across the software and infrastructure lifecycle:

1. **Least Privilege & Role-Based Access Control (RBAC)**:
   - `VIEWER`: Read-only telemetry, events, and alerts.
   - `ANALYST`: Alert triage, incident escalation, investigation notes.
   - `ADMIN`: Detection rule editing, user administration, response authorization.
2. **Password Security**:
   - Modern Argon2id hashing via Passlib.
   - Zero plaintext storage in database, caches, or logs.
3. **No Hard-Coded Credentials**:
   - Secret tokens and DB strings configured strictly via environment variables.
4. **Input Sanitization & Injection Prevention**:
   - Pydantic models validate every field, port range, IP format, and string length.
   - SQLAlchemy ORM parameterization prevents SQL injection.
5. **Secure HTTP Response Headers**:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - Strict CORS whitelist.
6. **Defensive Response Safe-Mode**:
   - Response actions (IP blocking, host isolation) are strictly simulated in default lab configurations.
   - Mandatory immutable audit records on every administrative operation.
