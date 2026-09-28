# SentinelX Deployment Guide

## 1. Prerequisites

- Docker Engine 24.0+ and Docker Compose v2.20+
- Host with at least 4 GB RAM and 20 GB disk space
- Ports: `3000` (Frontend), `8000` (Backend API), `5432` (PostgreSQL), `6379` (Redis)

## 2. Quickstart with Docker Compose

1. Clone or navigate to the repository:
   ```bash
   cd sentinelx
   ```

2. Copy the sample environment file and generate a production secret key:
   ```bash
   cp .env.example .env
   # Edit .env and replace SECRET_KEY with a strong secret
   ```

3. Launch all platform services:
   ```bash
   docker compose up --build -d
   ```

4. Verify service status and health:
   ```bash
   docker compose ps
   curl -s http://localhost:8000/health | jq .
   ```

5. Access interfaces:
   - SOC Web Dashboard: `http://localhost:3000`
   - FastAPI Interactive Docs: `http://localhost:8000/docs`
   - Health Status: `http://localhost:8000/health`

## 3. Manual / Local Development Setup

### Backend
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend
```bash
npm install
npm run dev
```
