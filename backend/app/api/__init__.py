"""API routers package for SentinelX."""

from fastapi import APIRouter
from backend.app.api.health import router as health_router
from backend.app.api.auth import router as auth_router
from backend.app.api.users import router as users_router
from backend.app.api.audit import router as audit_router
from backend.app.api.dashboard import router as dashboard_router
from backend.app.api.events import router as events_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.incidents import router as incidents_router
from backend.app.api.hosts import router as hosts_router
from backend.app.api.rules import router as rules_router
from backend.app.api.threat_intel import router as threat_intel_router
from backend.app.api.websocket import router as websocket_router
from backend.app.api.collectors import router as collectors_router

api_router = APIRouter()

api_router.include_router(health_router, prefix="/health", tags=["Health & Diagnostics"])
api_router.include_router(auth_router, prefix="/auth", tags=["Authentication & RBAC"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["SOC Dashboard & Analytics"])
api_router.include_router(users_router, prefix="/users", tags=["User Management"])
api_router.include_router(audit_router, prefix="/audit", tags=["Security Audit Logs"])
api_router.include_router(events_router, prefix="/events", tags=["Event Ingestion"])
api_router.include_router(alerts_router, prefix="/alerts", tags=["Alert Management"])
api_router.include_router(incidents_router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(hosts_router, prefix="/hosts", tags=["Host Management"])
api_router.include_router(collectors_router, prefix="/collectors", tags=["Endpoint Collectors & Agents"])
api_router.include_router(rules_router, prefix="/rules", tags=["Detection Rules"])
api_router.include_router(threat_intel_router, prefix="/threat-intel", tags=["Threat Intelligence"])
api_router.include_router(websocket_router, prefix="/ws", tags=["Real-time WebSockets & SSE"])

__all__ = ["api_router"]
