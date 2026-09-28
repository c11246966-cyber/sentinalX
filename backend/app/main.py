"""SentinelX Main Application Entrypoint.

Defensive cybersecurity SOC & Threat Detection Platform.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.app.api import api_router
from backend.app.api.health import router as root_health_router
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.redis import close_redis


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle management for startup and graceful shutdown."""
    logger.info("Initializing %s v%s in [%s] mode...", settings.PROJECT_NAME, settings.VERSION, settings.ENVIRONMENT)
    logger.info("Database URL target: %s", settings.POSTGRES_SERVER)
    logger.info("Redis host target: %s:%s", settings.REDIS_HOST, settings.REDIS_PORT)
    yield
    logger.info("Shutting down SentinelX platform services...")
    await close_redis()
    logger.info("SentinelX shutdown complete.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Defensive cybersecurity SOC & Threat Detection Platform for laboratory and "
        "authorized defensive environments. Provides event ingestion, detection rules, "
        "MITRE ATT&CK mapping, and multi-event correlation."
    ),
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ------------------------------------------------------------------------------
# Secure HTTP Headers Middleware
# ------------------------------------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# ------------------------------------------------------------------------------
# CORS Middleware
# ------------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With"],
)

# ------------------------------------------------------------------------------
# Router Mounts
# ------------------------------------------------------------------------------
# Root-level health check for container orchestrators and load balancers: GET /health
app.include_router(root_health_router, prefix="/health", tags=["Health & Diagnostics"])

# Versioned API routes: GET /api/v1/*
app.include_router(api_router, prefix=settings.API_V1_STR)

# Convenience mount for /api/* without versioning prefix
app.include_router(api_router, prefix="/api")


@app.get("/", tags=["Root"])
async def root():
    """Root info endpoint."""
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "operational",
        "docs_url": "/docs",
        "health_check": "/health",
        "api_prefix": settings.API_V1_STR,
    }
