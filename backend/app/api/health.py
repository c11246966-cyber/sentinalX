"""Health check endpoints for load balancers, orchestrators, and monitoring."""

import time
from datetime import datetime, timezone
from typing import Dict
from fastapi import APIRouter, status
from sqlalchemy import text
from backend.app.core.config import settings
from backend.app.core.database import AsyncSessionLocal
from backend.app.core.redis import get_redis
from backend.app.schemas.health import HealthStatusResponse, ServiceHealthDetail

router = APIRouter()


@router.get(
    "",
    response_model=HealthStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Comprehensive platform health check",
    description="Evaluates operational status of backend services, PostgreSQL database, and Redis cache.",
)
@router.get(
    "/",
    response_model=HealthStatusResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def check_health() -> HealthStatusResponse:
    """Perform real-time health check on core dependencies."""
    services: Dict[str, ServiceHealthDetail] = {}
    overall_status = "healthy"

    # 1. API Service Status
    services["api"] = ServiceHealthDetail(
        status="healthy",
        latency_ms=0.05,
        message="FastAPI core dispatcher active",
    )

    # 2. PostgreSQL Health Check
    t0 = time.perf_counter()
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        latency = round((time.perf_counter() - t0) * 1000, 2)
        services["database"] = ServiceHealthDetail(
            status="healthy",
            latency_ms=latency,
            message=f"PostgreSQL connection verified ({settings.POSTGRES_DB})",
        )
    except Exception as e:
        latency = round((time.perf_counter() - t0) * 1000, 2)
        services["database"] = ServiceHealthDetail(
            status="degraded",
            latency_ms=latency,
            message=f"PostgreSQL unreachable: {str(e)}",
        )
        overall_status = "degraded"

    # 3. Redis Health Check
    t0 = time.perf_counter()
    try:
        client = await get_redis()
        pong = await client.ping()
        latency = round((time.perf_counter() - t0) * 1000, 2)
        if pong:
            services["redis"] = ServiceHealthDetail(
                status="healthy",
                latency_ms=latency,
                message="Redis cache and pub/sub operational",
            )
        else:
            services["redis"] = ServiceHealthDetail(
                status="degraded",
                latency_ms=latency,
                message="Redis did not respond with PONG",
            )
            overall_status = "degraded"
    except Exception as e:
        latency = round((time.perf_counter() - t0) * 1000, 2)
        services["redis"] = ServiceHealthDetail(
            status="degraded",
            latency_ms=latency,
            message=f"Redis unreachable: {str(e)}",
        )
        overall_status = "degraded"

    return HealthStatusResponse(
        status=overall_status,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
        services=services,
    )
