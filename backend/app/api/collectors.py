"""Collector registration, heartbeat, and management endpoints for Phase 6."""

from datetime import datetime, timezone
import hashlib
import secrets
from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_db, require_admin, require_analyst, require_viewer
from backend.app.core.logging import logger
from backend.app.models.alert import Alert
from backend.app.models.collector import Collector
from backend.app.models.event import SecurityEvent
from backend.app.models.user import User
from backend.app.schemas.collector import (
    CollectorDetailResponse,
    CollectorHeartbeatRequest,
    CollectorHeartbeatResponse,
    CollectorRegisterRequest,
    CollectorRegisterResponse,
    CollectorResponse,
)
from backend.app.services.audit_service import AuditService

router = APIRouter()


def hash_collector_token(token: str) -> str:
    """Generate SHA-256 hash for secure token verification."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@router.post(
    "/register",
    response_model=CollectorRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new Windows endpoint collector (Requires Analyst+ role)",
)
async def register_collector(
    payload: CollectorRegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    request: Request,
) -> CollectorRegisterResponse:
    """Issue a unique collector ID and authorization API key for a Windows endpoint."""
    collector_id = f"win-{secrets.token_hex(8)}"
    raw_api_key = f"snx_col_{secrets.token_urlsafe(32)}"
    key_hash = hash_collector_token(raw_api_key)

    now = datetime.now(timezone.utc)
    collector = Collector(
        collector_id=collector_id,
        name=payload.name.strip(),
        hostname=payload.hostname.strip(),
        ip_address=payload.ip_address.strip(),
        operating_system=payload.operating_system.strip(),
        agent_version=payload.agent_version.strip(),
        status="ONLINE",
        api_key_hash=key_hash,
        registered_at=now,
        last_seen=now,
        event_count=0,
        alert_count=0,
        metadata_json=payload.metadata_json or {},
    )
    db.add(collector)
    await db.commit()
    await db.refresh(collector)

    # Audit log collector registration
    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="collector_register",
        target_type="collector",
        target_id=collector_id,
        user_id=current_user.id,
        details={
            "hostname": payload.hostname,
            "ip_address": payload.ip_address,
            "operating_system": payload.operating_system,
        },
        source_ip=client_ip,
    )

    instructions = (
        f"Collector registered successfully. Set SENTINELX_COLLECTOR_ID={collector_id} and "
        f"SENTINELX_API_KEY={raw_api_key} on the Windows host."
    )

    return CollectorRegisterResponse(
        collector_id=collector_id,
        api_key=raw_api_key,
        name=collector.name,
        hostname=collector.hostname,
        operating_system=collector.operating_system,
        registered_at=collector.registered_at,
        status=collector.status,
        instructions=instructions,
    )


@router.post(
    "/{collector_id}/heartbeat",
    response_model=CollectorHeartbeatResponse,
    summary="Update collector status, telemetry metrics, and check-in timestamp",
)
async def collector_heartbeat(
    collector_id: str,
    payload: CollectorHeartbeatRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    x_collector_key: Optional[str] = Header(None, alias="X-Collector-Key"),
) -> CollectorHeartbeatResponse:
    """Heartbeat endpoint pinged every 15-30s by Windows agents."""
    stmt = select(Collector).where(Collector.collector_id == collector_id)
    res = await db.execute(stmt)
    collector = res.scalar_one_or_none()

    if not collector:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Collector '{collector_id}' not found.",
        )

    # Optional key verification on heartbeat if key supplied
    if x_collector_key:
        if hash_collector_token(x_collector_key) != collector.api_key_hash:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid collector authorization token.",
            )

    now = datetime.now(timezone.utc)
    collector.last_seen = now
    collector.status = payload.status or "ONLINE"
    if payload.hostname:
        collector.hostname = payload.hostname
    if payload.ip_address:
        collector.ip_address = payload.ip_address
    if payload.agent_version:
        collector.agent_version = payload.agent_version
    if payload.telemetry_stats and isinstance(collector.metadata_json, dict):
        merged = dict(collector.metadata_json)
        merged["stats"] = payload.telemetry_stats
        collector.metadata_json = merged

    await db.commit()

    return CollectorHeartbeatResponse(
        collector_id=collector.collector_id,
        status=collector.status,
        last_seen=collector.last_seen,
        server_time=now,
        next_heartbeat_seconds=30,
    )


@router.get(
    "",
    response_model=List[CollectorResponse],
    summary="List all registered endpoint collectors and agent statuses",
)
@router.get(
    "/",
    response_model=List[CollectorResponse],
    include_in_schema=False,
)
async def list_collectors(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
    status_filter: Optional[str] = Query(None, alias="status"),
) -> List[CollectorResponse]:
    """Retrieve all monitored agents with dynamic status evaluation."""
    stmt = select(Collector).order_by(desc(Collector.last_seen))
    if status_filter and status_filter.upper() != "ALL":
        stmt = stmt.where(Collector.status == status_filter.upper())

    res = await db.execute(stmt)
    collectors = list(res.scalars().all())

    # Dynamically compute ONLINE/DEGRADED/OFFLINE if last_seen is stale
    now = datetime.now(timezone.utc)
    for c in collectors:
        diff = (now - c.last_seen).total_seconds()
        if diff > 120.0 and c.status != "OFFLINE":
            c.status = "OFFLINE"
        elif diff > 45.0 and c.status == "ONLINE":
            c.status = "DEGRADED"

    return collectors


@router.get(
    "/{collector_id}",
    response_model=CollectorDetailResponse,
    summary="Get detailed collector status, recent events, and alerts",
)
async def get_collector_detail(
    collector_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
) -> CollectorDetailResponse:
    """Retrieve collector metrics along with its recent events and triggered alerts."""
    stmt = select(Collector).where(Collector.collector_id == collector_id)
    res = await db.execute(stmt)
    collector = res.scalar_one_or_none()

    if not collector:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Collector '{collector_id}' not found.",
        )

    # Fetch recent events for this collector hostname
    events_stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.hostname == collector.hostname)
        .order_by(desc(SecurityEvent.created_at))
        .limit(15)
    )
    events_res = await db.execute(events_stmt)
    recent_events = [
        {
            "id": e.id,
            "event_id": e.event_id,
            "event_type": e.event_type,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "severity": e.severity,
            "message": e.message,
            "username": e.username,
            "process_name": e.process_name,
            "source_ip": e.source_ip,
        }
        for e in events_res.scalars().all()
    ]

    # Fetch alerts referencing this host
    alerts_stmt = (
        select(Alert)
        .where(Alert.description.ilike(f"%{collector.hostname}%"))
        .order_by(desc(Alert.created_at))
        .limit(10)
    )
    alerts_res = await db.execute(alerts_stmt)
    recent_alerts = [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "status": a.status,
            "created_at": a.created_at.isoformat(),
        }
        for a in alerts_res.scalars().all()
    ]

    return CollectorDetailResponse(
        id=collector.id,
        collector_id=collector.collector_id,
        name=collector.name,
        hostname=collector.hostname,
        ip_address=collector.ip_address,
        operating_system=collector.operating_system,
        agent_version=collector.agent_version,
        status=collector.status,
        registered_at=collector.registered_at,
        last_seen=collector.last_seen,
        event_count=collector.event_count,
        alert_count=collector.alert_count,
        metadata_json=collector.metadata_json,
        recent_events=recent_events,
        recent_alerts=recent_alerts,
    )


@router.delete(
    "/{collector_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke and deregister a collector (Requires Admin role)",
)
async def delete_collector(
    collector_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
    request: Request,
):
    """Permanently revoke and delete an endpoint telemetry agent registration."""
    stmt = select(Collector).where(Collector.collector_id == collector_id)
    res = await db.execute(stmt)
    collector = res.scalar_one_or_none()

    if not collector:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Collector '{collector_id}' not found.",
        )

    await db.delete(collector)
    await db.commit()

    # Log audit event
    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="collector_deregister",
        target_type="collector",
        target_id=collector_id,
        user_id=current_user.id,
        details={"hostname": collector.hostname},
        source_ip=client_ip,
    )
