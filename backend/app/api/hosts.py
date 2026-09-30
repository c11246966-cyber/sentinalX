"""Host inventory and endpoint monitoring endpoints for Phase 6."""

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_db, require_admin, require_analyst, require_viewer
from backend.app.core.logging import logger
from backend.app.models.alert import Alert
from backend.app.models.event import SecurityEvent
from backend.app.models.host import Host
from backend.app.models.user import User
from backend.app.api.websocket import manager
from backend.app.schemas.host import (
    HostCreate,
    HostDetailResponse,
    HostHeartbeat,
    HostIsolationRequest,
    HostResponse,
    HostUpdate,
)
from backend.app.services.audit_service import AuditService

router = APIRouter()


@router.get(
    "",
    response_model=List[HostResponse],
    summary="List monitored endpoints and inventory (Requires Viewer+ role)",
)
@router.get(
    "/",
    response_model=List[HostResponse],
    include_in_schema=False,
)
async def list_hosts(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
    status_filter: Optional[str] = Query(None, alias="status"),
    os_filter: Optional[str] = Query(None, alias="os"),
    search: Optional[str] = Query(None, alias="search"),
) -> List[HostResponse]:
    """Retrieve all monitored host endpoints with dynamic health status evaluation."""
    stmt = select(Host).order_by(desc(Host.last_seen))

    if status_filter and status_filter.upper() != "ALL":
        stmt = stmt.where(Host.status == status_filter.upper())
    if os_filter and os_filter.upper() != "ALL":
        stmt = stmt.where(Host.operating_system.ilike(f"%{os_filter}%"))
    if search:
        term = f"%{search.strip()}%"
        stmt = stmt.where(Host.hostname.ilike(term) | Host.ip_address.ilike(term))

    res = await db.execute(stmt)
    hosts = list(res.scalars().all())

    # Dynamically update in-memory status representation based on last_seen latency
    now = datetime.now(timezone.utc)
    for h in hosts:
        if h.status == "ISOLATED":
            continue
        diff = (now - h.last_seen).total_seconds()
        if diff > 180.0 and h.status != "OFFLINE":
            h.status = "OFFLINE"
        elif diff > 60.0 and h.status == "ONLINE":
            h.status = "DEGRADED"

    return hosts


@router.post(
    "",
    response_model=HostResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new endpoint in host inventory (Requires Analyst+ role)",
)
@router.post(
    "/",
    response_model=HostResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def register_host(
    payload: HostCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    request: Request,
) -> HostResponse:
    """Manually register an endpoint or provision an agent in inventory."""
    # Check uniqueness of hostname
    existing = await db.execute(select(Host).where(Host.hostname == payload.hostname.strip()))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Host with hostname '{payload.hostname}' is already registered.",
        )

    now = datetime.now(timezone.utc)
    host = Host(
        hostname=payload.hostname.strip(),
        ip_address=payload.ip_address.strip(),
        operating_system=payload.operating_system.strip(),
        agent_version=payload.agent_version.strip(),
        status=payload.status.upper() if payload.status else "ONLINE",
        last_seen=now,
        created_at=now,
    )
    db.add(host)
    await db.commit()
    await db.refresh(host)

    # Audit logging
    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="host_register",
        target_type="host",
        target_id=str(host.id),
        user_id=current_user.id,
        details={
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "operating_system": host.operating_system,
        },
        source_ip=client_ip,
    )

    # Real-time WebSocket broadcast
    await manager.broadcast_host_status({
        "id": host.id,
        "hostname": host.hostname,
        "ip_address": host.ip_address,
        "operating_system": host.operating_system,
        "agent_version": host.agent_version,
        "status": host.status,
        "last_seen": host.last_seen.isoformat(),
        "created_at": host.created_at.isoformat(),
    })

    return host


@router.get(
    "/{host_id}",
    response_model=HostDetailResponse,
    summary="Get endpoint telemetry details, recent events, and risk (Requires Viewer+ role)",
)
async def get_host_detail(
    host_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
) -> HostDetailResponse:
    """Retrieve complete profile of an endpoint including related security signals."""
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host ID {host_id} not found in inventory.",
        )

    # 1. Fetch recent events tied to this host
    events_stmt = (
        select(SecurityEvent)
        .where((SecurityEvent.hostname == host.hostname) | (SecurityEvent.source_ip == host.ip_address))
        .order_by(desc(SecurityEvent.timestamp))
        .limit(10)
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
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
        }
        for e in events_res.scalars().all()
    ]

    # 2. Fetch recent alerts tied to this host
    alerts_stmt = (
        select(Alert)
        .where(
            Alert.description.ilike(f"%{host.hostname}%")
            | (Alert.source_ip == host.ip_address)
            | (Alert.destination_ip == host.ip_address)
        )
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

    # Compute risk score
    max_risk = max([a["risk_score"] for a in recent_alerts], default=20)
    if host.status == "ISOLATED":
        max_risk = max(max_risk, 85)

    return HostDetailResponse(
        id=host.id,
        hostname=host.hostname,
        ip_address=host.ip_address,
        operating_system=host.operating_system,
        agent_version=host.agent_version,
        status=host.status,
        last_seen=host.last_seen,
        created_at=host.created_at,
        event_count=len(recent_events),
        alert_count=len(recent_alerts),
        calculated_risk=max_risk,
        recent_events=recent_events,
        recent_alerts=recent_alerts,
    )


@router.patch(
    "/{host_id}",
    response_model=HostResponse,
    summary="Update endpoint properties or status (Requires Analyst+ role)",
)
async def update_host(
    host_id: int,
    payload: HostUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    request: Request,
) -> HostResponse:
    """Update endpoint network metadata or administrative status."""
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host ID {host_id} not found in inventory.",
        )

    if payload.ip_address is not None:
        host.ip_address = payload.ip_address.strip()
    if payload.operating_system is not None:
        host.operating_system = payload.operating_system.strip()
    if payload.agent_version is not None:
        host.agent_version = payload.agent_version.strip()
    if payload.status is not None:
        host.status = payload.status.upper().strip()

    await db.commit()
    await db.refresh(host)

    # Audit logging
    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="host_update",
        target_type="host",
        target_id=str(host.id),
        user_id=current_user.id,
        details=payload.model_dump(exclude_unset=True),
        source_ip=client_ip,
    )

    # Real-time WebSocket broadcast
    await manager.broadcast_host_status({
        "id": host.id,
        "hostname": host.hostname,
        "ip_address": host.ip_address,
        "operating_system": host.operating_system,
        "status": host.status,
        "last_seen": host.last_seen.isoformat() if host.last_seen else None,
        "agent_version": host.agent_version,
    })

    return host


@router.post(
    "/{host_id}/heartbeat",
    response_model=HostResponse,
    summary="Process agent check-in heartbeat and update last_seen timestamp",
)
async def host_heartbeat(
    host_id: int,
    payload: HostHeartbeat,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HostResponse:
    """Agent check-in endpoint called periodically by endpoints."""
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host ID {host_id} not found in inventory.",
        )

    now = datetime.now(timezone.utc)
    host.last_seen = now
    if host.status != "ISOLATED":
        host.status = payload.status.upper() if payload.status else "ONLINE"
    if payload.agent_version:
        host.agent_version = payload.agent_version.strip()

    await db.commit()
    await db.refresh(host)

    # Real-time WebSocket broadcast
    await manager.broadcast_host_status({
        "id": host.id,
        "hostname": host.hostname,
        "ip_address": host.ip_address,
        "status": host.status,
        "last_seen": host.last_seen.isoformat(),
        "agent_version": host.agent_version,
    })

    return host


@router.post(
    "/{host_id}/isolate",
    response_model=HostResponse,
    summary="Safe simulated endpoint isolation / containment (Requires Analyst+ role)",
)
async def isolate_host(
    host_id: int,
    payload: HostIsolationRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    request: Request,
) -> HostResponse:
    """Safely isolate or restore an endpoint in laboratory simulation mode.
    
    Prevents malware spread in simulated labs without modifying live physical firewalls.
    """
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host ID {host_id} not found in inventory.",
        )

    prev_status = host.status
    new_status = "ISOLATED" if payload.isolate else "ONLINE"
    host.status = new_status
    await db.commit()
    await db.refresh(host)

    # Log safe simulated action
    logger.info(
        f"[SAFE LAB CONTAINMENT] User {current_user.username} (ID: {current_user.id}) set host "
        f"{host.hostname} ({host.ip_address}) status to {new_status}. Reason: {payload.reason}"
    )

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="host_isolate" if payload.isolate else "host_unisolate",
        target_type="host",
        target_id=str(host.id),
        user_id=current_user.id,
        details={
            "hostname": host.hostname,
            "ip_address": host.ip_address,
            "previous_status": prev_status,
            "new_status": new_status,
            "reason": payload.reason,
            "simulated_lab_mode": True,
        },
        source_ip=client_ip,
    )

    # Real-time WebSocket broadcast
    await manager.broadcast_host_status({
        "id": host.id,
        "hostname": host.hostname,
        "ip_address": host.ip_address,
        "status": host.status,
        "last_seen": host.last_seen.isoformat(),
        "agent_version": host.agent_version,
    })

    return host


@router.delete(
    "/{host_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Decommission and remove an endpoint from inventory (Requires Admin role)",
)
async def delete_host(
    host_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
    request: Request,
):
    """Permanently delete an endpoint from inventory records."""
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host ID {host_id} not found in inventory.",
        )

    hostname = host.hostname
    await db.delete(host)
    await db.commit()

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="host_delete",
        target_type="host",
        target_id=str(host_id),
        user_id=current_user.id,
        details={"hostname": hostname},
        source_ip=client_ip,
    )
