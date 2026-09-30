"""Alert management and lifecycle endpoints."""

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_db, require_analyst, require_viewer
from backend.app.api.websocket import manager
from backend.app.detection.mitre import lookup_mitre
from backend.app.models.alert import Alert
from backend.app.models.event import SecurityEvent
from backend.app.models.user import User
from backend.app.schemas.alert import AlertResponse, AlertUpdate
from backend.app.services.audit_service import AuditService

router = APIRouter()


@router.get(
    "",
    response_model=List[AlertResponse],
    summary="List security alerts with status, severity, and MITRE filters",
)
@router.get(
    "/",
    response_model=List[AlertResponse],
    include_in_schema=False,
)
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    mitre_technique: Optional[str] = None,
) -> List[AlertResponse]:
    """Retrieve security alerts ordered by newest first with rich filtering."""
    query = select(Alert).order_by(desc(Alert.created_at))

    if status_filter:
        query = query.where(Alert.status == status_filter.upper())
    if severity:
        query = query.where(Alert.severity == severity.upper())
    if source_ip:
        query = query.where(Alert.source_ip == source_ip)
    if destination_ip:
        query = query.where(Alert.destination_ip == destination_ip)
    if mitre_technique:
        query = query.where(Alert.mitre_technique == mitre_technique)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get(
    "/{alert_id}",
    summary="Get single alert full details including evidence, telemetry event, and MITRE mapping",
)
async def get_alert(
    alert_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
) -> Dict[str, Any]:
    """Fetch complete alert details and linked event telemetry."""
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    # Fetch associated event if present
    event_data = None
    if alert.event_id:
        evt_stmt = select(SecurityEvent).where(SecurityEvent.id == alert.event_id)
        evt_res = await db.execute(evt_stmt)
        evt = evt_res.scalar_one_or_none()
        if evt:
            event_data = {
                "id": evt.id,
                "event_id": evt.event_id,
                "timestamp": evt.timestamp.isoformat(),
                "event_type": evt.event_type,
                "severity": evt.severity,
                "source": evt.source,
                "source_ip": evt.source_ip,
                "destination_ip": evt.destination_ip,
                "source_port": evt.source_port,
                "destination_port": evt.destination_port,
                "protocol": evt.protocol,
                "username": evt.username,
                "hostname": evt.hostname,
                "process_name": evt.process_name,
                "command_line": evt.command_line,
                "message": evt.message,
                "raw_event": evt.raw_event,
                "normalized_event": evt.normalized_event,
            }

    mitre_info = lookup_mitre(alert.mitre_technique) if alert.mitre_technique else None

    return {
        "id": alert.id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "status": alert.status,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "mitre_details": mitre_info,
        "analyst_notes": alert.analyst_notes,
        "threat_intel_context": alert.threat_intel_context,
        "risk_adjustment_reason": alert.risk_adjustment_reason,
        "incident_id": alert.incident_id,
        "created_at": alert.created_at.isoformat(),
        "updated_at": alert.updated_at.isoformat(),
        "event": event_data,
    }


@router.patch(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Update alert lifecycle state (NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE) and notes",
)
async def update_alert_lifecycle(
    alert_id: int,
    update_data: AlertUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    request: Request,
) -> AlertResponse:
    """Triage and advance alert through the SOC investigation lifecycle."""
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    old_status = alert.status
    if update_data.status is not None:
        alert.status = update_data.status.upper()
    if update_data.severity is not None:
        alert.severity = update_data.severity.upper()
    if update_data.risk_score is not None:
        alert.risk_score = update_data.risk_score
    if update_data.analyst_notes is not None:
        alert.analyst_notes = update_data.analyst_notes
    if update_data.incident_id is not None:
        alert.incident_id = update_data.incident_id

    alert.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(alert)

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="alert_status_updated",
        target_type="alert",
        target_id=str(alert.id),
        user_id=current_user.id,
        details={"old_status": old_status, "new_status": alert.status, "notes": alert.analyst_notes},
        source_ip=client_ip,
    )

    # Real-time WebSocket & SSE broadcast (Phase 7 alert.updated)
    alert_payload = {
        "id": alert.id,
        "title": alert.title,
        "status": alert.status,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "analyst_notes": alert.analyst_notes,
        "updated_at": alert.updated_at.isoformat(),
    }
    await manager.broadcast_alert(alert_payload, is_new=False)

    # Real-time risk-score update broadcast if risk score was modified
    if update_data.risk_score is not None:
        await manager.broadcast_risk_update({
            "entity_type": "alert",
            "entity_id": alert.id,
            "risk_score": alert.risk_score,
            "title": alert.title,
            "updated_at": alert.updated_at.isoformat(),
        })

    return alert
