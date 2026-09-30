"""Incident management API endpoints."""

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_db, require_analyst, require_viewer
from backend.app.api.websocket import manager
from backend.app.models.alert import Alert
from backend.app.models.event import SecurityEvent
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.schemas.incident import IncidentCreate, IncidentResponse, IncidentUpdate
from backend.app.services.audit_service import AuditService

router = APIRouter()


@router.get(
    "",
    response_model=List[IncidentResponse],
    summary="List security incidents with status and severity filters",
)
@router.get(
    "/",
    response_model=List[IncidentResponse],
    include_in_schema=False,
)
async def list_incidents(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
) -> List[IncidentResponse]:
    """Retrieve security incidents ordered by creation time."""
    query = select(Incident).order_by(desc(Incident.created_at))

    if status_filter:
        query = query.where(Incident.status == status_filter.upper())
    if severity:
        query = query.where(Incident.severity == severity.upper())

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    incidents = result.scalars().all()

    # Populate alert counts
    responses = []
    for inc in incidents:
        alert_count_res = await db.execute(
            select(func.count(Alert.id)).where(Alert.incident_id == inc.id)
        )
        c = alert_count_res.scalar() or 0
        inc_dict = {
            "id": inc.id,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "status": inc.status,
            "assigned_to": inc.assigned_to,
            "analyst_notes": inc.analyst_notes,
            "created_at": inc.created_at,
            "updated_at": inc.updated_at,
            "resolved_at": inc.resolved_at,
            "alert_count": c,
        }
        responses.append(IncidentResponse(**inc_dict))
    return responses


@router.get(
    "/{incident_id}",
    summary="Get full incident detail with correlated alerts and evidence timeline",
)
async def get_incident(
    incident_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_viewer)],
) -> Dict[str, Any]:
    """Fetch complete incident record with related alerts, assigned analyst, and timeline."""
    stmt = select(Incident).where(Incident.id == incident_id)
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    # Fetch related alerts
    alerts_query = await db.execute(
        select(Alert).where(Alert.incident_id == incident.id).order_by(desc(Alert.created_at))
    )
    alerts = alerts_query.scalars().all()

    alert_ids = [a.id for a in alerts]
    event_ids = [a.event_id for a in alerts if a.event_id]

    events = []
    if event_ids:
        events_query = await db.execute(
            select(SecurityEvent).where(SecurityEvent.id.in_(event_ids)).order_by(desc(SecurityEvent.timestamp))
        )
        for ev in events_query.scalars().all():
            events.append({
                "id": ev.id,
                "event_id": ev.event_id,
                "timestamp": ev.timestamp.isoformat(),
                "event_type": ev.event_type,
                "severity": ev.severity,
                "source_ip": ev.source_ip,
                "destination_ip": ev.destination_ip,
                "message": ev.message,
            })

    # Fetch assignee username
    assignee_name = None
    if incident.assigned_to:
        user_res = await db.execute(select(User).where(User.id == incident.assigned_to))
        u = user_res.scalar_one_or_none()
        if u:
            assignee_name = u.username

    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "assigned_to": incident.assigned_to,
        "assignee_name": assignee_name,
        "analyst_notes": incident.analyst_notes,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "status": a.status,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "mitre_technique": a.mitre_technique,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
        "events": events,
    }


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new security incident from alerts (Requires Analyst role)",
)
async def create_incident(
    incident_in: IncidentCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    request: Request,
) -> IncidentResponse:
    """Manually declare or elevate a security incident."""
    incident = Incident(
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity,
        risk_score=incident_in.risk_score,
        status=incident_in.status,
        assigned_to=incident_in.assigned_to or current_user.id,
        analyst_notes=incident_in.analyst_notes,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    # Link alerts if provided
    alert_count = 0
    if incident_in.alert_ids:
        stmt = select(Alert).where(Alert.id.in_(incident_in.alert_ids))
        res = await db.execute(stmt)
        alerts = res.scalars().all()
        alert_count = len(alerts)
        for a in alerts:
            a.incident_id = incident.id
            if a.status == "NEW":
                a.status = "INVESTIGATING"
        await db.commit()

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="incident_created",
        target_type="incident",
        target_id=str(incident.id),
        user_id=current_user.id,
        details={"title": incident.title, "severity": incident.severity, "linked_alerts": alert_count},
        source_ip=client_ip,
    )

    # Broadcast real-time (Phase 7 structured incident.created)
    await manager.broadcast_incident({
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "assigned_to": incident.assigned_to,
        "created_at": incident.created_at.isoformat(),
    }, is_new=True)

    return IncidentResponse(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        risk_score=incident.risk_score,
        status=incident.status,
        assigned_to=incident.assigned_to,
        analyst_notes=incident.analyst_notes,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
        alert_count=alert_count,
    )


@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Update incident status, assignment, notes, or resolution (Requires Analyst role)",
)
async def update_incident(
    incident_id: int,
    incident_update: IncidentUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    request: Request,
) -> IncidentResponse:
    """Advance incident lifecycle: NEW, INVESTIGATING, CONTAINED, RESOLVED, CLOSED."""
    stmt = select(Incident).where(Incident.id == incident_id)
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    old_status = incident.status
    if incident_update.title is not None:
        incident.title = incident_update.title
    if incident_update.description is not None:
        incident.description = incident_update.description
    if incident_update.severity is not None:
        incident.severity = incident_update.severity
    if incident_update.risk_score is not None:
        incident.risk_score = incident_update.risk_score
    if incident_update.status is not None:
        incident.status = incident_update.status.upper()
        if incident.status in ["RESOLVED", "CLOSED"]:
            incident.resolved_at = datetime.now(timezone.utc)
    if incident_update.assigned_to is not None:
        incident.assigned_to = incident_update.assigned_to
    if incident_update.analyst_notes is not None:
        incident.analyst_notes = incident_update.analyst_notes

    incident.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(incident)

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="incident_updated",
        target_type="incident",
        target_id=str(incident.id),
        user_id=current_user.id,
        details={"old_status": old_status, "new_status": incident.status, "notes": incident.analyst_notes},
        source_ip=client_ip,
    )

    # Broadcast real-time (Phase 7 structured incident.updated)
    await manager.broadcast_incident({
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "assigned_to": incident.assigned_to,
        "analyst_notes": incident.analyst_notes,
        "updated_at": incident.updated_at.isoformat(),
    }, is_new=False)

    # Real-time risk-score update broadcast if risk score was modified
    if incident_update.risk_score is not None:
        await manager.broadcast_risk_update({
            "entity_type": "incident",
            "entity_id": incident.id,
            "risk_score": incident.risk_score,
            "title": incident.title,
            "updated_at": incident.updated_at.isoformat(),
        })

    # Count linked alerts
    c_res = await db.execute(select(func.count(Alert.id)).where(Alert.incident_id == incident.id))
    c = c_res.scalar() or 0

    return IncidentResponse(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        risk_score=incident.risk_score,
        status=incident.status,
        assigned_to=incident.assigned_to,
        analyst_notes=incident.analyst_notes,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
        alert_count=c,
    )
