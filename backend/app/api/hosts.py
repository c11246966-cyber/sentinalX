"""Host inventory and agent status endpoints."""

from fastapi import APIRouter

router = APIRouter()


@router.get("", summary="List monitored endpoints and hosts")
async def list_hosts():
    return {"hosts": [], "total": 0}
