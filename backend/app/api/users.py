"""User management API router with RBAC role authorization."""

from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_db, require_admin, require_analyst
from backend.app.core.security import get_password_hash
from backend.app.models.user import User
from backend.app.schemas.user import UserCreate, UserResponse, UserUpdate
from backend.app.services.audit_service import AuditService

router = APIRouter()


@router.get(
    "",
    response_model=List[UserResponse],
    summary="List all SOC users (Requires Analyst or Admin role)",
)
@router.get(
    "/",
    response_model=List[UserResponse],
    include_in_schema=False,
)
async def list_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    role: Optional[str] = None,
) -> List[UserResponse]:
    """Retrieve list of registered users in the platform."""
    stmt = select(User).order_by(User.id.asc())
    if role:
        stmt = stmt.where(User.role == role.lower())
    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account (Requires Admin role)",
)
@router.post(
    "/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def create_user(
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
    request: Request,
) -> UserResponse:
    """Create a new user with specified role (admin, analyst, viewer)."""
    stmt = select(User).where((User.username == user_in.username) | (User.email == user_in.email))
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already in use",
        )

    user = User(
        username=user_in.username,
        email=user_in.email,
        password_hash=get_password_hash(user_in.password),
        role=user_in.role,
        is_active=user_in.is_active,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="admin_create_user",
        target_type="user",
        target_id=str(user.id),
        user_id=current_user.id,
        details={"created_username": user.username, "role": user.role},
        source_ip=client_ip,
    )
    return user


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user details by ID (Requires Analyst or Admin role)",
)
async def get_user_by_id(
    user_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> UserResponse:
    """Fetch user account by ID."""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user profile or role (Requires Admin role)",
)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
    request: Request,
) -> UserResponse:
    """Update user attributes (role, active status, email, password)."""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    updated_fields = {}
    if user_update.email is not None:
        user.email = user_update.email
        updated_fields["email"] = user_update.email
    if user_update.role is not None:
        user.role = user_update.role
        updated_fields["role"] = user_update.role
    if user_update.is_active is not None:
        user.is_active = user_update.is_active
        updated_fields["is_active"] = user_update.is_active
    if user_update.password is not None:
        user.password_hash = get_password_hash(user_update.password)
        updated_fields["password_changed"] = True

    await db.commit()
    await db.refresh(user)

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="admin_update_user",
        target_type="user",
        target_id=str(user.id),
        user_id=current_user.id,
        details=updated_fields,
        source_ip=client_ip,
    )
    return user


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user account (Requires Admin role)",
)
async def delete_user(
    user_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
    request: Request,
):
    """Deactivate or remove a user account."""
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete own account",
        )

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    await db.delete(user)
    await db.commit()

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="admin_delete_user",
        target_type="user",
        target_id=str(user_id),
        user_id=current_user.id,
        details={"deleted_username": user.username},
        source_ip=client_ip,
    )
    return None
