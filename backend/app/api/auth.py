"""Authentication and session management API router."""

from datetime import datetime, timezone
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_current_user, get_db
from backend.app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    get_password_hash,
    verify_password,
)
from backend.app.models.user import User
from backend.app.schemas.user import RefreshTokenRequest, Token, UserCreate, UserResponse
from backend.app.services.audit_service import AuditService

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new SOC user account",
)
async def register(
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> UserResponse:
    """Register initial or analyst user account."""
    # Check if username or email already exists
    stmt = select(User).where((User.username == user_in.username) | (User.email == user_in.email))
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )

    # Hash password with Argon2
    hashed_password = get_password_hash(user_in.password)
    user = User(
        username=user_in.username,
        email=user_in.email,
        password_hash=hashed_password,
        role=user_in.role,
        is_active=user_in.is_active,
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="user_registered",
        target_type="user",
        target_id=str(user.id),
        user_id=user.id,
        details={"username": user.username, "role": user.role},
        source_ip=client_ip,
    )
    return user


@router.post(
    "/login",
    response_model=Token,
    summary="Authenticate and receive JWT access & refresh tokens (JSON)",
)
async def login(
    credentials: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> Token:
    """Verify credentials with Argon2 and issue JWT token pair."""
    stmt = select(User).where(User.username == credentials.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    client_ip = request.client.host if request.client else None

    if not user or not verify_password(credentials.password, user.password_hash):
        await AuditService.log_action(
            db=db,
            action="login_failure",
            target_type="user",
            target_id=credentials.username,
            details={"reason": "invalid_credentials"},
            source_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    # Update last login timestamp
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    access_token = create_access_token(subject=user.username, role=user.role)
    refresh_token = create_refresh_token(subject=user.username, role=user.role)

    await AuditService.log_action(
        db=db,
        action="login_success",
        target_type="user",
        target_id=str(user.id),
        user_id=user.id,
        details={"role": user.role},
        source_ip=client_ip,
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        role=user.role,
        username=user.username,
        user_id=user.id,
    )


@router.post(
    "/token",
    response_model=Token,
    summary="OAuth2 compatible token endpoint for Swagger/OpenAPI UI",
    include_in_schema=False,
)
async def login_oauth2(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> Token:
    """OAuth2 password form compatible authentication."""
    credentials = LoginRequest(username=form_data.username, password=form_data.password)
    return await login(credentials=credentials, db=db, request=request)


@router.post(
    "/refresh",
    response_model=Token,
    summary="Exchange valid refresh token for fresh access token",
)
async def refresh_token(
    payload: RefreshTokenRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> Token:
    """Issue a new access token using a valid refresh token."""
    decoded = decode_refresh_token(payload.refresh_token)
    if not decoded:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username: Optional[str] = decoded.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    stmt = select(User).where(User.username == username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer active or found",
        )

    new_access_token = create_access_token(subject=user.username, role=user.role)
    new_refresh_token = create_refresh_token(subject=user.username, role=user.role)

    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="token_refresh",
        target_type="user",
        target_id=str(user.id),
        user_id=user.id,
        source_ip=client_ip,
    )

    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        role=user.role,
        username=user.username,
        user_id=user.id,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile",
)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserResponse:
    """Retrieve profile and role details of authenticated operator."""
    return current_user


@router.post(
    "/logout",
    summary="Invalidate active session and log out operator",
)
async def logout(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
):
    """Log out current operator and write audit event."""
    client_ip = request.client.host if request.client else None
    await AuditService.log_action(
        db=db,
        action="user_logout",
        target_type="user",
        target_id=str(current_user.id),
        user_id=current_user.id,
        source_ip=client_ip,
    )
    return {"status": "logged_out", "username": current_user.username}
