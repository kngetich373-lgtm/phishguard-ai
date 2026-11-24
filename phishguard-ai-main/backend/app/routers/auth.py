from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, status
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, get_optional_user, hash_password, verify_password
from app.config import get_settings
from app.database import get_db
from app.models import RefreshToken, User, Team
from app.schemas import (
    EmailRequest,
    MfaCodeRequest,
    MfaSetupResponse,
    MessageResponse,
    OneTimeTokenRequest,
    RefreshRequest,
    Token,
    UserCreate,
    UserLogin,
    UserOut,
)
from app.services.auth_sessions import (
    consume_one_time_token,
    create_one_time_token,
    issue_session,
    revoke_access_token,
    revoke_refresh_token,
    revoke_refresh_token_by_value,
    rotate_refresh_token,
)
from app.services.email_delivery import deliver_account_email
from app.services.mfa import (
    decrypt_secret,
    encrypt_secret,
    generate_secret,
    provisioning_uri,
    verify_totp,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="An account with that email already exists")

    team = None
    if payload.team_name:
        team = Team(name=payload.team_name)
        db.add(team)
        await db.flush()

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        team_id=team.id if team else None,
        is_admin=bool(team),  # creating a team makes you its admin
        is_email_verified=not settings.email_verification_required,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    tokens = await issue_session(db, user)
    if settings.email_verification_required:
        await _send_verification_email(db, user)
    return Token(**tokens, user=UserOut.model_validate(user))


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            data = await request.json()
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid JSON request body") from None
    else:
        form_data = await request.form()
        data = {
            "email": form_data.get("username") or form_data.get("email"),
            "password": form_data.get("password"),
            "mfa_code": form_data.get("mfa_code"),
        }
    try:
        payload = UserLogin.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(include_input=False),
        ) from None

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if user.locked_until and user.locked_until > now:
        raise HTTPException(status_code=423, detail="Account temporarily locked")
    if user.locked_until and user.locked_until <= now:
        user.locked_until = None
        user.failed_login_attempts = 0

    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.auth_max_failed_attempts:
            user.locked_until = now + timedelta(minutes=settings.auth_lockout_minutes)
        await db.commit()
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    if user.mfa_enabled:
        if not user.mfa_secret_encrypted or not verify_totp(
            decrypt_secret(user.mfa_secret_encrypted), payload.mfa_code
        ):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.auth_max_failed_attempts:
                user.locked_until = now + timedelta(minutes=settings.auth_lockout_minutes)
            await db.commit()
            raise HTTPException(status_code=401, detail="Incorrect email or MFA code")

    if settings.email_verification_required and not user.is_email_verified:
        await db.commit()
        raise HTTPException(status_code=403, detail="Verify your email address to continue")

    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()
    tokens = await issue_session(db, user)
    return Token(**tokens, user=UserOut.model_validate(user))


@router.post("/refresh", response_model=Token)
async def refresh(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await rotate_refresh_token(db, payload.refresh_token)
    return Token(
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        user=UserOut.model_validate(result["user"]),
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    authorization: str | None = Header(default=None, alias="Authorization"),
    payload: RefreshRequest | None = Body(default=None),
    current_user: User | None = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    if authorization:
        scheme, _, access_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not access_token or current_user is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
        await revoke_access_token(db, access_token, current_user)
    if payload is not None:
        if current_user:
            await revoke_refresh_token(db, payload.refresh_token, current_user.id)
        else:
            await revoke_refresh_token_by_value(db, payload.refresh_token)
    elif current_user:
        await db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.owner_id == current_user.id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(timezone.utc).replace(tzinfo=None))
        )
        await db.commit()
    else:
        raise HTTPException(status_code=401, detail="A valid access or refresh token is required")
    return MessageResponse(message="Logged out")


async def _send_verification_email(db: AsyncSession, user: User) -> None:
    token = await create_one_time_token(db, user, "email_verification")
    link = f"{settings.frontend_url.rstrip('/')}/verify-email?token={token}"
    await deliver_account_email(
        user.email,
        "Verify your PhishGuard AI email",
        f"Verify your email address using this link: {link}",
    )


@router.post("/email-verification/request", response_model=MessageResponse)
async def request_email_verification(
    payload: EmailRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if user and not user.is_email_verified:
        await _send_verification_email(db, user)
    return MessageResponse(message="If the account needs verification, an email has been sent")


@router.post("/email-verification/confirm", response_model=MessageResponse)
async def confirm_email(
    payload: OneTimeTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    user = await consume_one_time_token(db, payload.token, "email_verification")
    user.is_email_verified = True
    await db.commit()
    return MessageResponse(message="Email verified")


@router.post("/password-reset/request", response_model=MessageResponse)
async def request_password_reset(
    payload: EmailRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if user:
        token = await create_one_time_token(db, user, "password_reset")
        link = f"{settings.frontend_url.rstrip('/')}/reset-password?token={token}"
        await deliver_account_email(
            user.email,
            "Reset your PhishGuard AI password",
            f"Reset your password using this link: {link}",
        )
    return MessageResponse(message="If the account exists, a reset email has been sent")


@router.post("/password-reset/confirm", response_model=MessageResponse)
async def confirm_password_reset(
    payload: OneTimeTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    if not payload.new_password:
        raise HTTPException(status_code=422, detail="new_password is required")
    user = await consume_one_time_token(db, payload.token, "password_reset")
    user.hashed_password = hash_password(payload.new_password)
    user.token_version += 1
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.owner_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    await db.commit()
    return MessageResponse(message="Password reset complete; sign in again")


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def setup_mfa(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if current_user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    secret = generate_secret()
    current_user.mfa_secret_encrypted = encrypt_secret(secret)
    await db.commit()
    return MfaSetupResponse(
        secret=secret,
        otpauth_uri=provisioning_uri(secret, current_user.email),
    )


@router.post("/mfa/enable", response_model=MessageResponse)
async def enable_mfa(
    payload: MfaCodeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.mfa_secret_encrypted:
        raise HTTPException(status_code=409, detail="Start MFA setup first")
    if not verify_totp(decrypt_secret(current_user.mfa_secret_encrypted), payload.code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    current_user.mfa_enabled = True
    await db.commit()
    return MessageResponse(message="MFA enabled")


@router.post("/mfa/disable", response_model=MessageResponse)
async def disable_mfa(
    payload: MfaCodeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.mfa_enabled or not current_user.mfa_secret_encrypted:
        raise HTTPException(status_code=409, detail="MFA is not enabled")
    if not verify_totp(decrypt_secret(current_user.mfa_secret_encrypted), payload.code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    current_user.mfa_enabled = False
    current_user.mfa_secret_encrypted = None
    current_user.token_version += 1
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.owner_id == current_user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc).replace(tzinfo=None))
    )
    await db.commit()
    return MessageResponse(message="MFA disabled; sign in again")


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user
