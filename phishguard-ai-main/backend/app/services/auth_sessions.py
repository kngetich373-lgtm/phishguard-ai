import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
import jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import OneTimeToken, RefreshToken, RevokedAccessToken, User


settings = get_settings()


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def make_access_token(user: User) -> tuple[str, datetime]:
    expires_at = _utcnow_naive() + timedelta(minutes=settings.access_token_expire_minutes)
    token = jwt.encode(
        {
            "sub": user.id,
            "ver": user.token_version,
            "exp": expires_at.replace(tzinfo=timezone.utc),
        },
        settings.secret_key,
        algorithm=settings.algorithm,
    )
    return token, expires_at


async def issue_session(db: AsyncSession, user: User, family_id: str | None = None) -> dict:
    access_token, _ = make_access_token(user)
    refresh_token = secrets.token_urlsafe(48)
    now = _utcnow_naive()
    db.add(
        RefreshToken(
            token_hash=_token_hash(refresh_token),
            family_id=family_id or str(uuid.uuid4()),
            owner_id=user.id,
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
            created_at=now,
        )
    )
    await db.commit()
    return {"access_token": access_token, "refresh_token": refresh_token}


async def rotate_refresh_token(db: AsyncSession, raw_token: str, user: User | None = None) -> dict:
    token_hash = _token_hash(raw_token)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash).with_for_update()
    )
    current = result.scalar_one_or_none()
    now = _utcnow_naive()
    if current is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if current.revoked_at is not None:
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == current.family_id)
            .values(revoked_at=now)
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Refresh token reuse detected")
    if current.expires_at <= now or (user is not None and current.owner_id != user.id):
        current.revoked_at = now
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    owner_result = await db.execute(select(User).where(User.id == current.owner_id))
    owner = owner_result.scalar_one_or_none()
    if owner is None:
        current.revoked_at = now
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    family_id = current.family_id
    current.revoked_at = now
    access_token, _ = make_access_token(owner)
    next_refresh_token = secrets.token_urlsafe(48)
    db.add(
        RefreshToken(
            token_hash=_token_hash(next_refresh_token),
            family_id=family_id,
            owner_id=owner.id,
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
            created_at=now,
        )
    )
    await db.commit()
    return {
        "access_token": access_token,
        "refresh_token": next_refresh_token,
        "user": owner,
    }


async def revoke_access_token(db: AsyncSession, token: str, user: User) -> None:
    try:
        claims = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        expires_at = datetime.fromtimestamp(claims["exp"], timezone.utc).replace(tzinfo=None)
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Could not validate credentials") from None

    now = _utcnow_naive()
    if expires_at <= now:
        return
    exists = await db.execute(
        select(RevokedAccessToken.id).where(
            RevokedAccessToken.token_hash == _token_hash(token)
        )
    )
    if exists.scalar_one_or_none() is None:
        db.add(
            RevokedAccessToken(
                token_hash=_token_hash(token),
                owner_id=user.id,
                expires_at=expires_at,
                created_at=now,
            )
        )
    await db.commit()


async def revoke_refresh_token(
    db: AsyncSession,
    raw_token: str,
    owner_id: str,
) -> None:
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == _token_hash(raw_token),
            RefreshToken.owner_id == owner_id,
        )
    )
    refresh = result.scalar_one_or_none()
    if refresh is not None and refresh.revoked_at is None:
        refresh.revoked_at = _utcnow_naive()
        await db.commit()


async def revoke_refresh_token_by_value(db: AsyncSession, raw_token: str) -> None:
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == _token_hash(raw_token))
    )
    refresh = result.scalar_one_or_none()
    if refresh is not None and refresh.revoked_at is None:
        refresh.revoked_at = _utcnow_naive()
        await db.commit()


async def create_one_time_token(
    db: AsyncSession,
    user: User,
    purpose: str,
) -> str:
    raw_token = secrets.token_urlsafe(48)
    now = _utcnow_naive()
    if purpose == "password_reset":
        expires_at = now + timedelta(minutes=settings.password_reset_expire_minutes)
    elif purpose == "email_verification":
        expires_at = now + timedelta(hours=settings.email_verification_expire_hours)
    else:
        raise ValueError(f"Unsupported one-time token purpose: {purpose}")
    db.add(
        OneTimeToken(
            token_hash=_token_hash(raw_token),
            purpose=purpose,
            owner_id=user.id,
            expires_at=expires_at,
            created_at=now,
        )
    )
    await db.commit()
    return raw_token


async def consume_one_time_token(
    db: AsyncSession,
    raw_token: str,
    purpose: str,
) -> User:
    result = await db.execute(
        select(OneTimeToken)
        .where(OneTimeToken.token_hash == _token_hash(raw_token))
        .with_for_update()
    )
    token = result.scalar_one_or_none()
    now = _utcnow_naive()
    if (
        token is None
        or token.purpose != purpose
        or token.consumed_at is not None
        or token.expires_at <= now
    ):
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    token.consumed_at = now
    user_result = await db.execute(select(User).where(User.id == token.owner_id))
    user = user_result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    return user
