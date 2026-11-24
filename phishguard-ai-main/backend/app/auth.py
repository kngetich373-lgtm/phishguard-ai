"""
Authentication utilities: password hashing and JWT issuance/verification.
"""
from datetime import datetime, timedelta, timezone
import hashlib

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import ApiKey, RevokedAccessToken, User

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
optional_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    return await _resolve_access_token(token, db)


async def _resolve_access_token(token: str, db: AsyncSession) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id = payload.get("sub")
        if not user_id:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or payload.get("ver", 0) != user.token_version:
        raise credentials_exception
    if settings.email_verification_required and not user.is_email_verified:
        raise HTTPException(status_code=403, detail="Verify your email address to continue")
    revoked = await db.execute(
        select(RevokedAccessToken.id).where(
            RevokedAccessToken.token_hash == hashlib.sha256(token.encode("utf-8")).hexdigest()
        )
    )
    if revoked.scalar_one_or_none() is not None:
        raise credentials_exception
    return user


async def get_optional_user(
    token: str | None = Depends(optional_oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    if not token:
        return None
    return await _resolve_access_token(token, db)


async def get_api_key_user(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> User:
    return await _resolve_api_key(x_api_key, db)


async def _resolve_api_key(x_api_key: str | None, db: AsyncSession) -> User:
    if not x_api_key or not x_api_key.startswith("pg_live_"):
        raise HTTPException(status_code=401, detail="A valid API key is required")
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.active.is_(True))
    )
    api_key = result.scalar_one_or_none()
    if api_key is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    owner_result = await db.execute(select(User).where(User.id == api_key.owner_id))
    owner = owner_result.scalar_one_or_none()
    if owner is None:
        raise HTTPException(status_code=401, detail="API key owner not found")
    return owner


async def get_scan_user(
    token: str | None = Depends(optional_oauth2_scheme),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    if x_api_key:
        return await _resolve_api_key(x_api_key, db)
    if token:
        return await _resolve_access_token(token, db)
    return None
