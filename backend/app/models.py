"""
ORM models for PhishGuard AI.

Tables:
  users          - accounts (individual + team members)
  teams          - organizations for the "For Business" dashboard
  api_keys       - issued keys for the public detection API
  scans          - unified log of every URL / SMS / email scan performed
  alerts         - real-time alert feed, pushed over websocket + stored here
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Enum, ForeignKey, Float, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class ScanType(str, enum.Enum):
    URL = "url"
    SMS = "sms"
    EMAIL = "email"


class Verdict(str, enum.Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Team(Base):
    __tablename__ = "teams"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    members: Mapped[list["User"]] = relationship(back_populates="team")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    full_name: Mapped[str] = mapped_column(String, default="")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    team_id: Mapped[str | None] = mapped_column(ForeignKey("teams.id"), nullable=True)
    team: Mapped["Team | None"] = relationship(back_populates="members")

    scans: Mapped[list["Scan"]] = relationship(back_populates="owner")
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="owner")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    key: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    label: Mapped[str] = mapped_column(String, default="Default key")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    owner: Mapped["User"] = relationship(back_populates="api_keys")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), nullable=False)
    input_value: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[Verdict] = mapped_column(Enum(Verdict), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0-100
    reasons_json: Mapped[str] = mapped_column(Text, default="[]")  # JSON list of strings
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    owner: Mapped["User | None"] = relationship(back_populates="scans")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    title: Mapped[str] = mapped_column(String, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Verdict] = mapped_column(Enum(Verdict), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    read: Mapped[bool] = mapped_column(Boolean, default=False)

    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
