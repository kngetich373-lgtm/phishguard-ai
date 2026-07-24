"""Pydantic request/response schemas."""
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


# ---------- Auth ----------
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = ""
    team_name: str | None = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    is_admin: bool
    team_id: str | None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


# ---------- Scanning ----------
class URLScanRequest(BaseModel):
    url: str


class SMSScanRequest(BaseModel):
    message: str
    sender: str | None = None


class EmailScanRequest(BaseModel):
    subject: str = ""
    body: str
    sender: str | None = None


class ScanResult(BaseModel):
    id: str
    scan_type: str
    input_value: str
    verdict: str
    risk_score: float
    reasons: list[str]
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Alerts ----------
class AlertOut(BaseModel):
    id: str
    title: str
    message: str
    severity: str
    created_at: datetime
    read: bool

    class Config:
        from_attributes = True


# ---------- Reports ----------
class ReportSummary(BaseModel):
    total_scans: int
    safe_count: int
    suspicious_count: int
    malicious_count: int
    scans_by_type: dict[str, int]
    recent_scans: list[ScanResult]


# ---------- API Keys ----------
class ApiKeyOut(BaseModel):
    id: str
    key: str
    label: str
    active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Team ----------
class TeamMemberOut(BaseModel):
    id: str
    email: str
    full_name: str
    is_admin: bool

    class Config:
        from_attributes = True


class TeamOut(BaseModel):
    id: str
    name: str
    members: list[TeamMemberOut]

    class Config:
        from_attributes = True
