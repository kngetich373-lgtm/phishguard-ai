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
    mfa_code: str | None = Field(default=None, pattern=r"^\d{6}$")


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
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=512)


class EmailRequest(BaseModel):
    email: EmailStr


class OneTimeTokenRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)
    new_password: str | None = Field(default=None, min_length=12, max_length=256)


class MessageResponse(BaseModel):
    message: str


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaCodeRequest(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


# ---------- Scanning ----------
class URLScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


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
    normalized_url: str | None = None
    risk_category: str | None = None
    confidence: str | None = None
    confidence_score: float | None = None
    confidence_interpretation: str | None = None
    ml_prediction: str | None = None
    ml_probability: float | None = None
    ml_model: str | None = None
    ml_model_version: str | None = None
    operating_mode: str | None = None
    network_status: str | None = None
    degraded: bool = False
    scan_duration_ms: int | None = None
    unavailable_signals: list[str] = Field(default_factory=list)

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
