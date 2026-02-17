from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SUPER_ADMIN = "super-admin"


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1)
    email: EmailStr
    password: str = Field(min_length=6)
    role: UserRole = Field(default=UserRole.USER)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    access_token: str
    new_password: str = Field(min_length=6)


class UserResponse(BaseModel):
    id: str
    snowflake_id: int
    email: EmailStr
    name: str
    role: UserRole
    password_updated_at: datetime | None = None


class MeResponse(BaseModel):
    id: str
    email: EmailStr
    name: str
    role: UserRole
    password_updated_at: datetime | None = None
    is_active: bool | None = None
    role_permission: str | None = None
    invitation_state: str | None = None
    project_id: str | None = None
    session_id: int | None = None
    csrf_token: str | None = None
    roles: list[UserRole] | None = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    user: UserResponse
    session_id: int
    csrf_token: str


class PasswordHistoryEntry(BaseModel):
    id: int
    snowflake_id: int
    password_hash: str
    created_at: datetime


class PasswordHistoryResponse(BaseModel):
    history: list[PasswordHistoryEntry]


class SessionEntry(BaseModel):
    session_id: int
    snowflake_id: int
    is_active: bool
    created_at: datetime
    last_active_at: datetime
    expires_at: datetime


class SessionsResponse(BaseModel):
    sessions: list[SessionEntry]


class LogoutRequest(BaseModel):
    session_id: int


class SSOTokenRequest(BaseModel):
    """Request to generate an SSO token for cross-domain authentication"""
    target_domain: str = Field(..., description="Target domain URL to redirect to")


class SSOTokenResponse(BaseModel):
    """Response containing SSO token and redirect URL"""
    sso_token: str
    redirect_url: str
    expires_in: int = 300  # 5 minutes in seconds


class SSOExchangeRequest(BaseModel):
    """Request to exchange SSO token for session credentials"""
    sso_token: str


class SSOExchangeResponse(BaseModel):
    """Response with session credentials after SSO token exchange"""
    access_token: str
    refresh_token: str
    user: UserResponse
    session_id: int
    csrf_token: str
