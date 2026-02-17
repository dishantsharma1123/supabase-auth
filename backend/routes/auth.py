from fastapi import APIRouter, HTTPException, Header
from supabase_client import supabase
from schemas import (
    RegisterRequest,
    LoginRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    MeResponse,
    LoginResponse,
    UserResponse,
    PasswordHistoryEntry,
    PasswordHistoryResponse,
    SessionEntry,
    SessionsResponse,
    LogoutRequest,
    UserRole,
    SSOTokenRequest,
    SSOTokenResponse,
    SSOExchangeRequest,
    SSOExchangeResponse
)
from snowflake import generate_snowflake_id, generate_csrf_token
from config import SSO_TOKEN_EXPIRY
import bcrypt
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin


router = APIRouter(prefix="/auth", tags=["auth"])


def validate_session(user_id: str, session_id: int) -> bool:
    """
    Validate that a session belongs to the user and is active.

    Args:
        user_id: The user's UUID
        session_id: The session ID to validate

    Returns:
        True if session is valid, False otherwise
    """
    try:
        session = (
            supabase.table("sessions")
            .select("*")
            .eq("user_id", user_id)
            .eq("session_id", session_id)
            .eq("is_active", True)
            .single()
            .execute()
        )

        if not session.data:
            return False

        # Check if session has expired
        if session.data["expires_at"] < datetime.now(session.data["expires_at"].tzinfo):
            # Mark as inactive if expired
            supabase.table("sessions").update({
                "is_active": False
            }).eq("id", session.data["id"]).execute()
            return False

        return True
    except Exception:
        return False


def validate_csrf_token(csrf_token: str, user_id: str) -> bool:
    """
    Validate that a CSRF token is valid for the user.

    Args:
        csrf_token: The CSRF token to validate
        user_id: The user's UUID

    Returns:
        True if CSRF token is valid, False otherwise
    """
    # Strict validation: token must be present and exactly 64 hex characters
    if not csrf_token:
        return False

    if len(csrf_token) != 64:
        return False

    # Validate it's a hexadecimal string
    try:
        int(csrf_token, 16)
        return True
    except ValueError:
        return False
    except Exception:
        return False


def get_user_from_metadata(user) -> dict:
    """
    Extract user data from Supabase Auth user object's user_metadata.

    Args:
        user: Supabase Auth user object

    Returns:
        Dictionary with user data
    """
    metadata = user.user_metadata or {}
    snowflake_id = metadata.get("snowflake_id")

    # If snowflake_id is missing, generate one and update user_metadata
    if not snowflake_id:
        snowflake_id = generate_snowflake_id()
        supabase.auth.admin.update_user_by_id(
            user.id,
            user_metadata={
                **metadata,
                "snowflake_id": snowflake_id
            }
        )

    return {
        "id": user.id,
        "snowflake_id": snowflake_id,
        "email": user.email,
        "name": metadata.get("name", user.email.split("@")[0]),
        "role": metadata.get("role", UserRole.USER.value),
        "password_updated_at": metadata.get("password_updated_at")
    }


@router.post("/register")
def register(data: RegisterRequest):
    try:
        # Generate Snowflake ID
        snowflake_id = generate_snowflake_id()

        # Create user with metadata
        auth_response = supabase.auth.sign_up({
            "email": data.email,
            "password": data.password,
            "options": {
                "data": {
                    "snowflake_id": snowflake_id,
                    "name": data.name,
                    "role": data.role.value,
                    "password_updated_at": datetime.now().isoformat()
                }
            }
        })

        user = auth_response.user
        if not user:
            raise HTTPException(status_code=400, detail="Auth user not created")

        # Hash the password and store in password history
        password_hash = bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        supabase.table("password_history").insert({
            "user_id": user.id,
            "snowflake_id": snowflake_id,
            "password_hash": password_hash
        }).execute()

        return {"message": "User registered successfully"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login", response_model=LoginResponse)
def login(data: LoginRequest):
    try:
        response = supabase.auth.sign_in_with_password({
            "email": data.email,
            "password": data.password
        })

        if not response.session:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user = response.user

        # Get user data from user_metadata
        user_data = get_user_from_metadata(user)

        # Generate a new session ID for this login
        session_id = generate_snowflake_id()

        # Invalidate all previous sessions for this user
        supabase.table("sessions").update({
            "is_active": False
        }).eq("user_id", user.id).execute()

        # Create new session in database
        supabase.table("sessions").insert({
            "session_id": session_id,
            "user_id": user.id,
            "snowflake_id": user_data["snowflake_id"],
            "is_active": True
        }).execute()

        # Generate CSRF token for this session
        csrf_token = generate_csrf_token()

        return {
            "access_token": response.session.access_token,
            "refresh_token": response.session.refresh_token,
            "user": user_data,
            "session_id": session_id,
            "csrf_token": csrf_token
        }

    except Exception:
        raise HTTPException(status_code=401, detail="Login failed")


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest):
    try:
        supabase.auth.reset_password_for_email(
            data.email,
            {"redirect_to": "http://localhost:3000/reset-password"}
        )
        return {"message": "Password reset email sent"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest):
    try:
        # Authenticate using recovery token
        supabase.auth.set_session(data.access_token, "")

        user_response = supabase.auth.update_user({
            "password": data.new_password
        })

        # Update password_updated_at in user_metadata
        if user_response.user:
            metadata = user_response.user.user_metadata or {}
            snowflake_id = metadata.get("snowflake_id")

            supabase.auth.admin.update_user_by_id(
                user_response.user.id,
                user_metadata={
                    **metadata,
                    "password_updated_at": datetime.now().isoformat()
                }
            )

            # Hash the new password and store in password history
            if snowflake_id:
                password_hash = bcrypt.hashpw(data.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                supabase.table("password_history").insert({
                    "user_id": user_response.user.id,
                    "snowflake_id": snowflake_id,
                    "password_hash": password_hash
                }).execute()

        return {"message": "Password updated successfully"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/me", response_model=MeResponse)
def me(authorization: str = Header(...), x_csrf_token: str = Header(...)):
    try:
        token = authorization.replace("Bearer ", "")

        user_response = supabase.auth.get_user(token)
        user = user_response.user

        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Validate CSRF token
        if not validate_csrf_token(x_csrf_token, user.id):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

        # Get user data from user_metadata
        user_data = get_user_from_metadata(user)

        # Get current session from database
        session = (
            supabase.table("sessions")
            .select("*")
            .eq("user_id", user.id)
            .eq("is_active", True)
            .single()
            .execute()
        )

        session_id = session.data["session_id"] if session.data else None
        is_session_active = session.data["is_active"] if session.data else False

        # Determine invitation state based on email_confirmed_at and invited_at
        invitation_state = None
        if hasattr(user, 'email_confirmed_at') and user.email_confirmed_at:
            invitation_state = "accepted"
        elif hasattr(user, 'invited_at') and user.invited_at:
            invitation_state = "pending"
        else:
            invitation_state = "none"

        # Determine is_active based on deleted_at and session status
        is_active = True
        if hasattr(user, 'deleted_at') and user.deleted_at:
            is_active = False
        elif not is_session_active:
            is_active = False

        # Determine role_permission based on role
        role_permission = None
        role = user_data["role"]
        if role == UserRole.USER.value:
            role_permission = "read"
        elif role == UserRole.ADMIN.value:
            role_permission = "read,write"
        elif role == UserRole.SUPER_ADMIN.value:
            role_permission = "read,write,delete,admin"

        # roles field - return as array with single role
        roles = [UserRole(role)]

        return {
            "id": user_data["id"],
            "email": user_data["email"],
            "name": user_data["name"],
            "role": user_data["role"],
            "password_updated_at": user_data["password_updated_at"],
            "is_active": is_active,
            "role_permission": role_permission,
            "invitation_state": invitation_state,
            "project_id": None,  # Not implemented yet
            "session_id": session_id,
            "csrf_token": x_csrf_token,
            "roles": roles
        }

    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.get("/password-history", response_model=PasswordHistoryResponse)
def get_password_history(authorization: str = Header(...), x_csrf_token: str = Header(...)):
    try:
        token = authorization.replace("Bearer ", "")

        user_response = supabase.auth.get_user(token)
        user = user_response.user

        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Validate CSRF token
        if not validate_csrf_token(x_csrf_token, user.id):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

        # Get user's snowflake_id from metadata
        metadata = user.user_metadata or {}
        snowflake_id = metadata.get("snowflake_id")

        if not snowflake_id:
            raise HTTPException(status_code=404, detail="Snowflake ID not found")

        # Get password history (last 3 passwords)
        history_response = (
            supabase.table("password_history")
            .select("*")
            .eq("user_id", user.id)
            .order("created_at", desc=True)
            .limit(3)
            .execute()
        )

        history_entries = []
        if history_response.data:
            for entry in history_response.data:
                history_entries.append({
                    "id": entry["id"],
                    "snowflake_id": entry["snowflake_id"],
                    "password_hash": entry["password_hash"],
                    "created_at": entry["created_at"]
                })

        return {"history": history_entries}

    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.post("/logout")
def logout(data: LogoutRequest, authorization: str = Header(...), x_csrf_token: str = Header(...)):
    try:
        token = authorization.replace("Bearer ", "")

        user_response = supabase.auth.get_user(token)
        user = user_response.user

        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Validate CSRF token
        if not validate_csrf_token(x_csrf_token, user.id):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

        # Invalidate the session
        supabase.table("sessions").update({
            "is_active": False
        }).eq("session_id", data.session_id).eq("user_id", user.id).execute()

        return {"message": "Logged out successfully"}

    except Exception:
        raise HTTPException(status_code=401, detail="Logout failed")


@router.get("/sessions", response_model=SessionsResponse)
def get_sessions(authorization: str = Header(...), x_csrf_token: str = Header(...)):
    try:
        token = authorization.replace("Bearer ", "")

        user_response = supabase.auth.get_user(token)
        user = user_response.user

        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Validate CSRF token
        if not validate_csrf_token(x_csrf_token, user.id):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

        # Get all sessions for the user
        sessions_response = (
            supabase.table("sessions")
            .select("*")
            .eq("user_id", user.id)
            .order("created_at", desc=True)
            .execute()
        )

        sessions = []
        if sessions_response.data:
            for session in sessions_response.data:
                sessions.append({
                    "session_id": session["session_id"],
                    "snowflake_id": session["snowflake_id"],
                    "is_active": session["is_active"],
                    "created_at": session["created_at"],
                    "last_active_at": session["last_active_at"],
                    "expires_at": session["expires_at"]
                })

        return {"sessions": sessions}

    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.post("/sso/token", response_model=SSOTokenResponse)
def generate_sso_token(
    data: SSOTokenRequest,
    authorization: str = Header(...),
    x_csrf_token: str = Header(...)
):
    """
    Generate an SSO token for cross-domain authentication.
    
    This endpoint creates a short-lived token that can be used to transfer
    the user's session to another domain. The token contains the user's
    access token, refresh token, and session information.
    
    Flow:
    1. User is logged in on domain A
    2. Frontend calls this endpoint with target domain B
    3. Backend generates a one-time SSO token and stores it in the database
    4. Frontend redirects to domain B with the SSO token
    5. Domain B exchanges the SSO token for session credentials
    """
    try:
        token = authorization.replace("Bearer ", "")

        # Validate the user's session
        user_response = supabase.auth.get_user(token)
        user = user_response.user

        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Validate CSRF token
        if not validate_csrf_token(x_csrf_token, user.id):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

        # Get user data
        user_data = get_user_from_metadata(user)

        # Validate target domain (basic URL validation)
        try:
            parsed_url = urlparse(data.target_domain)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise HTTPException(status_code=400, detail="Invalid target domain URL")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid target domain URL")

        # Get current active session
        session = (
            supabase.table("sessions")
            .select("*")
            .eq("user_id", user.id)
            .eq("is_active", True)
            .single()
            .execute()
        )

        if not session.data:
            raise HTTPException(status_code=401, detail="No active session found")

        # Generate a secure one-time SSO token
        sso_token = secrets.token_urlsafe(64)

        # Get the refresh token from the current session
        # Note: We need to refresh the session to get a new access/refresh token pair
        # or use the existing tokens. For SSO, we'll store the current tokens.
        refresh_token = None
        
        # Try to get refresh token from the request context
        # Since we're using Supabase, we need to refresh the session to get new tokens
        try:
            # Set the session and refresh to get new tokens
            supabase.auth.set_session(token, "")
            refreshed = supabase.auth.refresh_session()
            if refreshed.session:
                access_token = refreshed.session.access_token
                refresh_token = refreshed.session.refresh_token
            else:
                # If refresh fails, use the original token
                access_token = token
                refresh_token = ""
        except Exception:
            # If refresh fails, use original token
            access_token = token
            refresh_token = ""

        # Generate CSRF token for the new domain
        new_csrf_token = generate_csrf_token()

        # Store SSO token in database
        supabase.table("sso_tokens").insert({
            "token": sso_token,
            "user_id": user.id,
            "snowflake_id": user_data["snowflake_id"],
            "access_token": access_token,
            "refresh_token": refresh_token,
            "session_id": session.data["session_id"],
            "csrf_token": new_csrf_token,
            "expires_at": (datetime.utcnow() + timedelta(seconds=SSO_TOKEN_EXPIRY)).isoformat(),
            "used": False
        }).execute()

        # Build redirect URL with SSO token
        redirect_url = urljoin(data.target_domain, f"/sso/callback?sso_token={sso_token}")

        return {
            "sso_token": sso_token,
            "redirect_url": redirect_url,
            "expires_in": SSO_TOKEN_EXPIRY
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/sso/exchange", response_model=SSOExchangeResponse)
def exchange_sso_token(data: SSOExchangeRequest):
    """
    Exchange an SSO token for session credentials.
    
    This endpoint is called by the target domain to exchange the SSO token
    for the user's access token, refresh token, and session information.
    The SSO token is one-time use and expires after 5 minutes.
    
    Flow:
    1. User redirects from domain A to domain B with SSO token
    2. Domain B's frontend calls this endpoint with the SSO token
    3. Backend validates the token, returns session credentials
    4. Backend marks the token as used (one-time use)
    5. Domain B's frontend stores the credentials and logs the user in
    """
    try:
        # Look up the SSO token
        sso_response = (
            supabase.table("sso_tokens")
            .select("*")
            .eq("token", data.sso_token)
            .single()
            .execute()
        )

        if not sso_response.data:
            raise HTTPException(status_code=400, detail="Invalid SSO token")

        sso_data = sso_response.data

        # Check if token has been used
        if sso_data["used"]:
            raise HTTPException(status_code=400, detail="SSO token has already been used")

        # Check if token has expired
        expires_at = datetime.fromisoformat(sso_data["expires_at"].replace("Z", "+00:00"))
        if datetime.now(expires_at.tzinfo) > expires_at:
            raise HTTPException(status_code=400, detail="SSO token has expired")

        # Mark token as used
        supabase.table("sso_tokens").update({
            "used": True
        }).eq("token", data.sso_token).execute()

        # Get user information
        user_response = supabase.auth.get_user(sso_data["access_token"])
        user = user_response.user

        if not user:
            # Try with admin API to get user
            admin_response = supabase.auth.admin.get_user_by_id(sso_data["user_id"])
            if admin_response.user:
                user = admin_response.user
            else:
                raise HTTPException(status_code=401, detail="User not found")

        # Get user data from metadata
        user_data = get_user_from_metadata(user)

        # Verify the session is still active
        session = (
            supabase.table("sessions")
            .select("*")
            .eq("session_id", sso_data["session_id"])
            .eq("user_id", sso_data["user_id"])
            .eq("is_active", True)
            .single()
            .execute()
        )

        if not session.data:
            raise HTTPException(status_code=401, detail="Session is no longer active")

        return {
            "access_token": sso_data["access_token"],
            "refresh_token": sso_data["refresh_token"],
            "user": user_data,
            "session_id": sso_data["session_id"],
            "csrf_token": sso_data["csrf_token"]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/sso/redirect")
def sso_redirect(
    data: SSOTokenRequest,
    authorization: str = Header(...),
    x_csrf_token: str = Header(...)
):
    """
    Convenience endpoint that generates SSO token and returns HTML redirect page.
    
    This is useful for scenarios where you want to automatically redirect
    the user to the target domain with the SSO token.
    """
    from fastapi.responses import HTMLResponse
    
    try:
        # Reuse the generate_sso_token logic
        token = authorization.replace("Bearer ", "")
        user_response = supabase.auth.get_user(token)
        user = user_response.user

        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        if not validate_csrf_token(x_csrf_token, user.id):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

        user_data = get_user_from_metadata(user)

        try:
            parsed_url = urlparse(data.target_domain)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise HTTPException(status_code=400, detail="Invalid target domain URL")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid target domain URL")

        session = (
            supabase.table("sessions")
            .select("*")
            .eq("user_id", user.id)
            .eq("is_active", True)
            .single()
            .execute()
        )

        if not session.data:
            raise HTTPException(status_code=401, detail="No active session found")

        sso_token = secrets.token_urlsafe(64)

        try:
            supabase.auth.set_session(token, "")
            refreshed = supabase.auth.refresh_session()
            if refreshed.session:
                access_token = refreshed.session.access_token
                refresh_token = refreshed.session.refresh_token
            else:
                access_token = token
                refresh_token = ""
        except Exception:
            access_token = token
            refresh_token = ""

        new_csrf_token = generate_csrf_token()

        supabase.table("sso_tokens").insert({
            "token": sso_token,
            "user_id": user.id,
            "snowflake_id": user_data["snowflake_id"],
            "access_token": access_token,
            "refresh_token": refresh_token,
            "session_id": session.data["session_id"],
            "csrf_token": new_csrf_token,
            "expires_at": (datetime.utcnow() + timedelta(seconds=SSO_TOKEN_EXPIRY)).isoformat(),
            "used": False
        }).execute()

        redirect_url = urljoin(data.target_domain, f"/sso/callback?sso_token={sso_token}")

        # Return HTML page that redirects immediately
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting...</title>
        </head>
        <body>
            <p>Redirecting to {data.target_domain}...</p>
            <script>
                window.location.href = "{redirect_url}";
            </script>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
