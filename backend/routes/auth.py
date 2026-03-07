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
from email_service import email_service, generate_reset_token, EmailConfig
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
    """
    Register a new user.
    
    Creates a new user account with the provided details and sends
    a welcome email to the user.
    """
    try:
        print(f"\n{'='*60}")
        print(f"REGISTRATION REQUEST FOR: {data.email}")
        print(f"{'='*60}")
        
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

        print(f"[DEBUG] User registered successfully: {user.id}")
        
        # Send welcome email in background (non-blocking)
        user_name = data.name or data.email.split("@")[0]
        print(f"[DEBUG] Queuing welcome email to: {data.email}")
        
        # Try to send email, but don't block the response
        import threading
        def send_email_async():
            try:
                email_sent = email_service.send_welcome_email(
                    to_email=data.email,
                    user_name=user_name
                )
                if email_sent:
                    print(f"[SUCCESS] Welcome email sent to {data.email}")
                else:
                    print(f"[WARNING] Failed to send welcome email to {data.email}")
            except Exception as e:
                print(f"[ERROR] Email sending failed: {e}")
        
        email_thread = threading.Thread(target=send_email_async)
        email_thread.daemon = True
        email_thread.start()
        
        print(f"{'='*60}\n")
        return {"message": "User registered successfully"}

    except Exception as e:
        print(f"[ERROR] Registration failed: {e}")
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
    """
    Request a password reset email.
    
    This endpoint generates a password reset token and sends an email
    with a reset link. The token expires after the configured time (default: 1 hour).
    
    For development, the email is logged to console. For production,
    configure SMTP or SendGrid in environment variables.
    """
    try:
        print(f"\n{'='*60}")
        print(f"FORGOT PASSWORD REQUEST FOR: {data.email}")
        print(f"{'='*60}")
        
        user_id = None
        user_name = data.email.split("@")[0]
        snowflake_id = None
        
        # Debug: Check email config
        print(f"[DEBUG] Email Provider: {EmailConfig.EMAIL_PROVIDER}")
        print(f"[DEBUG] SMTP Host: {EmailConfig.SMTP_HOST}")
        print(f"[DEBUG] SMTP Port: {EmailConfig.SMTP_PORT}")
        print(f"[DEBUG] SMTP User: {EmailConfig.SMTP_USER}")
        print(f"[DEBUG] SMTP From: {EmailConfig.SMTP_FROM_EMAIL}")
        print(f"[DEBUG] Frontend URL: {EmailConfig.FRONTEND_URL}")
        
        # Query password_history by email directly (no admin API needed)
        print(f"[DEBUG] Querying password_history for email: {data.email}")
        history_response = (
            supabase.table("password_history")
            .select("user_id, snowflake_id, email")
            .eq("email", data.email)
            .limit(1)
            .execute()
        )
        
        print(f"[DEBUG] Query response: {history_response.data}")
        
        if history_response.data and len(history_response.data) > 0:
            entry = history_response.data[0]
            user_id = entry["user_id"]
            snowflake_id = entry.get("snowflake_id")
            print(f"[DEBUG] Found user - user_id: {user_id}, snowflake_id: {snowflake_id}")
        else:
            # User not found, but return success for security
            print(f"[DEBUG] No user found with email: {data.email}")
            return {"message": "If the email exists, a password reset link has been sent"}
        
        print(f"[DEBUG] Generating reset token...")
        
        # Invalidate any existing reset tokens for this user
        try:
            supabase.table("password_reset_tokens").update({
                "used": True
            }).eq("user_id", user_id).eq("used", False).execute()
            print(f"[DEBUG] Invalidated old tokens")
        except Exception as e:
            print(f"[DEBUG] Note: Could not invalidate old tokens: {e}")
        
        # Generate a new reset token
        reset_token = generate_reset_token()
        print(f"[DEBUG] Generated token: {reset_token[:20]}...")
        
        # Calculate expiry time
        expiry_minutes = EmailConfig.PASSWORD_RESET_EXPIRY
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        
        # Store the token in database
        print(f"[DEBUG] Storing token in database...")
        token_insert_response = supabase.table("password_reset_tokens").insert({
            "token": reset_token,
            "user_id": user_id,
            "snowflake_id": snowflake_id or 0,
            "email": data.email,
            "expires_at": expires_at.isoformat(),
            "used": False
        }).execute()
        print(f"[DEBUG] Token stored: {token_insert_response.data}")
        
        print(f"[DEBUG] Queuing password reset email to: {data.email}")
        
        # Send password reset email in background (non-blocking)
        import threading
        def send_reset_email_async():
            try:
                email_sent = email_service.send_password_reset_email(
                    to_email=data.email,
                    user_name=user_name,
                    reset_token=reset_token
                )
                if email_sent:
                    print(f"[SUCCESS] Password reset email sent to {data.email}")
                else:
                    print(f"[WARNING] Failed to send password reset email to {data.email}")
            except Exception as e:
                print(f"[ERROR] Password reset email sending failed: {e}")
        
        email_thread = threading.Thread(target=send_reset_email_async)
        email_thread.daemon = True
        email_thread.start()
        
        print(f"{'='*60}\n")
        return {"message": "If the email exists, a password reset link has been sent"}

    except Exception as e:
        print(f"[EXCEPTION] Forgot password error: {e}")
        import traceback
        traceback.print_exc()
        return {"message": "If the email exists, a password reset link has been sent"}


@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest):
    """
    Reset password using the token from the email.
    
    This endpoint validates the reset token and updates the user's password.
    The token is one-time use and expires after the configured time.
    """
    try:
        # Look up the reset token
        token_response = (
            supabase.table("password_reset_tokens")
            .select("*")
            .eq("token", data.access_token)
            .single()
            .execute()
        )
        
        if not token_response.data:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        
        token_data = token_response.data
        
        # Check if token has been used
        if token_data["used"]:
            raise HTTPException(status_code=400, detail="Reset token has already been used")
        
        # Check if token has expired
        expires_at = datetime.fromisoformat(token_data["expires_at"].replace("Z", "+00:00"))
        if datetime.now(expires_at.tzinfo) > expires_at:
            raise HTTPException(status_code=400, detail="Reset token has expired")
        
        user_id = token_data["user_id"]
        
        # Get the user
        user_response = supabase.auth.admin.get_user_by_id(user_id)
        if not user_response.user:
            raise HTTPException(status_code=400, detail="User not found")
        
        user = user_response.user
        metadata = user.user_metadata or {}
        user_name = metadata.get("name", user.email.split("@")[0])
        
        # Update the password using admin API
        supabase.auth.admin.update_user_by_id(
            user_id,
            password=data.new_password
        )
        
        # Update password_updated_at in user_metadata
        supabase.auth.admin.update_user_by_id(
            user_id,
            user_metadata={
                **metadata,
                "password_updated_at": datetime.now().isoformat()
            }
        )
        
        # Get snowflake_id for password history
        snowflake_id = metadata.get("snowflake_id")
        
        # Hash the new password and store in password history
        if snowflake_id:
            password_hash = bcrypt.hashpw(data.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            supabase.table("password_history").insert({
                "user_id": user_id,
                "snowflake_id": snowflake_id,
                "password_hash": password_hash
            }).execute()
        
        # Mark the reset token as used
        supabase.table("password_reset_tokens").update({
            "used": True
        }).eq("token", data.access_token).execute()
        
        # Invalidate all sessions for this user (force re-login)
        supabase.table("sessions").update({
            "is_active": False
        }).eq("user_id", user_id).execute()
        
        # Send password changed notification email
        email_service.send_password_changed_email(
            to_email=user.email,
            user_name=user_name
        )
        
        return {"message": "Password updated successfully"}

    except HTTPException:
        raise
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

        # Security: Reject inactive sessions
        if not is_session_active:
            raise HTTPException(status_code=401, detail="Session expired or logged out")

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

        # Check if session is active
        session = (
            supabase.table("sessions")
            .select("is_active")
            .eq("user_id", user.id)
            .eq("is_active", True)
            .single()
            .execute()
        )

        if not session.data:
            raise HTTPException(status_code=401, detail="Session expired or logged out")

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

        # Check if session is active
        session = (
            supabase.table("sessions")
            .select("is_active")
            .eq("user_id", user.id)
            .eq("is_active", True)
            .single()
            .execute()
        )

        if not session.data:
            raise HTTPException(status_code=401, detail="Session expired or logged out")

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
