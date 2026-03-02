import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env from parent directory
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(env_path)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8756"))

# SSO Configuration
# Comma-separated list of allowed origins for CORS (for cross-domain SSO)
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", FRONTEND_ORIGIN).split(",")
# Always include the primary frontend origin
if FRONTEND_ORIGIN not in ALLOWED_ORIGINS:
    ALLOWED_ORIGINS.insert(0, FRONTEND_ORIGIN)

# SSO Token expiration in seconds (default: 5 minutes)
SSO_TOKEN_EXPIRY = int(os.getenv("SSO_TOKEN_EXPIRY", "300"))

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Supabase environment variables not set")
