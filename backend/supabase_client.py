from supabase import create_client
from config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

# Service role client – full access, backend only
supabase = create_client(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY
)

print("SUPABASE KEY PREFIX:", SUPABASE_SERVICE_ROLE_KEY[:15])

