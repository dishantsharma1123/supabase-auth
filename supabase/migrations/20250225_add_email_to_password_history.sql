-- Migration: Add email column to password_history table
-- This allows querying users by email without needing admin API access

-- Add email column if it doesn't exist
ALTER TABLE public.password_history 
ADD COLUMN IF NOT EXISTS email TEXT;

-- Create index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_password_history_email ON public.password_history(email);

-- Add comment for documentation
COMMENT ON COLUMN public.password_history.email IS 'User email address for password reset lookups';