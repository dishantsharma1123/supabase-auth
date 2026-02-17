-- Migration: Create SSO tokens table
-- This migration creates a table to store short-lived tokens for cross-domain SSO

-- Create sso_tokens table
-- Note: We use user_id as the primary reference and snowflake_id without FK constraint
-- to avoid dependency issues with profiles table
CREATE TABLE IF NOT EXISTS public.sso_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(128) NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    snowflake_id BIGINT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    session_id BIGINT NOT NULL,
    csrf_token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '5 minutes',
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.sso_tokens ENABLE ROW LEVEL SECURITY;

-- Create policy to allow service role full access
CREATE POLICY "Service role full access on sso_tokens"
    ON public.sso_tokens FOR ALL
    USING (true);

-- Create index on token for faster lookups
CREATE INDEX IF NOT EXISTS idx_sso_tokens_token ON public.sso_tokens(token);

-- Create index on user_id for user lookups
CREATE INDEX IF NOT EXISTS idx_sso_tokens_user_id ON public.sso_tokens(user_id);

-- Create index on expires_at for cleanup
CREATE INDEX IF NOT EXISTS idx_sso_tokens_expires_at ON public.sso_tokens(expires_at);

-- Create index on used for filtering unused tokens
CREATE INDEX IF NOT EXISTS idx_sso_tokens_used ON public.sso_tokens(used);

-- Add comments for documentation
COMMENT ON TABLE public.sso_tokens IS 'Stores short-lived tokens for cross-domain SSO exchange';
COMMENT ON COLUMN public.sso_tokens.id IS 'Auto-incrementing ID';
COMMENT ON COLUMN public.sso_tokens.token IS 'Unique SSO token (one-time use)';
COMMENT ON COLUMN public.sso_tokens.user_id IS 'Reference to auth.users.id';
COMMENT ON COLUMN public.sso_tokens.snowflake_id IS 'Reference to profiles.snowflake_id';
COMMENT ON COLUMN public.sso_tokens.access_token IS 'Supabase access token to transfer';
COMMENT ON COLUMN public.sso_tokens.refresh_token IS 'Supabase refresh token to transfer';
COMMENT ON COLUMN public.sso_tokens.session_id IS 'Session ID associated with this SSO token';
COMMENT ON COLUMN public.sso_tokens.csrf_token IS 'CSRF token for the session';
COMMENT ON COLUMN public.sso_tokens.expires_at IS 'Token expiration (default 5 minutes)';
COMMENT ON COLUMN public.sso_tokens.used IS 'Whether token has been used (one-time use)';
COMMENT ON COLUMN public.sso_tokens.created_at IS 'Token creation timestamp';