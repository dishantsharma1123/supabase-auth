-- Migration: Create password reset tokens table
-- This migration creates a table to store password reset tokens for custom email handling

-- Create password_reset_tokens table
CREATE TABLE IF NOT EXISTS public.password_reset_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(64) NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    snowflake_id BIGINT NOT NULL,
    email TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '1 hour',
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.password_reset_tokens ENABLE ROW LEVEL SECURITY;

-- Create policy to allow service role full access (drop if exists first)
DROP POLICY IF EXISTS "Service role full access on password_reset_tokens" ON public.password_reset_tokens;
CREATE POLICY "Service role full access on password_reset_tokens"
    ON public.password_reset_tokens FOR ALL
    USING (true);

-- Create index on token for faster lookups
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON public.password_reset_tokens(token);

-- Create index on user_id for user lookups
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON public.password_reset_tokens(user_id);

-- Create index on email for email lookups
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_email ON public.password_reset_tokens(email);

-- Create index on expires_at for cleanup
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON public.password_reset_tokens(expires_at);

-- Create index on used for filtering unused tokens
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_used ON public.password_reset_tokens(used);

-- Add comments for documentation
COMMENT ON TABLE public.password_reset_tokens IS 'Stores password reset tokens for custom email handling';
COMMENT ON COLUMN public.password_reset_tokens.id IS 'Auto-incrementing ID';
COMMENT ON COLUMN public.password_reset_tokens.token IS 'Unique password reset token';
COMMENT ON COLUMN public.password_reset_tokens.user_id IS 'Reference to auth.users.id';
COMMENT ON COLUMN public.password_reset_tokens.snowflake_id IS 'Reference to profiles.snowflake_id';
COMMENT ON COLUMN public.password_reset_tokens.email IS 'Email address the token was sent to';
COMMENT ON COLUMN public.password_reset_tokens.expires_at IS 'Token expiration time';
COMMENT ON COLUMN public.password_reset_tokens.used IS 'Whether token has been used';
COMMENT ON COLUMN public.password_reset_tokens.created_at IS 'Token creation timestamp';