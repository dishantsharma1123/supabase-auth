-- Migration: Create sessions table
-- This migration creates a table to track user sessions with unique session IDs

-- Create sessions table
CREATE TABLE IF NOT EXISTS public.sessions (
    id BIGSERIAL PRIMARY KEY,
    session_id BIGINT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    snowflake_id BIGINT NOT NULL REFERENCES public.profiles(snowflake_id) ON DELETE CASCADE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '1 hour'
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.sessions ENABLE ROW LEVEL SECURITY;

-- Create policy to allow users to view their own sessions
CREATE POLICY "Users can view own sessions"
    ON public.sessions FOR SELECT
    USING (auth.uid() = user_id);

-- Create policy to allow service role to insert sessions
CREATE POLICY "Service role can insert sessions"
    ON public.sessions FOR INSERT
    WITH CHECK (true);

-- Create policy to allow service role to update sessions
CREATE POLICY "Service role can update sessions"
    ON public.sessions FOR UPDATE
    USING (true);

-- Create policy to allow service role to delete sessions
CREATE POLICY "Service role can delete sessions"
    ON public.sessions FOR DELETE
    USING (true);

-- Create index on user_id for faster queries
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON public.sessions(user_id);

-- Create index on session_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON public.sessions(session_id);

-- Create index on is_active for filtering active sessions
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON public.sessions(is_active);

-- Create index on expires_at for cleanup
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON public.sessions(expires_at);

-- Add comments for documentation
COMMENT ON TABLE public.sessions IS 'Tracks user sessions with unique Snowflake-based session IDs';
COMMENT ON COLUMN public.sessions.id IS 'Auto-incrementing ID for the session record';
COMMENT ON COLUMN public.sessions.session_id IS 'Unique Snowflake-based session identifier';
COMMENT ON COLUMN public.sessions.user_id IS 'Reference to auth.users.id';
COMMENT ON COLUMN public.sessions.snowflake_id IS 'Reference to profiles.snowflake_id';
COMMENT ON COLUMN public.sessions.is_active IS 'Session status (true = active, false = logged out)';
COMMENT ON COLUMN public.sessions.created_at IS 'Timestamp when session was created';
COMMENT ON COLUMN public.sessions.last_active_at IS 'Timestamp of last activity in this session';
COMMENT ON COLUMN public.sessions.expires_at IS 'Timestamp when session expires (default 1 hour)';
