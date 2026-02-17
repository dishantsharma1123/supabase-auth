-- Migration: Create password_history table
-- This migration creates a table to track the last 3 passwords for each user

-- Create password_history table
CREATE TABLE IF NOT EXISTS public.password_history (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    snowflake_id BIGINT NOT NULL REFERENCES public.profiles(snowflake_id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.password_history ENABLE ROW LEVEL SECURITY;

-- Create policy to allow users to view their own password history
CREATE POLICY "Users can view own password history"
    ON public.password_history FOR SELECT
    USING (auth.uid() = user_id);

-- Create policy to allow service role to insert password history
CREATE POLICY "Service role can insert password history"
    ON public.password_history FOR INSERT
    WITH CHECK (true);

-- Create policy to allow service role to delete password history
CREATE POLICY "Service role can delete password history"
    ON public.password_history FOR DELETE
    USING (true);

-- Create index on user_id for faster queries
CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON public.password_history(user_id);

-- Create index on created_at for sorting
CREATE INDEX IF NOT EXISTS idx_password_history_created_at ON public.password_history(created_at DESC);

-- Add comments for documentation
COMMENT ON TABLE public.password_history IS 'Stores the last 3 passwords for each user with timestamps';
COMMENT ON COLUMN public.password_history.id IS 'Auto-incrementing ID for the password history record';
COMMENT ON COLUMN public.password_history.user_id IS 'Reference to auth.users.id';
COMMENT ON COLUMN public.password_history.snowflake_id IS 'Reference to profiles.snowflake_id';
COMMENT ON COLUMN public.password_history.password_hash IS 'Hashed password (for security, never store plain text)';
COMMENT ON COLUMN public.password_history.created_at IS 'Timestamp when this password was set';

-- Create function to keep only the last 3 passwords
CREATE OR REPLACE FUNCTION public.clean_old_passwords()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM public.password_history
    WHERE user_id = NEW.user_id
    AND id NOT IN (
        SELECT id FROM public.password_history
        WHERE user_id = NEW.user_id
        ORDER BY created_at DESC
        LIMIT 3
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically clean old passwords
DROP TRIGGER IF EXISTS clean_old_passwords_trigger ON public.password_history;
CREATE TRIGGER clean_old_passwords_trigger
    AFTER INSERT ON public.password_history
    FOR EACH ROW
    EXECUTE FUNCTION public.clean_old_passwords();
