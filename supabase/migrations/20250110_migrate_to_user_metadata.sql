-- Migration: Remove dependency on public.profiles table
-- This migration removes the profiles table and relies on Supabase Auth's
-- raw_user_meta_data (exposed as user_metadata in Python client)

-- Step 1: Update sessions table to remove snowflake_id foreign key
-- First, drop the foreign key constraint if it exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'sessions_snowflake_id_fkey'
    ) THEN
        ALTER TABLE public.sessions
        DROP CONSTRAINT sessions_snowflake_id_fkey;
    END IF;
END $$;

-- Step 2: Add snowflake_id column to sessions (not a foreign key)
-- This column will store the snowflake_id directly without foreign key constraint
ALTER TABLE public.sessions
ADD COLUMN IF NOT EXISTS snowflake_id BIGINT;

-- Step 3: Migrate snowflake_id from profiles to sessions
UPDATE public.sessions s
SET snowflake_id = p.snowflake_id
FROM public.profiles p
WHERE s.user_id = p.id
AND s.snowflake_id IS NULL;

-- Step 4: Update password_history table to remove snowflake_id foreign key
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'password_history_snowflake_id_fkey'
    ) THEN
        ALTER TABLE public.password_history
        DROP CONSTRAINT password_history_snowflake_id_fkey;
    END IF;
END $$;

-- Step 5: Add snowflake_id column to password_history
ALTER TABLE public.password_history
ADD COLUMN IF NOT EXISTS snowflake_id BIGINT;

-- Step 6: Migrate snowflake_id from profiles to password_history
UPDATE public.password_history ph
SET snowflake_id = p.snowflake_id
FROM public.profiles p
WHERE ph.user_id = p.id
AND ph.snowflake_id IS NULL;

-- Step 7: Drop the profiles table and all its dependencies
-- The profiles table is no longer needed as all data will be stored in
-- auth.users.raw_user_meta_data (exposed as user_metadata in Python client)
DROP TABLE IF EXISTS public.profiles CASCADE;

-- Migration complete
-- The public.profiles table has been removed
-- Sessions and password_history tables now store snowflake_id directly
-- User data is stored in auth.users.raw_user_meta_data
