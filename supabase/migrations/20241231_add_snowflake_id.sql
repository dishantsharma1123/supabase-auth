-- Migration: Add snowflake_id column to profiles table
-- This migration adds a snowflake_id column for generating unique, sortable IDs

-- Add snowflake_id column (BIGINT to support 64-bit Snowflake IDs)
ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS snowflake_id BIGINT;

-- Add a unique constraint on snowflake_id to ensure uniqueness
ALTER TABLE public.profiles
ADD CONSTRAINT profiles_snowflake_id_key UNIQUE (snowflake_id);

-- Add a comment for documentation
COMMENT ON COLUMN public.profiles.snowflake_id IS 'Snowflake ID - a unique, time-based ID for the user (64-bit)';
