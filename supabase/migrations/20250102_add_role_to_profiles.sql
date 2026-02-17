-- Migration: Add role column to profiles table
-- This migration adds a role column to support role-based access control (RBAC)

-- Add role column with default value 'user'
ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';

-- Add check constraint to ensure only valid roles are allowed
ALTER TABLE public.profiles
ADD CONSTRAINT profiles_role_check 
CHECK (role IN ('user', 'admin', 'super-admin'));

-- Add comment for documentation
COMMENT ON COLUMN public.profiles.role IS 'User role: user, admin, or super-admin';
