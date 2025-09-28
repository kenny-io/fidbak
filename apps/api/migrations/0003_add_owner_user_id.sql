-- Add Clerk user ID column (owner_user_id) and index for sites table
-- Safe to run multiple times: index creation is IF NOT EXISTS; column add will error if already exists

ALTER TABLE sites ADD COLUMN owner_user_id TEXT;

CREATE INDEX IF NOT EXISTS idx_sites_owner_user_id ON sites(owner_user_id);

-- Migration number: 0003 	 2025-09-28T13:42:54.421Z
