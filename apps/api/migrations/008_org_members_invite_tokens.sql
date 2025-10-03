PRAGMA foreign_keys = ON;

-- Add invite columns if they don't exist (SQLite/D1 is permissive for ALTER; ignore errors if already present)
ALTER TABLE org_members ADD COLUMN invite_token TEXT;
ALTER TABLE org_members ADD COLUMN invite_expires_at TEXT; -- ISO 8601
ALTER TABLE org_members ADD COLUMN invited_by TEXT; -- inviter user_sub

-- Helpful indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_members_invite_token ON org_members(invite_token);
CREATE INDEX IF NOT EXISTS idx_org_members_email_status ON org_members(lower(email), status);
