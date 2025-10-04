-- Org members (seats) table and indexes (idempotent-ish)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS org_members (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_sub TEXT,
  email TEXT,
  role TEXT NOT NULL DEFAULT 'member', -- owner|admin|member
  status TEXT NOT NULL DEFAULT 'pending', -- pending|active|removed
  invited_at TEXT NOT NULL,
  joined_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_members_org_user ON org_members(org_id, user_sub);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_members_org_email ON org_members(org_id, lower(email));
CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_id);
