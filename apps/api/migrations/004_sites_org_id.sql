-- Add org association to sites and backfill (idempotent)
PRAGMA foreign_keys = ON;

ALTER TABLE sites ADD COLUMN org_id TEXT; -- references orgs(id)
CREATE INDEX IF NOT EXISTS idx_sites_org_id ON sites(org_id);

-- Backfill by owner_sub first
UPDATE sites SET org_id = (
  SELECT id FROM orgs WHERE orgs.owner_sub = sites.owner_user_id LIMIT 1
) WHERE org_id IS NULL;

-- Backfill by owner_email if still null
UPDATE sites SET org_id = (
  SELECT id FROM orgs WHERE lower(orgs.owner_email) = lower(sites.owner_email) LIMIT 1
) WHERE org_id IS NULL;
