-- NO-OP for column add: sites.org_id already exists in production
PRAGMA foreign_keys = ON;

-- Keep index creation idempotent
CREATE INDEX IF NOT EXISTS idx_sites_org_id ON sites(org_id);

-- Skip backfill since org_id is already present
