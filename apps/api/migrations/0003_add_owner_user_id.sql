-- NO-OP for column add: owner_user_id already exists in production
-- Keep index creation for idempotency
CREATE INDEX IF NOT EXISTS idx_sites_owner_user_id ON sites(owner_user_id);

-- Migration number: 0003 	 2025-09-28T13:42:54.421Z
