-- Add subscription state fields to orgs (idempotent)
PRAGMA foreign_keys = ON;

-- Idempotent column adds (D1/SQLite supports IF NOT EXISTS on ADD COLUMN)
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS subscription_status TEXT; -- trialing|active|past_due|unpaid|canceled|incomplete|incomplete_expired|paused
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS current_period_end TEXT; -- ISO timestamp
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS cancel_at TEXT; -- ISO timestamp
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS trial_end TEXT; -- ISO timestamp
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS price_id TEXT; -- last active Stripe price id
