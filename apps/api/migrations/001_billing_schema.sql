-- Phase 2: Core billing tables (prod-safe)
-- idempotent; safe to run multiple times

PRAGMA foreign_keys = ON;

-- Plans: define available product tiers
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY,           -- e.g., free, pro, team, enterprise
  name TEXT NOT NULL,
  stripe_price_id TEXT,          -- optional; set in prod
  monthly_event_limit INTEGER,   -- NULL means unlimited
  features_json TEXT,            -- JSON string of feature flags/caps
  active INTEGER NOT NULL DEFAULT 1
);

-- Orgs: tenant container for sites and seats
CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY,                  -- UUID
  name TEXT,
  owner_sub TEXT,                       -- Clerk user sub
  owner_email TEXT,
  plan_id TEXT REFERENCES plans(id),
  stripe_customer_id TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orgs_owner_sub ON orgs(owner_sub);
CREATE INDEX IF NOT EXISTS idx_orgs_owner_email ON orgs(owner_email);

-- Entitlements: calculated flags/caps attached to an org
CREATE TABLE IF NOT EXISTS org_entitlements (
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  value TEXT,
  PRIMARY KEY (org_id, key)
);
