-- Per-site webhooks table
CREATE TABLE IF NOT EXISTS site_webhooks (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_site_webhooks_site_id ON site_webhooks(site_id);

-- Migration number: 0004 	 2025-09-28T14:10:44.414Z
