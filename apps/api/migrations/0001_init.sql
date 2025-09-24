-- D1 initial schema for Fidbak
-- sites: id (TEXT PK), name, hmac_secret, cors_json, created_at
CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  hmac_secret TEXT,
  cors_json TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- feedback: rows submitted from widget
CREATE TABLE IF NOT EXISTS feedback (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  page_id TEXT NOT NULL,
  rating TEXT NOT NULL CHECK (rating IN ('up','down')),
  comment TEXT,
  email TEXT,
  context_json TEXT,
  ip_hash TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_site_created ON feedback(site_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_site_page ON feedback(site_id, page_id);

-- destinations: fanout targets per site (Slack or generic HTTP)
CREATE TABLE IF NOT EXISTS destinations (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('slack_webhook','http_webhook')),
  config_json TEXT NOT NULL
);

