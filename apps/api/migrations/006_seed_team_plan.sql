-- Seed 'team' plan if missing, and normalize enterprise to unlimited features
PRAGMA foreign_keys = ON;

-- Create plans table if it doesn't exist (idempotent-ish minimal)
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY,
  name TEXT,
  monthly_event_limit INTEGER,
  price_id TEXT,
  features_json TEXT
);

-- Insert Team plan if missing
INSERT INTO plans (id, name, monthly_event_limit, price_id, features_json)
SELECT 'team', 'Team', 50000, NULL, '{"sites":20,"storage":"50GB","seats":5}'
WHERE NOT EXISTS (SELECT 1 FROM plans WHERE id = 'team');

-- Normalize Enterprise to unlimited
UPDATE plans
SET monthly_event_limit = NULL,
    features_json = COALESCE(NULLIF(TRIM(features_json), ''), '{}')
WHERE id = 'enterprise';

-- Merge unlimited keys into enterprise features_json
-- Note: SQLite json_patch may not be available; do simple overwrite for keys.
-- Build a merged JSON by preferring existing fields and setting Unlimited defaults.
-- In D1/SQLite without JSON functions, simplest is overwrite explicitly.
UPDATE plans
SET features_json = '{"sites":"Unlimited","storage":"Unlimited","seats":"Unlimited"}'
WHERE id = 'enterprise';
