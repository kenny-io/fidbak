-- Fix: seed Team plan using stripe_price_id column and normalize Enterprise to unlimited
PRAGMA foreign_keys = ON;

-- Insert Team plan if missing (use stripe_price_id column)
INSERT INTO plans (id, name, monthly_event_limit, stripe_price_id, features_json)
SELECT 'team', 'Team', 50000, NULL, '{"sites":20,"storage":"50GB","seats":5}'
WHERE NOT EXISTS (SELECT 1 FROM plans WHERE id = 'team');

-- Set Enterprise to unlimited monthly_event_limit
UPDATE plans
SET monthly_event_limit = NULL
WHERE id = 'enterprise';

-- Set Enterprise features to Unlimited (overwrite for clarity)
UPDATE plans
SET features_json = '{"sites":"Unlimited","storage":"Unlimited","seats":"Unlimited"}'
WHERE id = 'enterprise';
