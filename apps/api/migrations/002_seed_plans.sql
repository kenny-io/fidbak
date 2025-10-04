-- Seed default plans (safe/idempotent)
INSERT OR IGNORE INTO plans (id, name, stripe_price_id, monthly_event_limit, features_json, active)
VALUES
  ('free', 'Free', NULL, 1000, '{"seats":1,"sites":1,"webhooks":0,"retention_days":30}', 1),
  ('pro', 'Pro', NULL, 10000, '{"seats":3,"sites":5,"webhooks":2,"retention_days":365}', 1),
  ('team', 'Team', NULL, 50000, '{"seats":10,"sites":20,"webhooks":5,"retention_days":1095}', 1),
  ('enterprise', 'Enterprise', NULL, NULL, '{"seats":"custom","sites":"custom","webhooks":"custom","retention_days":"custom"}', 1);
