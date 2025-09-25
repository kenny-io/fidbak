-- Extend 'sites' with owner/verification columns for self-serve onboarding
ALTER TABLE sites ADD COLUMN owner_email TEXT;
ALTER TABLE sites ADD COLUMN verify_token TEXT;
ALTER TABLE sites ADD COLUMN verified_at TEXT;
