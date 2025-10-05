-- NO-OP: invite columns already exist in production. Preserve index creation idempotently.
PRAGMA foreign_keys = ON;

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_members_invite_token ON org_members(invite_token);
CREATE INDEX IF NOT EXISTS idx_org_members_email_status ON org_members(lower(email), status);
