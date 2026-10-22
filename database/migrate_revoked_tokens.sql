-- Migration: server-side logout (token revocation)
-- Run this ONCE in the Supabase SQL Editor on databases created before this table existed.
-- Rows can be deleted once expires_at has passed; expired tokens are rejected anyway.

CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti TEXT PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;

-- Optional housekeeping:
-- DELETE FROM revoked_tokens WHERE expires_at < NOW();
