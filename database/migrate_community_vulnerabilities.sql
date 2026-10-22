-- Migration: Community Vulnerability Mapping
-- Run ONCE in the Supabase SQL Editor on an existing SentriX database.
-- The vulnerability records themselves live in data/vulnerabilities.txt (no table).
-- Only per-scan match results are stored, plus the on/off check below.

CREATE TABLE IF NOT EXISTS device_vulnerability_matches (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  vulnerability_id TEXT NOT NULL,            -- record ID from the text file
  vulnerability_snapshot JSONB,              -- copy of the matched record at scan time
  match_type TEXT NOT NULL,
  match_confidence TEXT NOT NULL CHECK (match_confidence IN ('High', 'Medium', 'Low')),
  matched_fields JSONB DEFAULT '[]',
  matched_reason TEXT,
  risk_score_added INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dvm_device_id ON device_vulnerability_matches(device_id);
CREATE INDEX IF NOT EXISTS idx_dvm_scan_id ON device_vulnerability_matches(scan_id);

ALTER TABLE device_vulnerability_matches ENABLE ROW LEVEL SECURITY;

-- Enabled Vulnerability Check (configurable on the Settings page)
INSERT INTO vulnerability_checks (id, name, slug, description, severity, risk_score, recommendation, enabled) VALUES
  ('d0000001-0000-0000-0000-000000000016', 'Community Vulnerability Mapping', 'community-vulnerability-mapping',
   'Maps detected CCTV device details against the SentriX community-maintained vulnerability database.',
   'high', 0,
   'Review matched vulnerability records, update firmware, disable exposed services, and follow vendor security hardening guidance.', true)
ON CONFLICT (slug) DO NOTHING;
