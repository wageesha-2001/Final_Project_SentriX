-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'technician' CHECK (role IN ('admin', 'technician')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  scan_name TEXT NOT NULL,
  network_range TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'stopped', 'failed')),
  total_devices INT DEFAULT 0,
  vulnerable_devices INT DEFAULT 0,
  critical_devices INT DEFAULT 0,
  overall_risk TEXT DEFAULT 'secure' CHECK (overall_risk IN ('secure', 'low', 'medium', 'high', 'critical')),
  started_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  progress INT DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
  scan_mode TEXT CHECK (scan_mode IN ('real', 'simulated'))
);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  ip_address TEXT NOT NULL,
  mac_address TEXT,
  vendor TEXT DEFAULT 'Unknown',
  model TEXT DEFAULT 'Unknown',
  firmware_version TEXT DEFAULT 'Unknown',
  device_type TEXT DEFAULT 'unknown' CHECK (device_type IN ('camera', 'nvr', 'dvr', 'router', 'unknown')),
  open_ports JSONB DEFAULT '[]',
  protocols JSONB DEFAULT '[]',
  risk_score INT DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
  risk_level TEXT DEFAULT 'secure' CHECK (risk_level IN ('secure', 'low', 'medium', 'high', 'critical')),
  status TEXT DEFAULT 'active',
  -- Separated per-device assessment statuses (computed at scan time)
  known_vulnerability_status TEXT CHECK (known_vulnerability_status IN ('MATCHED', 'NO_MATCH', 'UNVERIFIED')),
  authentication_status TEXT CHECK (authentication_status IN ('CONFIRMED_DEFAULT_CREDENTIALS', 'CONFIRMED_WEAK_PASSWORD', 'AUTHENTICATION_REJECTED', 'NOT_TESTED', 'AUTHENTICATION_ERROR')),
  overall_security_status TEXT CHECK (overall_security_status IN ('VULNERABLE', 'HEALTHY', 'NOT_VERIFIED')),
  trust_score INT DEFAULT 100 CHECK (trust_score >= 0 AND trust_score <= 100),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  score INT NOT NULL DEFAULT 0,
  recommendation TEXT NOT NULL,
  -- Observation only (open port, HTTP-only, …): shown but excluded from risk/status
  informational BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  report_title TEXT NOT NULL,
  report_html TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
  safe_scan_mode BOOLEAN DEFAULT true,
  scan_timeout INT DEFAULT 300,
  login_attempt_limit INT DEFAULT 5,
  enabled_checks JSONB DEFAULT '{
    "default_credentials": true,
    "weak_auth": true,
    "open_ports": true,
    "http_only": true,
    "rtsp_exposed": true,
    "outdated_firmware": true,
    "insecure_web": true,
    "missing_headers": true,
    "telnet_open": true
  }',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Default credentials table
CREATE TABLE IF NOT EXISTS default_credentials (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  vendor TEXT NOT NULL,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  risk_level TEXT DEFAULT 'critical' CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT uq_default_credentials_vendor_user_pass UNIQUE (vendor, username, password)
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  details JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tokens revoked by logout; a token's jti stays here until it expires
CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti TEXT PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_devices_risk_level ON devices(risk_level);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device_id ON vulnerabilities(device_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Vulnerability checks table
CREATE TABLE IF NOT EXISTS vulnerability_checks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  description TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
  risk_score INT NOT NULL DEFAULT 0,
  recommendation TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vuln_checks_slug ON vulnerability_checks(slug);
CREATE INDEX IF NOT EXISTS idx_vuln_checks_enabled ON vulnerability_checks(enabled);

-- Row Level Security: all application access goes through the server-side
-- service-role client (see lib/supabase/server.ts), which bypasses RLS
-- entirely, so this adds no restriction on the app's own behavior. What it
-- does is remove the zero-defense-in-depth gap: with RLS enabled and no
-- policies defined, the anon/authenticated Supabase roles get no access to
-- any of these tables by default, so a future client-side Supabase call (or
-- a missed route-level auth check) fails closed instead of exposing data.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE default_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;

-- Community Vulnerability Mapping: per-scan matches (records live in data/vulnerabilities.txt)
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
