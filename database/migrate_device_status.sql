-- Migration: separated per-device assessment statuses + informational findings.
-- Run ONCE in the Supabase SQL Editor. Safe to re-run (IF NOT EXISTS / guarded).

-- Devices: known-vulnerability, authentication and overall statuses + trust score.
ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS known_vulnerability_status TEXT,
  ADD COLUMN IF NOT EXISTS authentication_status TEXT,
  ADD COLUMN IF NOT EXISTS overall_security_status TEXT,
  ADD COLUMN IF NOT EXISTS trust_score INT DEFAULT 100;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.constraint_column_usage
                 WHERE constraint_name = 'devices_known_vulnerability_status_check') THEN
    ALTER TABLE devices ADD CONSTRAINT devices_known_vulnerability_status_check
      CHECK (known_vulnerability_status IS NULL OR known_vulnerability_status IN ('MATCHED','NO_MATCH','UNVERIFIED'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.constraint_column_usage
                 WHERE constraint_name = 'devices_authentication_status_check') THEN
    ALTER TABLE devices ADD CONSTRAINT devices_authentication_status_check
      CHECK (authentication_status IS NULL OR authentication_status IN
        ('CONFIRMED_DEFAULT_CREDENTIALS','AUTHENTICATION_REJECTED','NOT_TESTED','AUTHENTICATION_ERROR'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.constraint_column_usage
                 WHERE constraint_name = 'devices_overall_security_status_check') THEN
    ALTER TABLE devices ADD CONSTRAINT devices_overall_security_status_check
      CHECK (overall_security_status IS NULL OR overall_security_status IN ('VULNERABLE','HEALTHY','NOT_VERIFIED'));
  END IF;
END $$;

-- Vulnerabilities: informational flag (open-port/HTTP-only observations).
ALTER TABLE vulnerabilities
  ADD COLUMN IF NOT EXISTS informational BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_devices_overall_status ON devices(overall_security_status);
