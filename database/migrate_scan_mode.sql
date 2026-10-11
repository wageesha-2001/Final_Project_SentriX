-- Migration: record whether each scan used real discovery or simulated demo devices
-- Run this ONCE in the Supabase SQL Editor on databases created before this column existed.
-- Scans created before the migration keep NULL (mode unknown) and show no banner.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_mode TEXT CHECK (scan_mode IN ('real', 'simulated'));
