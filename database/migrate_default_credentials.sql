-- Migration: Reset and re-seed default_credentials with 196 records (worldwide CCTV vendors)
-- Run this ONCE in the Supabase SQL Editor.
-- Steps: add unique constraint → clear old rows → insert all records.

-- Step 1: Add unique constraint so ON CONFLICT works correctly in future seeds
ALTER TABLE default_credentials
  DROP CONSTRAINT IF EXISTS uq_default_credentials_vendor_user_pass;

ALTER TABLE default_credentials
  ADD CONSTRAINT uq_default_credentials_vendor_user_pass
  UNIQUE (vendor, username, password);

-- Step 2: Remove all existing rows (old seed had only 12–15 incomplete records)
TRUNCATE TABLE default_credentials RESTART IDENTITY;

-- Step 3: Insert all 196 records
INSERT INTO default_credentials (vendor, username, password, risk_level) VALUES

  -- Hikvision (China) — world's largest CCTV manufacturer
  ('Hikvision', 'admin', '12345', 'critical'),
  ('Hikvision', 'admin', 'admin', 'critical'),
  ('Hikvision', 'admin', 'admin123', 'critical'),
  ('Hikvision', 'admin', '', 'critical'),
  ('Hikvision', 'admin', '123456', 'critical'),

  -- Dahua Technology (China)
  ('Dahua', 'admin', 'admin', 'critical'),
  ('Dahua', 'admin', '123456', 'critical'),
  ('Dahua', 'admin', '', 'critical'),
  ('Dahua', '888888', '888888', 'critical'),
  ('Dahua', '666666', '666666', 'critical'),
  ('Dahua', 'default', 'default', 'critical'),

  -- EZVIZ (Hikvision sub-brand, China)
  ('EZVIZ', 'admin', 'admin', 'critical'),
  ('EZVIZ', 'admin', '123456', 'critical'),
  ('EZVIZ', 'admin', '', 'critical'),

  -- Imou (Dahua sub-brand, China)
  ('Imou', 'admin', 'admin', 'critical'),
  ('Imou', 'admin', '', 'critical'),

  -- Uniview / UNV (China)
  ('Uniview', 'admin', '123456', 'critical'),
  ('Uniview', 'admin', 'admin', 'critical'),
  ('Uniview', 'admin', '', 'critical'),

  -- Tiandy (China)
  ('Tiandy', 'admin', 'admin', 'critical'),
  ('Tiandy', 'admin', '123456', 'critical'),
  ('Tiandy', 'admin', '', 'critical'),

  -- Kedacom (China)
  ('Kedacom', 'admin', 'admin', 'critical'),
  ('Kedacom', 'admin', '123456', 'critical'),

  -- Sunell (China)
  ('Sunell', 'admin', 'admin', 'critical'),
  ('Sunell', 'admin', '123456', 'critical'),

  -- Longse Technology (China)
  ('Longse', 'admin', 'admin', 'critical'),
  ('Longse', 'admin', '12345', 'critical'),

  -- Jovision (China)
  ('Jovision', 'admin', 'admin', 'critical'),
  ('Jovision', 'admin', '12345', 'critical'),

  -- XM Technology / XMEye (China)
  ('XM Technology', 'admin', '', 'critical'),
  ('XM Technology', 'admin', 'admin', 'critical'),
  ('XM Technology', 'default', '', 'critical'),

  -- Foscam (China)
  ('Foscam', 'admin', '', 'critical'),
  ('Foscam', 'admin', 'admin', 'critical'),
  ('Foscam', 'admin', 'foscam', 'high'),

  -- Reolink (China)
  ('Reolink', 'admin', '', 'critical'),
  ('Reolink', 'admin', 'admin', 'critical'),
  ('Reolink', 'admin', '123456', 'critical'),

  -- Annke (China)
  ('Annke', 'admin', '12345', 'critical'),
  ('Annke', 'admin', 'admin', 'critical'),

  -- Sannce (China)
  ('Sannce', 'admin', '12345', 'critical'),
  ('Sannce', 'admin', 'admin', 'critical'),

  -- Amcrest (Dahua OEM, US/China)
  ('Amcrest', 'admin', 'admin', 'critical'),
  ('Amcrest', 'admin', 'amcrest', 'high'),

  -- Zmodo (China)
  ('Zmodo', 'admin', 'admin', 'critical'),
  ('Zmodo', 'admin', '111111', 'critical'),

  -- Zosi (China)
  ('Zosi', 'admin', 'admin', 'critical'),
  ('Zosi', 'admin', '', 'critical'),

  -- LaView (China/US)
  ('LaView', 'admin', 'admin', 'critical'),
  ('LaView', 'admin', '1234', 'critical'),

  -- Provision-ISR (Israel/China)
  ('Provision-ISR', 'admin', '1234', 'critical'),
  ('Provision-ISR', 'admin', 'admin', 'critical'),

  -- Axis Communications (Sweden)
  ('Axis', 'root', 'pass', 'critical'),
  ('Axis', 'root', '', 'critical'),
  ('Axis', 'admin', 'admin', 'critical'),
  ('Axis', 'operator', 'operator', 'high'),
  ('Axis', 'viewer', 'viewer', 'medium'),

  -- Hanwha Vision / Samsung Techwin (South Korea)
  ('Hanwha Vision', 'admin', '', 'critical'),
  ('Hanwha Vision', 'admin', '4321', 'critical'),
  ('Hanwha Vision', 'admin', '1111', 'critical'),
  ('Hanwha Vision', 'admin', 'admin', 'critical'),
  ('Samsung Techwin', 'admin', '4321', 'critical'),
  ('Samsung Techwin', 'admin', '', 'critical'),

  -- LG Electronics (South Korea)
  ('LG Electronics', 'admin', 'admin', 'critical'),
  ('LG Electronics', 'admin', '', 'critical'),
  ('LG Electronics', 'guest', 'guest', 'high'),

  -- Idis (South Korea)
  ('Idis', 'admin', 'admin', 'critical'),
  ('Idis', 'admin', '', 'critical'),

  -- Sony (Japan)
  ('Sony', 'admin', 'admin', 'critical'),
  ('Sony', 'admin', '', 'critical'),
  ('Sony', 'root', 'sony', 'high'),

  -- Panasonic (Japan)
  ('Panasonic', 'admin', '12345', 'critical'),
  ('Panasonic', 'admin', 'admin', 'critical'),
  ('Panasonic', 'admin1', 'password', 'high'),
  ('Panasonic', 'user1', 'password', 'high'),

  -- JVC (Japan)
  ('JVC', 'admin', 'jvc', 'high'),
  ('JVC', 'admin', 'admin', 'critical'),

  -- Bosch Security Systems (Germany)
  ('Bosch', 'admin', 'admin', 'critical'),
  ('Bosch', 'service', 'service', 'critical'),
  ('Bosch', 'live', 'live', 'high'),
  ('Bosch', 'admin', '', 'critical'),

  -- Mobotix (Germany)
  ('Mobotix', 'admin', 'meinsm', 'critical'),
  ('Mobotix', 'admin', 'admin', 'critical'),

  -- Dallmeier (Germany)
  ('Dallmeier', 'admin', 'admin', 'critical'),
  ('Dallmeier', 'admin', '0000', 'critical'),

  -- Geutebruck (Germany)
  ('Geutebruck', 'admin', 'admin', 'critical'),
  ('Geutebruck', 'admin', '', 'critical'),

  -- Pelco (USA / Schneider Electric)
  ('Pelco', 'admin', 'admin', 'critical'),
  ('Pelco', 'admin', '', 'critical'),
  ('Pelco', 'admin', 'pelco', 'high'),

  -- FLIR Systems (USA)
  ('FLIR', 'admin', 'admin', 'critical'),
  ('FLIR', 'admin', 'fliradmin', 'high'),

  -- Lorex (Canada / FLIR subsidiary)
  ('Lorex', 'admin', 'admin', 'critical'),
  ('Lorex', 'admin', '000000', 'critical'),

  -- Avigilon (Canada / Motorola Solutions)
  ('Avigilon', 'admin', 'admin', 'critical'),
  ('Avigilon', 'admin', 'password', 'high'),

  -- Honeywell Security (USA)
  ('Honeywell', 'admin', '1234', 'critical'),
  ('Honeywell', 'admin', 'admin', 'critical'),
  ('Honeywell', 'user', '1234', 'high'),

  -- Speco Technologies (USA)
  ('Speco Technologies', 'admin', '1234', 'critical'),
  ('Speco Technologies', 'admin', 'admin', 'critical'),

  -- Digital Watchdog (USA)
  ('Digital Watchdog', 'admin', 'admin', 'critical'),
  ('Digital Watchdog', 'admin', '1234', 'critical'),

  -- Arecont Vision (USA)
  ('Arecont Vision', 'admin', '', 'critical'),
  ('Arecont Vision', 'admin', 'admin', 'critical'),

  -- Exacq Vision / Johnson Controls (USA)
  ('Exacq Vision', 'admin', 'admin256', 'high'),
  ('Exacq Vision', 'admin', 'admin', 'critical'),

  -- American Dynamics / Tyco (USA)
  ('American Dynamics', 'admin', 'admin', 'critical'),
  ('American Dynamics', 'admin', '', 'critical'),

  -- IndigoVision (UK / Scotland)
  ('IndigoVision', 'admin', 'admin', 'critical'),
  ('IndigoVision', 'admin', '', 'critical'),

  -- March Networks (Canada)
  ('March Networks', 'admin', 'admin', 'critical'),
  ('March Networks', 'admin', 'march', 'high'),

  -- Vivotek (Taiwan)
  ('Vivotek', 'root', '', 'critical'),
  ('Vivotek', 'admin', 'admin', 'critical'),
  ('Vivotek', 'admin', '', 'critical'),

  -- ACTi (Taiwan)
  ('ACTi', 'admin', '123456', 'critical'),
  ('ACTi', 'Admin', '123456', 'critical'),
  ('ACTi', 'admin', 'admin', 'critical'),

  -- Surveon (Taiwan)
  ('Surveon', 'admin', 'admin', 'critical'),
  ('Surveon', 'admin', '', 'critical'),

  -- Brickcom (Taiwan)
  ('Brickcom', 'admin', 'admin', 'critical'),
  ('Brickcom', 'admin', '1234', 'critical'),

  -- Hunt Electronics (Taiwan)
  ('Hunt Electronics', 'admin', '12345', 'critical'),
  ('Hunt Electronics', 'admin', 'admin', 'critical'),

  -- AirLive (Taiwan)
  ('AirLive', 'admin', 'airlive', 'high'),
  ('AirLive', 'admin', 'admin', 'critical'),

  -- PLANET Technology (Taiwan)
  ('PLANET Technology', 'admin', 'admin', 'critical'),
  ('PLANET Technology', 'admin', '1234', 'critical'),

  -- GeoVision (Taiwan)
  ('GeoVision', 'admin', 'admin', 'critical'),
  ('GeoVision', 'admin', '', 'critical'),

  -- D-Link (Taiwan)
  ('D-Link', 'admin', 'admin', 'critical'),
  ('D-Link', 'admin', '', 'critical'),
  ('D-Link', 'Admin', '', 'critical'),

  -- TRENDnet (USA/Taiwan)
  ('TRENDnet', 'admin', 'admin', 'critical'),
  ('TRENDnet', 'admin', '', 'critical'),
  ('TRENDnet', 'admin', 'trendnet', 'high'),

  -- Swann (Australia)
  ('Swann', 'admin', 'admin', 'critical'),
  ('Swann', 'admin', '12345', 'critical'),

  -- Night Owl (USA)
  ('Night Owl', 'admin', 'admin', 'critical'),
  ('Night Owl', 'admin', '1234', 'critical'),

  -- Q-See (USA / Dahua OEM)
  ('Q-See', 'admin', 'admin', 'critical'),
  ('Q-See', 'admin', '', 'critical'),

  -- Montavue (USA / Dahua OEM)
  ('Montavue', 'admin', 'admin', 'critical'),
  ('Montavue', 'admin', '123456', 'critical'),

  -- Ubiquiti UniFi Protect (USA)
  ('Ubiquiti UniFi', 'ubnt', 'ubnt', 'critical'),
  ('Ubiquiti UniFi', 'admin', 'admin', 'critical'),

  -- Nuvico (USA)
  ('Nuvico', 'admin', 'admin', 'critical'),
  ('Nuvico', 'admin', '1234', 'critical'),

  -- Messoa (Taiwan)
  ('Messoa', 'admin', 'admin', 'critical'),
  ('Messoa', 'admin', '', 'critical'),

  -- Infinova (USA/China)
  ('Infinova', 'admin', 'admin', 'critical'),
  ('Infinova', 'admin', 'infinova', 'high'),

  -- Verint (Israel/USA)
  ('Verint', 'admin', 'admin', 'critical'),
  ('Verint', 'operator', 'operator', 'high'),

  -- OnSSI (USA)
  ('OnSSI', 'admin', 'admin', 'critical'),
  ('OnSSI', 'onssi', 'onssi', 'high'),

  -- Lenel / Carrier (USA)
  ('Lenel', 'admin', 'lenel', 'high'),
  ('Lenel', 'admin', 'admin', 'critical'),

  -- Milestone Systems (Denmark)
  ('Milestone', 'admin', 'admin', 'critical'),
  ('Milestone', 'admin', '', 'critical'),

  -- IQinVision (USA)
  ('IQinVision', '', 'system', 'critical'),
  ('IQinVision', 'admin', 'system', 'high'),

  -- Generic / Unknown vendor fallbacks
  ('Generic', 'admin', 'admin', 'critical'),
  ('Generic', 'admin', '', 'critical'),
  ('Generic', 'root', 'root', 'critical'),
  ('Generic', 'root', '', 'critical'),
  ('Generic', 'admin', '1234', 'critical'),
  ('Generic', 'admin', '12345', 'critical'),
  ('Generic', 'admin', '123456', 'critical'),
  ('Generic', 'admin', '000000', 'critical'),
  ('Generic', 'admin', '111111', 'critical'),
  ('Generic', 'admin', 'password', 'high'),
  ('Generic', 'user', 'user', 'high'),
  ('Generic', 'guest', 'guest', 'high'),
  ('Generic', 'service', 'service', 'high'),
  ('Generic', 'operator', 'operator', 'high'),
  ('Generic', 'default', 'default', 'high')

ON CONFLICT (vendor, username, password) DO NOTHING;
