-- Seed default credentials (100+ records, worldwide CCTV/IP camera vendors)
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

-- Seed admin user. Credentials are documented in README.md — rotate them
-- before any real deployment; see the security audit findings for why.
INSERT INTO users (id, name, email, password_hash, role) VALUES
  (
    'a0000000-0000-0000-0000-000000000001',
    'System Administrator',
    'admin@sentrix.local',
    '$2b$12$V/cs7h0a8fMeSEibZq.SWehwqMyOCPoaAuZR1WeMtrluLEDJTD0qC',
    'admin'
  )
ON CONFLICT (email) DO NOTHING;

-- Seed technician user. Credentials are documented in README.md — rotate
-- them before any real deployment; see the security audit findings for why.
INSERT INTO users (id, name, email, password_hash, role) VALUES
  (
    'a0000000-0000-0000-0000-000000000002',
    'Security Technician',
    'tech@sentrix.local',
    '$2b$12$5vsTaGDrlg3RkDaNEaLeCeSMsFoM3pOyeX4Ff42shEejINB9MYo3a',
    'technician'
  )
ON CONFLICT (email) DO NOTHING;

-- Seed settings for admin
INSERT INTO settings (user_id, safe_scan_mode, scan_timeout, login_attempt_limit)
VALUES ('a0000000-0000-0000-0000-000000000001', true, 300, 5)
ON CONFLICT (user_id) DO NOTHING;

-- Seed settings for technician
INSERT INTO settings (user_id, safe_scan_mode, scan_timeout, login_attempt_limit)
VALUES ('a0000000-0000-0000-0000-000000000002', true, 300, 5)
ON CONFLICT (user_id) DO NOTHING;

-- Seed vulnerability checks
INSERT INTO vulnerability_checks (id, name, slug, description, severity, risk_score, recommendation, enabled) VALUES
  ('d0000001-0000-0000-0000-000000000001', 'Default Credentials Check', 'default_credentials',
   'Detect whether CCTV devices use known vendor default usernames and passwords.',
   'critical', 35,
   'Change all default credentials immediately and use strong unique passwords.', true),

  ('d0000001-0000-0000-0000-000000000002', 'Weak Authentication Detection', 'weak_auth',
   'Detect weak passwords or insecure authentication methods.',
   'high', 25,
   'Enforce strong password policies and disable weak authentication methods.', true),

  ('d0000001-0000-0000-0000-000000000003', 'Open Risky Ports Scan', 'open_ports',
   'Detect exposed high-risk ports such as Telnet, FTP, RTSP, HTTP, SSH, and UPnP.',
   'high', 20,
   'Close unused ports and restrict access using firewall rules.', true),

  ('d0000001-0000-0000-0000-000000000004', 'HTTP-Only Interface Check', 'http_only',
   'Detect CCTV web interfaces that use HTTP without HTTPS encryption.',
   'medium', 15,
   'Enable HTTPS and redirect all HTTP traffic securely.', true),

  ('d0000001-0000-0000-0000-000000000005', 'RTSP Exposure Check', 'rtsp_exposed',
   'Detect RTSP video streams accessible without proper authentication.',
   'high', 25,
   'Require authentication for RTSP streams and restrict access.', true),

  ('d0000001-0000-0000-0000-000000000006', 'Firmware Version Analysis', 'outdated_firmware',
   'Analyze firmware versions and identify outdated or unsupported versions.',
   'high', 20,
   'Update firmware to the latest stable secure release.', true),

  ('d0000001-0000-0000-0000-000000000007', 'Web Interface Security Check', 'insecure_web',
   'Analyze CCTV admin web interfaces for insecure configurations.',
   'medium', 15,
   'Disable unnecessary features and secure the admin interface.', true),

  ('d0000001-0000-0000-0000-000000000008', 'Security Headers Check', 'missing_headers',
   'Check for missing HTTP security headers such as CSP, HSTS, X-Frame-Options, and X-Content-Type-Options.',
   'medium', 10,
   'Implement proper HTTP security headers.', true),

  ('d0000001-0000-0000-0000-000000000009', 'Telnet Service Detection', 'telnet_open',
   'Detect enabled Telnet services on CCTV devices.',
   'high', 25,
   'Disable Telnet and use secure protocols such as SSH.', true),

  ('d0000001-0000-0000-0000-000000000010', 'ONVIF Anonymous Access Check', 'onvif_anonymous',
   'Detect ONVIF services that allow unauthenticated access.',
   'high', 20,
   'Require authentication for ONVIF services.', true),

  ('d0000001-0000-0000-0000-000000000011', 'Internet Exposure Detection', 'internet_exposure',
   'Detect CCTV devices that may be publicly accessible from the internet.',
   'critical', 30,
   'Restrict public exposure and use VPN-based remote access.', true),

  ('d0000001-0000-0000-0000-000000000012', 'Device Trust Score', 'device_trust_score',
   'Generate an overall device trust/security score based on detected vulnerabilities.',
   'informational', 0,
   'Improve device configuration to increase trust score.', true),

  ('d0000001-0000-0000-0000-000000000013', 'Risk Scoring System', 'risk_scoring',
   'Calculate overall device and network risk levels based on detected vulnerabilities.',
   'informational', 0,
   'Address high-risk vulnerabilities first.', true),

  ('d0000001-0000-0000-0000-000000000014', 'Known CVE Mapping', 'cve_mapping',
   'Map detected firmware versions and services against known CVEs.',
   'high', 20,
   'Patch vulnerable systems immediately.', true),

  ('d0000001-0000-0000-0000-000000000015', 'Session Cookie Security Check', 'session_cookies',
   'Analyze web session cookies for missing Secure, HttpOnly, and SameSite attributes.',
   'medium', 10,
   'Configure secure cookie settings.', true)

ON CONFLICT (slug) DO NOTHING;
