/**
 * Local in-memory database — zero external dependencies.
 * Implements the Supabase query builder interface used across all API routes.
 * Pre-seeded with demo users and default credentials.
 * Data resets on server restart (use real Supabase for persistence).
 */

export type Row = Record<string, unknown>
type DbResult<T> = Promise<{ data: T; error: null | { message: string } }>

// ─── Credential seed helper ──────────────────────────────────────────────────

let _credSeq = 0
function cred(vendor: string, username: string, password: string, risk_level: string): Row {
  _credSeq++
  return {
    id: `dc${String(_credSeq).padStart(6, '0')}-0000-0000-0000-000000000000`,
    vendor, username, password, risk_level,
    created_at: new Date().toISOString(),
  }
}

// ─── In-memory data store ────────────────────────────────────────────────────

function seedData(): Record<string, Row[]> {
  return {
  users: [
    {
      id: 'a0000000-0000-0000-0000-000000000001',
      name: 'System Administrator',
      email: 'admin@sentrix.local',
      password_hash: '$2b$12$V/cs7h0a8fMeSEibZq.SWehwqMyOCPoaAuZR1WeMtrluLEDJTD0qC',
      role: 'admin',
      created_at: new Date().toISOString(),
    },
    {
      id: 'a0000000-0000-0000-0000-000000000002',
      name: 'Security Technician',
      email: 'tech@sentrix.local',
      password_hash: '$2b$12$5vsTaGDrlg3RkDaNEaLeCeSMsFoM3pOyeX4Ff42shEejINB9MYo3a',
      role: 'technician',
      created_at: new Date().toISOString(),
    },
  ],
  scans: [],
  devices: [],
  vulnerabilities: [],
  reports: [],
  settings: [
    {
      id: 'b0000000-0000-0000-0000-000000000001',
      user_id: 'a0000000-0000-0000-0000-000000000001',
      safe_scan_mode: true,
      scan_timeout: 300,
      login_attempt_limit: 5,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'b0000000-0000-0000-0000-000000000002',
      user_id: 'a0000000-0000-0000-0000-000000000002',
      safe_scan_mode: true,
      scan_timeout: 300,
      login_attempt_limit: 5,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ],
  default_credentials: [
    // Hikvision (China)
    cred('Hikvision', 'admin', '12345', 'critical'),
    cred('Hikvision', 'admin', 'admin', 'critical'),
    cred('Hikvision', 'admin', 'admin123', 'critical'),
    cred('Hikvision', 'admin', '', 'critical'),
    cred('Hikvision', 'admin', '123456', 'critical'),
    // Dahua Technology (China)
    cred('Dahua', 'admin', 'admin', 'critical'),
    cred('Dahua', 'admin', '123456', 'critical'),
    cred('Dahua', 'admin', '', 'critical'),
    cred('Dahua', '888888', '888888', 'critical'),
    cred('Dahua', '666666', '666666', 'critical'),
    cred('Dahua', 'default', 'default', 'critical'),
    // EZVIZ (Hikvision sub-brand)
    cred('EZVIZ', 'admin', 'admin', 'critical'),
    cred('EZVIZ', 'admin', '123456', 'critical'),
    cred('EZVIZ', 'admin', '', 'critical'),
    // Imou (Dahua sub-brand)
    cred('Imou', 'admin', 'admin', 'critical'),
    cred('Imou', 'admin', '', 'critical'),
    // Uniview / UNV (China)
    cred('Uniview', 'admin', '123456', 'critical'),
    cred('Uniview', 'admin', 'admin', 'critical'),
    cred('Uniview', 'admin', '', 'critical'),
    // Tiandy (China)
    cred('Tiandy', 'admin', 'admin', 'critical'),
    cred('Tiandy', 'admin', '123456', 'critical'),
    cred('Tiandy', 'admin', '', 'critical'),
    // Kedacom (China)
    cred('Kedacom', 'admin', 'admin', 'critical'),
    cred('Kedacom', 'admin', '123456', 'critical'),
    // Sunell (China)
    cred('Sunell', 'admin', 'admin', 'critical'),
    cred('Sunell', 'admin', '123456', 'critical'),
    // Longse Technology (China)
    cred('Longse', 'admin', 'admin', 'critical'),
    cred('Longse', 'admin', '12345', 'critical'),
    // Jovision (China)
    cred('Jovision', 'admin', 'admin', 'critical'),
    cred('Jovision', 'admin', '12345', 'critical'),
    // XM Technology / XMEye (China)
    cred('XM Technology', 'admin', '', 'critical'),
    cred('XM Technology', 'admin', 'admin', 'critical'),
    cred('XM Technology', 'default', '', 'critical'),
    // Foscam (China)
    cred('Foscam', 'admin', '', 'critical'),
    cred('Foscam', 'admin', 'admin', 'critical'),
    cred('Foscam', 'admin', 'foscam', 'high'),
    // Reolink (China)
    cred('Reolink', 'admin', '', 'critical'),
    cred('Reolink', 'admin', 'admin', 'critical'),
    cred('Reolink', 'admin', '123456', 'critical'),
    // Annke (China)
    cred('Annke', 'admin', '12345', 'critical'),
    cred('Annke', 'admin', 'admin', 'critical'),
    // Sannce (China)
    cred('Sannce', 'admin', '12345', 'critical'),
    cred('Sannce', 'admin', 'admin', 'critical'),
    // Amcrest (Dahua OEM)
    cred('Amcrest', 'admin', 'admin', 'critical'),
    cred('Amcrest', 'admin', 'amcrest', 'high'),
    // Zmodo (China)
    cred('Zmodo', 'admin', 'admin', 'critical'),
    cred('Zmodo', 'admin', '111111', 'critical'),
    // Zosi (China)
    cred('Zosi', 'admin', 'admin', 'critical'),
    cred('Zosi', 'admin', '', 'critical'),
    // LaView (China/US)
    cred('LaView', 'admin', 'admin', 'critical'),
    cred('LaView', 'admin', '1234', 'critical'),
    // Provision-ISR (Israel/China)
    cred('Provision-ISR', 'admin', '1234', 'critical'),
    cred('Provision-ISR', 'admin', 'admin', 'critical'),
    // Axis Communications (Sweden)
    cred('Axis', 'root', 'pass', 'critical'),
    cred('Axis', 'root', '', 'critical'),
    cred('Axis', 'admin', 'admin', 'critical'),
    cred('Axis', 'operator', 'operator', 'high'),
    cred('Axis', 'viewer', 'viewer', 'medium'),
    // Hanwha Vision / Samsung Techwin (South Korea)
    cred('Hanwha Vision', 'admin', '', 'critical'),
    cred('Hanwha Vision', 'admin', '4321', 'critical'),
    cred('Hanwha Vision', 'admin', '1111', 'critical'),
    cred('Hanwha Vision', 'admin', 'admin', 'critical'),
    cred('Samsung Techwin', 'admin', '4321', 'critical'),
    cred('Samsung Techwin', 'admin', '', 'critical'),
    // LG Electronics (South Korea)
    cred('LG Electronics', 'admin', 'admin', 'critical'),
    cred('LG Electronics', 'admin', '', 'critical'),
    cred('LG Electronics', 'guest', 'guest', 'high'),
    // Idis (South Korea)
    cred('Idis', 'admin', 'admin', 'critical'),
    cred('Idis', 'admin', '', 'critical'),
    // Sony (Japan)
    cred('Sony', 'admin', 'admin', 'critical'),
    cred('Sony', 'admin', '', 'critical'),
    cred('Sony', 'root', 'sony', 'high'),
    // Panasonic (Japan)
    cred('Panasonic', 'admin', '12345', 'critical'),
    cred('Panasonic', 'admin', 'admin', 'critical'),
    cred('Panasonic', 'admin1', 'password', 'high'),
    cred('Panasonic', 'user1', 'password', 'high'),
    // JVC (Japan)
    cred('JVC', 'admin', 'jvc', 'high'),
    cred('JVC', 'admin', 'admin', 'critical'),
    // Bosch Security Systems (Germany)
    cred('Bosch', 'admin', 'admin', 'critical'),
    cred('Bosch', 'service', 'service', 'critical'),
    cred('Bosch', 'live', 'live', 'high'),
    cred('Bosch', 'admin', '', 'critical'),
    // Mobotix (Germany)
    cred('Mobotix', 'admin', 'meinsm', 'critical'),
    cred('Mobotix', 'admin', 'admin', 'critical'),
    // Dallmeier (Germany)
    cred('Dallmeier', 'admin', 'admin', 'critical'),
    cred('Dallmeier', 'admin', '0000', 'critical'),
    // Geutebruck (Germany)
    cred('Geutebruck', 'admin', 'admin', 'critical'),
    cred('Geutebruck', 'admin', '', 'critical'),
    // Pelco (USA / Schneider Electric)
    cred('Pelco', 'admin', 'admin', 'critical'),
    cred('Pelco', 'admin', '', 'critical'),
    cred('Pelco', 'admin', 'pelco', 'high'),
    // FLIR Systems (USA)
    cred('FLIR', 'admin', 'admin', 'critical'),
    cred('FLIR', 'admin', 'fliradmin', 'high'),
    // Lorex (Canada / FLIR subsidiary)
    cred('Lorex', 'admin', 'admin', 'critical'),
    cred('Lorex', 'admin', '000000', 'critical'),
    // Avigilon (Canada / Motorola Solutions)
    cred('Avigilon', 'admin', 'admin', 'critical'),
    cred('Avigilon', 'admin', 'password', 'high'),
    // Honeywell Security (USA)
    cred('Honeywell', 'admin', '1234', 'critical'),
    cred('Honeywell', 'admin', 'admin', 'critical'),
    cred('Honeywell', 'user', '1234', 'high'),
    // Speco Technologies (USA)
    cred('Speco Technologies', 'admin', '1234', 'critical'),
    cred('Speco Technologies', 'admin', 'admin', 'critical'),
    // Digital Watchdog (USA)
    cred('Digital Watchdog', 'admin', 'admin', 'critical'),
    cred('Digital Watchdog', 'admin', '1234', 'critical'),
    // Arecont Vision (USA)
    cred('Arecont Vision', 'admin', '', 'critical'),
    cred('Arecont Vision', 'admin', 'admin', 'critical'),
    // Exacq Vision / Johnson Controls (USA)
    cred('Exacq Vision', 'admin', 'admin256', 'high'),
    cred('Exacq Vision', 'admin', 'admin', 'critical'),
    // American Dynamics / Tyco (USA)
    cred('American Dynamics', 'admin', 'admin', 'critical'),
    cred('American Dynamics', 'admin', '', 'critical'),
    // IndigoVision (UK)
    cred('IndigoVision', 'admin', 'admin', 'critical'),
    cred('IndigoVision', 'admin', '', 'critical'),
    // March Networks (Canada)
    cred('March Networks', 'admin', 'admin', 'critical'),
    cred('March Networks', 'admin', 'march', 'high'),
    // Vivotek (Taiwan)
    cred('Vivotek', 'root', '', 'critical'),
    cred('Vivotek', 'admin', 'admin', 'critical'),
    cred('Vivotek', 'admin', '', 'critical'),
    // ACTi (Taiwan)
    cred('ACTi', 'admin', '123456', 'critical'),
    cred('ACTi', 'Admin', '123456', 'critical'),
    cred('ACTi', 'admin', 'admin', 'critical'),
    // Surveon (Taiwan)
    cred('Surveon', 'admin', 'admin', 'critical'),
    cred('Surveon', 'admin', '', 'critical'),
    // Brickcom (Taiwan)
    cred('Brickcom', 'admin', 'admin', 'critical'),
    cred('Brickcom', 'admin', '1234', 'critical'),
    // Hunt Electronics (Taiwan)
    cred('Hunt Electronics', 'admin', '12345', 'critical'),
    cred('Hunt Electronics', 'admin', 'admin', 'critical'),
    // AirLive (Taiwan)
    cred('AirLive', 'admin', 'airlive', 'high'),
    cred('AirLive', 'admin', 'admin', 'critical'),
    // PLANET Technology (Taiwan)
    cred('PLANET Technology', 'admin', 'admin', 'critical'),
    cred('PLANET Technology', 'admin', '1234', 'critical'),
    // GeoVision (Taiwan)
    cred('GeoVision', 'admin', 'admin', 'critical'),
    cred('GeoVision', 'admin', '', 'critical'),
    // D-Link (Taiwan)
    cred('D-Link', 'admin', 'admin', 'critical'),
    cred('D-Link', 'admin', '', 'critical'),
    cred('D-Link', 'Admin', '', 'critical'),
    // TRENDnet (USA/Taiwan)
    cred('TRENDnet', 'admin', 'admin', 'critical'),
    cred('TRENDnet', 'admin', '', 'critical'),
    cred('TRENDnet', 'admin', 'trendnet', 'high'),
    // Swann (Australia)
    cred('Swann', 'admin', 'admin', 'critical'),
    cred('Swann', 'admin', '12345', 'critical'),
    // Night Owl (USA)
    cred('Night Owl', 'admin', 'admin', 'critical'),
    cred('Night Owl', 'admin', '1234', 'critical'),
    // Q-See (USA / Dahua OEM)
    cred('Q-See', 'admin', 'admin', 'critical'),
    cred('Q-See', 'admin', '', 'critical'),
    // Montavue (USA / Dahua OEM)
    cred('Montavue', 'admin', 'admin', 'critical'),
    cred('Montavue', 'admin', '123456', 'critical'),
    // Ubiquiti UniFi Protect (USA)
    cred('Ubiquiti UniFi', 'ubnt', 'ubnt', 'critical'),
    cred('Ubiquiti UniFi', 'admin', 'admin', 'critical'),
    // Nuvico (USA)
    cred('Nuvico', 'admin', 'admin', 'critical'),
    cred('Nuvico', 'admin', '1234', 'critical'),
    // Messoa (Taiwan)
    cred('Messoa', 'admin', 'admin', 'critical'),
    cred('Messoa', 'admin', '', 'critical'),
    // Infinova (USA/China)
    cred('Infinova', 'admin', 'admin', 'critical'),
    cred('Infinova', 'admin', 'infinova', 'high'),
    // Verint (Israel/USA)
    cred('Verint', 'admin', 'admin', 'critical'),
    cred('Verint', 'operator', 'operator', 'high'),
    // OnSSI (USA)
    cred('OnSSI', 'admin', 'admin', 'critical'),
    cred('OnSSI', 'onssi', 'onssi', 'high'),
    // Lenel / Carrier (USA)
    cred('Lenel', 'admin', 'lenel', 'high'),
    cred('Lenel', 'admin', 'admin', 'critical'),
    // Milestone Systems (Denmark)
    cred('Milestone', 'admin', 'admin', 'critical'),
    cred('Milestone', 'admin', '', 'critical'),
    // IQinVision (USA)
    cred('IQinVision', '', 'system', 'critical'),
    cred('IQinVision', 'admin', 'system', 'high'),
    // Generic / Unknown vendor fallbacks
    cred('Generic', 'admin', 'admin', 'critical'),
    cred('Generic', 'admin', '', 'critical'),
    cred('Generic', 'root', 'root', 'critical'),
    cred('Generic', 'root', '', 'critical'),
    cred('Generic', 'admin', '1234', 'critical'),
    cred('Generic', 'admin', '12345', 'critical'),
    cred('Generic', 'admin', '123456', 'critical'),
    cred('Generic', 'admin', '000000', 'critical'),
    cred('Generic', 'admin', '111111', 'critical'),
    cred('Generic', 'admin', 'password', 'high'),
    cred('Generic', 'user', 'user', 'high'),
    cred('Generic', 'guest', 'guest', 'high'),
    cred('Generic', 'service', 'service', 'high'),
    cred('Generic', 'operator', 'operator', 'high'),
    cred('Generic', 'default', 'default', 'high'),
  ],
  audit_logs: [],
  // Per-scan community vulnerability matches (the records themselves live in data/vulnerabilities.txt)
  device_vulnerability_matches: [],
  vulnerability_checks: [
    { id: 'd0000001-0000-0000-0000-000000000001', name: 'Default Credentials Check', slug: 'default_credentials', description: 'Detect whether CCTV devices use known vendor default usernames and passwords.', severity: 'critical', risk_score: 35, recommendation: 'Change all default credentials immediately and use strong unique passwords.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000002', name: 'Weak Authentication Detection', slug: 'weak_auth', description: 'Detect weak passwords or insecure authentication methods.', severity: 'high', risk_score: 25, recommendation: 'Enforce strong password policies and disable weak authentication methods.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000003', name: 'Open Risky Ports Scan', slug: 'open_ports', description: 'Detect exposed high-risk ports such as Telnet, FTP, RTSP, HTTP, SSH, and UPnP.', severity: 'high', risk_score: 20, recommendation: 'Close unused ports and restrict access using firewall rules.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000004', name: 'HTTP-Only Interface Check', slug: 'http_only', description: 'Detect CCTV web interfaces that use HTTP without HTTPS encryption.', severity: 'medium', risk_score: 15, recommendation: 'Enable HTTPS and redirect all HTTP traffic securely.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000005', name: 'RTSP Exposure Check', slug: 'rtsp_exposed', description: 'Detect RTSP video streams accessible without proper authentication.', severity: 'high', risk_score: 25, recommendation: 'Require authentication for RTSP streams and restrict access.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000006', name: 'Firmware Version Analysis', slug: 'outdated_firmware', description: 'Analyze firmware versions and identify outdated or unsupported versions.', severity: 'high', risk_score: 20, recommendation: 'Update firmware to the latest stable secure release.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000007', name: 'Web Interface Security Check', slug: 'insecure_web', description: 'Analyze CCTV admin web interfaces for insecure configurations.', severity: 'medium', risk_score: 15, recommendation: 'Disable unnecessary features and secure the admin interface.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000008', name: 'Security Headers Check', slug: 'missing_headers', description: 'Check for missing HTTP security headers such as CSP, HSTS, X-Frame-Options, and X-Content-Type-Options.', severity: 'medium', risk_score: 10, recommendation: 'Implement proper HTTP security headers.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000009', name: 'Telnet Service Detection', slug: 'telnet_open', description: 'Detect enabled Telnet services on CCTV devices.', severity: 'high', risk_score: 25, recommendation: 'Disable Telnet and use secure protocols such as SSH.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000010', name: 'ONVIF Anonymous Access Check', slug: 'onvif_anonymous', description: 'Detect ONVIF services that allow unauthenticated access.', severity: 'high', risk_score: 20, recommendation: 'Require authentication for ONVIF services.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000011', name: 'Internet Exposure Detection', slug: 'internet_exposure', description: 'Detect CCTV devices that may be publicly accessible from the internet.', severity: 'critical', risk_score: 30, recommendation: 'Restrict public exposure and use VPN-based remote access.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000012', name: 'Device Trust Score', slug: 'device_trust_score', description: 'Generate an overall device trust/security score based on detected vulnerabilities.', severity: 'informational', risk_score: 0, recommendation: 'Improve device configuration to increase trust score.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000013', name: 'Risk Scoring System', slug: 'risk_scoring', description: 'Calculate overall device and network risk levels based on detected vulnerabilities.', severity: 'informational', risk_score: 0, recommendation: 'Address high-risk vulnerabilities first.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000014', name: 'Known CVE Mapping', slug: 'cve_mapping', description: 'Map detected firmware versions and services against known CVEs.', severity: 'high', risk_score: 20, recommendation: 'Patch vulnerable systems immediately.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000015', name: 'Session Cookie Security Check', slug: 'session_cookies', description: 'Analyze web session cookies for missing Secure, HttpOnly, and SameSite attributes.', severity: 'medium', risk_score: 10, recommendation: 'Configure secure cookie settings.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    { id: 'd0000001-0000-0000-0000-000000000016', name: 'Community Vulnerability Mapping', slug: 'community-vulnerability-mapping', description: 'Maps detected CCTV device details against the SentriX community-maintained vulnerability database.', severity: 'high', risk_score: 0, recommendation: 'Review matched vulnerability records, update firmware, disable exposed services, and follow vendor security hardening guidance.', enabled: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
  ],
}
}

// Kept on globalThis so every API route shares ONE store. Next.js compiles each
// route separately (especially in `next dev`), so a plain module-level object
// would give each route its own copy — a scan created by POST /api/scans would
// then be invisible to /api/scans/[id]/start.
const globalStore = globalThis as typeof globalThis & { __sentrixLocalDb?: Record<string, Row[]> }
const db: Record<string, Row[]> = (globalStore.__sentrixLocalDb ??= seedData())

/** Test helper: discard all in-memory data and re-seed. */
export function resetLocalDb() {
  for (const key of Object.keys(db)) delete db[key]
  Object.assign(db, seedData())
}

// ─── Helper ──────────────────────────────────────────────────────────────────

function uid(): string {
  return crypto.randomUUID()
}

function projectFields(rows: Row[], fields: string): Row[] {
  if (!fields || fields === '*') return rows
  const cols = fields.split(',').map(f => f.trim().split(' ')[0])
  return rows.map(row => {
    const out: Row = {}
    cols.forEach(c => { if (c in row) out[c] = row[c] })
    return out
  })
}

// ─── Result builder returned from insert / upsert ───────────────────────────

class InsertResult {
  constructor(private rows: Row[]) {}

  // Mirrors Supabase: only the requested columns are returned (never e.g. password_hash)
  select(fields = '*') {
    this.rows = projectFields(this.rows, fields)
    return this
  }

  single(): DbResult<Row | null> {
    const row = this.rows[0] ?? null
    return Promise.resolve({ data: row, error: row ? null : { message: 'No row inserted' } })
  }

  // Make it directly awaitable as array result
  then<T>(
    resolve: (v: { data: Row[]; error: null }) => T,
    _reject?: (e: unknown) => T
  ): Promise<T> {
    return Promise.resolve(resolve({ data: this.rows, error: null }))
  }
}

// ─── Result builder returned from update / delete ───────────────────────────

class MutationResult {
  constructor(private affected: Row[] = []) {}

  // Make it directly awaitable
  then<T>(
    resolve: (v: { data: null; error: null }) => T,
    _reject?: (e: unknown) => T
  ): Promise<T> {
    return Promise.resolve(resolve({ data: null, error: null }))
  }
}

// ─── Main query builder ──────────────────────────────────────────────────────

class QueryBuilder {
  private _fields = '*'
  private _eqFilters: [string, unknown][] = []
  private _inFilters: [string, unknown[]][] = []
  private _orderField?: string
  private _orderAsc = true
  private _limit?: number

  constructor(private table: string) {
    if (!db[table]) db[table] = []
  }

  // ── Filter / shape ──────────────────────────────────────────────────────

  select(fields = '*'): this {
    this._fields = fields
    return this
  }

  eq(field: string, value: unknown): this {
    this._eqFilters.push([field, value])
    return this
  }

  in(field: string, values: unknown[]): this {
    this._inFilters.push([field, values])
    return this
  }

  order(field: string, opts?: { ascending?: boolean }): this {
    this._orderField = field
    this._orderAsc = opts?.ascending !== false
    return this
  }

  limit(n: number): this {
    this._limit = n
    return this
  }

  // ── Execute helpers ──────────────────────────────────────────────────────

  private execute(): Row[] {
    let rows = [...(db[this.table] ?? [])]

    for (const [field, value] of this._eqFilters) {
      rows = rows.filter(r => r[field] === value)
    }
    for (const [field, values] of this._inFilters) {
      rows = rows.filter(r => values.includes(r[field]))
    }
    if (this._orderField) {
      const f = this._orderField
      const asc = this._orderAsc
      rows.sort((a, b) => {
        const av = a[f]
        const bv = b[f]
        if (typeof av === 'number' && typeof bv === 'number') {
          return asc ? av - bv : bv - av
        }
        const as = String(av ?? '')
        const bs = String(bv ?? '')
        return asc ? as.localeCompare(bs) : bs.localeCompare(as)
      })
    }
    if (this._limit !== undefined) rows = rows.slice(0, this._limit)
    return projectFields(rows, this._fields)
  }

  // ── Terminal: single row ─────────────────────────────────────────────────

  single(): DbResult<Row | null> {
    const rows = this.execute()
    if (rows.length === 0) return Promise.resolve({ data: null, error: { message: 'Not found' } })
    return Promise.resolve({ data: rows[0], error: null })
  }

  // ── Terminal: make the builder itself awaitable (returns array) ──────────

  then<T>(
    resolve: (v: { data: Row[]; error: null }) => T,
    _reject?: (e: unknown) => T
  ): Promise<T> {
    return Promise.resolve(resolve({ data: this.execute(), error: null }))
  }

  // ── Mutations ────────────────────────────────────────────────────────────

  insert(data: Row | Row[]): InsertResult {
    const table = this.table
    if (!db[table]) db[table] = []
    const rows = (Array.isArray(data) ? data : [data]).map(row => ({
      id: uid(),
      created_at: new Date().toISOString(),
      ...row,
    }))
    db[table].push(...rows)
    return new InsertResult(rows)
  }

  update(data: Partial<Row>): UpdateBuilder {
    return new UpdateBuilder(this.table, data)
  }

  delete(): DeleteBuilder {
    return new DeleteBuilder(this.table)
  }

  upsert(data: Row, opts?: { onConflict?: string }): InsertResult {
    const table = this.table
    if (!db[table]) db[table] = []
    const conflictField = opts?.onConflict

    if (conflictField && data[conflictField] !== undefined) {
      const idx = db[table].findIndex(r => r[conflictField] === data[conflictField])
      if (idx >= 0) {
        db[table][idx] = { ...db[table][idx], ...data, updated_at: new Date().toISOString() }
        return new InsertResult([db[table][idx]])
      }
    }
    const newRow: Row = { id: uid(), created_at: new Date().toISOString(), ...data }
    db[table].push(newRow)
    return new InsertResult([newRow])
  }
}

// ─── Update builder ──────────────────────────────────────────────────────────

class UpdateBuilder {
  private _eqFilters: [string, unknown][] = []
  private _neqFilters: [string, unknown][] = []
  private _inFilters: [string, unknown[]][] = []
  private _fields = '*'
  private _selectCalled = false
  private _applied = false
  private _matched: Row[] = []

  constructor(private table: string, private data: Partial<Row>) {}

  eq(field: string, value: unknown): this {
    this._eqFilters.push([field, value])
    return this
  }

  // Matches Supabase's .neq() — required for atomic conditional updates,
  // e.g. "only flip status to running if it isn't already".
  neq(field: string, value: unknown): this {
    this._neqFilters.push([field, value])
    return this
  }

  in(field: string, values: unknown[]): this {
    this._inFilters.push([field, values])
    return this
  }

  select(fields = '*'): this {
    this._fields = fields
    this._selectCalled = true
    return this
  }

  private applyOnce() {
    if (this._applied) return
    this._applied = true
    const table = this.table
    const data = this.data
    if (!db[table]) return
    db[table] = db[table].map(row => {
      const matchesEq = this._eqFilters.every(([f, v]) => row[f] === v)
      const matchesNeq = this._neqFilters.every(([f, v]) => row[f] !== v)
      const matchesIn = this._inFilters.every(([f, vs]) => vs.includes(row[f]))
      if (matchesEq && matchesNeq && matchesIn) {
        const updated = { ...row, ...data }
        this._matched.push(updated)
        return updated
      }
      return row
    })
  }

  single(): DbResult<Row | null> {
    this.applyOnce()
    const row = this._matched[0] ?? null
    return Promise.resolve({ data: row, error: row ? null : { message: 'Not found' } })
  }

  // Mirrors Supabase: an update without .select() resolves { data: null };
  // with .select() it resolves the matched (possibly empty) rows.
  then<T>(
    resolve: (v: { data: Row[] | null; error: null }) => T,
    _reject?: (e: unknown) => T
  ): Promise<T> {
    this.applyOnce()
    const data = this._selectCalled ? projectFields(this._matched, this._fields) : null
    return Promise.resolve(resolve({ data, error: null }))
  }
}

// ─── Delete builder ──────────────────────────────────────────────────────────

class DeleteBuilder {
  private _eqFilters: [string, unknown][] = []

  constructor(private table: string) {}

  eq(field: string, value: unknown): this {
    this._eqFilters.push([field, value])
    return this
  }

  then<T>(
    resolve: (v: { error: null }) => T,
    _reject?: (e: unknown) => T
  ): Promise<T> {
    const table = this.table
    const filters = this._eqFilters
    if (db[table] && filters.length > 0) {
      db[table] = db[table].filter(row => !filters.every(([f, v]) => row[f] === v))
    }
    return Promise.resolve(resolve({ error: null }))
  }
}

// ─── Public factory ───────────────────────────────────────────────────────────

export function createLocalClient() {
  return {
    from: (table: string) => new QueryBuilder(table),
  }
}
