import { createScanSchema, loginSchema, settingsSchema, credentialSchema } from '@/lib/validators/schemas'

// ── CIDR validation (Fix 5 regression test) ──────────────────────────────────

describe('createScanSchema – network_range CIDR validation', () => {
  const valid = (range: string) =>
    createScanSchema.safeParse({ scan_name: 'Test Scan', network_range: range, authorized: true })

  it('accepts a standard /24', () => {
    expect(valid('192.168.1.0/24').success).toBe(true)
  })
  it('accepts a /32 (single host)', () => {
    expect(valid('10.0.0.1/32').success).toBe(true)
  })
  it('accepts a /16 (the allowed floor)', () => {
    expect(valid('10.0.0.0/16').success).toBe(true)
  })
  it('accepts an IP without a prefix', () => {
    expect(valid('192.168.1.1').success).toBe(true)
  })

  it('rejects a /0 (entire internet) — below the allowed floor', () => {
    expect(valid('0.0.0.0/0').success).toBe(false)
  })
  it('rejects a /8 — below the allowed floor', () => {
    expect(valid('10.0.0.0/8').success).toBe(false)
  })
  it('rejects prefix > 32', () => {
    expect(valid('192.168.1.0/33').success).toBe(false)
  })
  it('rejects prefix > 99', () => {
    expect(valid('192.168.1.0/99').success).toBe(false)
  })
  it('rejects octet > 255', () => {
    expect(valid('999.999.999.0/24').success).toBe(false)
  })
  it('rejects partial IP', () => {
    expect(valid('192.168.1').success).toBe(false)
  })
  it('rejects non-numeric', () => {
    expect(valid('not-an-ip').success).toBe(false)
  })
  it('rejects empty string', () => {
    expect(valid('').success).toBe(false)
  })
})

describe('createScanSchema – authorized field', () => {
  it('rejects when authorized is false', () => {
    const result = createScanSchema.safeParse({
      scan_name: 'Test', network_range: '10.0.0.0/24', authorized: false,
    })
    expect(result.success).toBe(false)
  })
  it('rejects when authorized is missing', () => {
    const result = createScanSchema.safeParse({
      scan_name: 'Test', network_range: '10.0.0.0/24',
    })
    expect(result.success).toBe(false)
  })
})

describe('createScanSchema – scan_name', () => {
  it('rejects names shorter than 3 characters', () => {
    const r = createScanSchema.safeParse({ scan_name: 'ab', network_range: '10.0.0.0/24', authorized: true })
    expect(r.success).toBe(false)
  })
  it('rejects names longer than 100 characters', () => {
    const r = createScanSchema.safeParse({ scan_name: 'a'.repeat(101), network_range: '10.0.0.0/24', authorized: true })
    expect(r.success).toBe(false)
  })
})

// ── Login schema ──────────────────────────────────────────────────────────────

describe('loginSchema', () => {
  it('accepts valid email and password', () => {
    expect(loginSchema.safeParse({ email: 'a@b.com', password: 'secret' }).success).toBe(true)
  })
  it('rejects invalid email', () => {
    expect(loginSchema.safeParse({ email: 'not-email', password: 'secret' }).success).toBe(false)
  })
  it('rejects short password', () => {
    expect(loginSchema.safeParse({ email: 'a@b.com', password: '12345' }).success).toBe(false)
  })
})

// ── Settings schema ───────────────────────────────────────────────────────────

describe('settingsSchema', () => {
  const base = { safe_scan_mode: true, scan_timeout: 300, login_attempt_limit: 5 }
  it('accepts valid settings', () => {
    expect(settingsSchema.safeParse(base).success).toBe(true)
  })
  it('rejects scan_timeout below 60', () => {
    expect(settingsSchema.safeParse({ ...base, scan_timeout: 59 }).success).toBe(false)
  })
  it('rejects scan_timeout above 3600', () => {
    expect(settingsSchema.safeParse({ ...base, scan_timeout: 3601 }).success).toBe(false)
  })
  it('rejects login_attempt_limit below 3', () => {
    expect(settingsSchema.safeParse({ ...base, login_attempt_limit: 2 }).success).toBe(false)
  })
  it('rejects login_attempt_limit above 20', () => {
    expect(settingsSchema.safeParse({ ...base, login_attempt_limit: 21 }).success).toBe(false)
  })
})

// ── Credential schema ─────────────────────────────────────────────────────────

describe('credentialSchema', () => {
  it('accepts a valid credential', () => {
    const r = credentialSchema.safeParse({ vendor: 'Hikvision', username: 'admin', password: 'admin', risk_level: 'critical' })
    expect(r.success).toBe(true)
  })
  it('rejects missing vendor', () => {
    expect(credentialSchema.safeParse({ vendor: '', username: 'admin', password: '', risk_level: 'critical' }).success).toBe(false)
  })
  it('rejects invalid risk_level', () => {
    expect(credentialSchema.safeParse({ vendor: 'X', username: 'u', password: 'p', risk_level: 'unknown' }).success).toBe(false)
  })
})
