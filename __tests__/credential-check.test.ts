/**
 * @jest-environment node
 *
 * Authorized credential audit: gating, multi-attempt behaviour (vendor defaults
 * then weak passwords), default vs weak classification, lockout handling, and
 * the guarantee that a password is never returned.
 */
import {
  verifyCredentials, selectVendorCredentials, isCredentialCheckAllowed,
  StoredCredential, AuthProbe, WEAK_PASSWORDS,
} from '@/lib/scanner/credential-check'

const CREDS: StoredCredential[] = [
  { vendor: 'Hikvision', username: 'admin', password: 'hik-default-a', risk_level: 'high' },
  { vendor: 'Hikvision', username: 'admin', password: 'hik-default-b', risk_level: 'critical' },
  { vendor: 'Dahua', username: 'admin', password: 'dh', risk_level: 'critical' },
]
const hik = { ip: '192.168.1.10', vendor: 'Hikvision', open_ports: [{ port: 80 }] }

/** Probe that accepts exactly ONE (Authorization header) value, else 401. */
function probeAccepting(acceptAuthContains: string | null, challenge = 'Basic realm="x"') {
  const calls: { authorization?: string }[] = []
  const probe: AuthProbe = async opts => {
    calls.push({ authorization: opts.authorization })
    if (!opts.authorization) return { status: 401, wwwAuthenticate: challenge } // unauth probe
    if (acceptAuthContains && opts.authorization.includes(acceptAuthContains)) return { status: 200 }
    return { status: 401 }
  }
  return { probe, calls }
}
const b64 = (u: string, p: string) => Buffer.from(`${u}:${p}`).toString('base64')

afterEach(() => { delete process.env.SENTRIX_ALLOW_CRED_CHECK })

describe('gating', () => {
  it('runs whenever Safe Scan Mode is off (no env flag needed)', () => {
    expect(isCredentialCheckAllowed(false)).toBe(true)
    expect(isCredentialCheckAllowed(true)).toBe(false)
  })
})

describe('selectVendorCredentials', () => {
  it('returns all entries for the exact vendor, highest risk first, de-duplicated', () => {
    const list = selectVendorCredentials('Hikvision', CREDS)
    expect(list.map(c => c.password)).toEqual(['hik-default-b', 'hik-default-a']) // critical before high
  })
  it('returns nothing for a vendor with no entries (weak list still applies later)', () => {
    expect(selectVendorCredentials('Axis', CREDS)).toEqual([])
  })
})

describe('verifyCredentials', () => {
  it('CONFIRMED_DEFAULT_CREDENTIALS when a factory default is accepted (tries defaults first)', async () => {
    const { probe, calls } = probeAccepting(b64('admin', 'hik-default-b'))
    const r = await verifyCredentials(hik, CREDS, probe)
    expect(r.status).toBe('CONFIRMED_DEFAULT_CREDENTIALS')
    expect(r.attempted).toEqual({ vendor: 'Hikvision', username: 'admin', kind: 'default' })
    expect(JSON.stringify(r)).not.toContain('hik-default-b') // never leaks the password
    expect(calls.length).toBeLessThanOrEqual(2) // unauth + first default (highest risk) accepted
  })

  it('CONFIRMED_WEAK_PASSWORD when no default works but a weak password does', async () => {
    const { probe } = probeAccepting(b64('admin', '12345')) // '12345' is in WEAK_PASSWORDS
    const r = await verifyCredentials(hik, CREDS, probe)
    expect(r.status).toBe('CONFIRMED_WEAK_PASSWORD')
    expect(r.attempted).toMatchObject({ kind: 'weak', username: 'admin' })
    expect(JSON.stringify(r)).not.toContain('12345') // weak password value not leaked
  })

  it('tries ALL vendor defaults and ALL weak passwords before rejecting', async () => {
    const { probe, calls } = probeAccepting(null) // nothing is accepted
    const r = await verifyCredentials(hik, CREDS, probe)
    expect(r.status).toBe('AUTHENTICATION_REJECTED')
    // 2 vendor defaults + (1 username x WEAK_PASSWORDS) authenticated attempts, plus 1 unauth probe
    expect(r.attempts).toBe(2 + WEAK_PASSWORDS.length)
    expect(calls.length).toBe(1 + r.attempts)
  })

  it('stops immediately on a lockout signal and does not keep trying', async () => {
    const calls: { authorization?: string }[] = []
    const probe: AuthProbe = async opts => {
      calls.push({ authorization: opts.authorization })
      if (!opts.authorization) return { status: 401, wwwAuthenticate: 'Basic realm="x"' }
      return { status: 429 } // first login attempt triggers lockout
    }
    const r = await verifyCredentials(hik, CREDS, probe)
    expect(r.status).toBe('AUTHENTICATION_ERROR')
    expect(r.attempts).toBe(1)        // stopped after the first attempt
    expect(calls.length).toBe(2)      // unauth + one attempt only
  })

  it('NOT_TESTED when the endpoint does not require authentication', async () => {
    const probe: AuthProbe = async () => ({ status: 200 })
    const r = await verifyCredentials(hik, CREDS, probe)
    expect(r.status).toBe('NOT_TESTED')
  })

  it('NOT_TESTED when there is no HTTP(S) interface', async () => {
    const probe: AuthProbe = async () => ({ status: 401 })
    const r = await verifyCredentials({ ...hik, open_ports: [{ port: 554 }] }, CREDS, probe)
    expect(r.status).toBe('NOT_TESTED')
    expect(r.attempts).toBe(0)
  })

  it('falls back to common usernames (admin/root) for a vendor with no stored defaults', async () => {
    const { probe } = probeAccepting(b64('root', '12345')) // '12345' is weak, 'root' is a fallback user
    const r = await verifyCredentials({ ...hik, vendor: 'NoSuchVendor' }, CREDS, probe)
    expect(r.status).toBe('CONFIRMED_WEAK_PASSWORD')
    expect(r.attempted).toMatchObject({ username: 'root', kind: 'weak' })
  })

  it('uses Digest when advertised and never puts the password in the header in cleartext', async () => {
    const calls: { authorization?: string }[] = []
    const probe: AuthProbe = async opts => {
      calls.push({ authorization: opts.authorization })
      if (!opts.authorization) return { status: 401, wwwAuthenticate: 'Digest realm="r", nonce="abc", qop="auth"' }
      return opts.authorization.includes('response=') ? { status: 200 } : { status: 401 }
    }
    const r = await verifyCredentials(hik, CREDS, probe)
    expect(r.status).toBe('CONFIRMED_DEFAULT_CREDENTIALS')
    expect(calls[1].authorization).toMatch(/^Digest /)
    expect(calls.some(c => (c.authorization ?? '').includes('hik-default'))).toBe(false)
  })
})
