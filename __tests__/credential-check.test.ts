/**
 * @jest-environment node
 *
 * Authorized default-credential verification: gating, single-attempt behaviour,
 * reliable success signal, lockout handling, and the guarantee that a password
 * is never returned.
 */
import {
  verifyDefaultCredential, selectVendorCredential, isCredentialCheckAllowed,
  StoredCredential, AuthProbe,
} from '@/lib/scanner/credential-check'

const CREDS: StoredCredential[] = [
  { vendor: 'Hikvision', username: 'admin', password: 'low-pw', risk_level: 'high' },
  { vendor: 'Hikvision', username: 'admin', password: 'top-pw', risk_level: 'critical' },
  { vendor: 'Dahua', username: 'admin', password: 'dh', risk_level: 'critical' },
]
const hik = { ip: '192.168.1.10', vendor: 'Hikvision', open_ports: [{ port: 80 }] }

/** A scripted probe: returns queued responses and records how many calls happened. */
function scriptedProbe(responses: ({ status: number; wwwAuthenticate?: string } | null)[]) {
  const calls: { authorization?: string }[] = []
  const probe: AuthProbe = async opts => { calls.push({ authorization: opts.authorization }); return responses[calls.length - 1] ?? null }
  return { probe, calls }
}

afterEach(() => { delete process.env.SENTRIX_ALLOW_CRED_CHECK })

describe('gating', () => {
  it('is not allowed unless the env flag is set and Safe Scan Mode is off', () => {
    expect(isCredentialCheckAllowed(false)).toBe(false)
    process.env.SENTRIX_ALLOW_CRED_CHECK = '1'
    expect(isCredentialCheckAllowed(true)).toBe(false)   // safe mode on
    expect(isCredentialCheckAllowed(false)).toBe(true)
  })
})

describe('selectVendorCredential', () => {
  it('picks exactly one credential, highest risk, for the matching vendor only', () => {
    const c = selectVendorCredential('Hikvision', CREDS)
    expect(c).toMatchObject({ vendor: 'Hikvision', risk_level: 'critical' })
  })
  it('returns null for a vendor with no stored credential (no cross-vendor attempts)', () => {
    expect(selectVendorCredential('Axis', CREDS)).toBeNull()
  })
})

describe('verifyDefaultCredential', () => {
  it('NOT_TESTED when no credential exists for the vendor', async () => {
    const { probe, calls } = scriptedProbe([])
    const r = await verifyDefaultCredential({ ...hik, vendor: 'Axis' }, CREDS, probe)
    expect(r.status).toBe('NOT_TESTED')
    expect(calls).toHaveLength(0) // no traffic at all
  })

  it('CONFIRMED when a protected 401 endpoint returns 2xx after one authenticated attempt', async () => {
    const { probe, calls } = scriptedProbe([
      { status: 401, wwwAuthenticate: 'Basic realm="x"' }, // unauth → requires auth
      { status: 200 },                                     // authed → accepted
    ])
    const r = await verifyDefaultCredential(hik, CREDS, probe)
    expect(r.status).toBe('CONFIRMED_DEFAULT_CREDENTIALS')
    expect(calls).toHaveLength(2)             // exactly one authenticated attempt
    expect(calls[1].authorization).toMatch(/^Basic /)
    expect(r.attempted).toEqual({ vendor: 'Hikvision', username: 'admin' })
    // The password is never surfaced anywhere in the outcome.
    expect(JSON.stringify(r)).not.toContain('top-pw')
    expect(JSON.stringify(r)).not.toContain('low-pw')
  })

  it('AUTHENTICATION_REJECTED when the authenticated attempt is still 401', async () => {
    const { probe, calls } = scriptedProbe([
      { status: 401, wwwAuthenticate: 'Basic realm="x"' },
      { status: 401 },
    ])
    const r = await verifyDefaultCredential(hik, CREDS, probe)
    expect(r.status).toBe('AUTHENTICATION_REJECTED')
    expect(calls).toHaveLength(2)
  })

  it('stops on lockout/throttle without attempting a login', async () => {
    const { probe, calls } = scriptedProbe([{ status: 429 }])
    const r = await verifyDefaultCredential(hik, CREDS, probe)
    expect(r.status).toBe('AUTHENTICATION_ERROR')
    expect(calls).toHaveLength(1) // never sent the credential
  })

  it('NOT_TESTED when the endpoint does not require authentication', async () => {
    const { probe } = scriptedProbe([{ status: 200 }]) // open without auth
    const r = await verifyDefaultCredential(hik, CREDS, probe)
    expect(r.status).toBe('NOT_TESTED')
  })

  it('AUTHENTICATION_ERROR when there is no response', async () => {
    const { probe } = scriptedProbe([null])
    const r = await verifyDefaultCredential(hik, CREDS, probe)
    expect(r.status).toBe('AUTHENTICATION_ERROR')
  })

  it('uses Digest when the server advertises it, still one attempt', async () => {
    const { probe, calls } = scriptedProbe([
      { status: 401, wwwAuthenticate: 'Digest realm="r", nonce="abc", qop="auth"' },
      { status: 200 },
    ])
    const r = await verifyDefaultCredential(hik, CREDS, probe)
    expect(r.status).toBe('CONFIRMED_DEFAULT_CREDENTIALS')
    expect(calls[1].authorization).toMatch(/^Digest /)
    expect(calls[1].authorization).not.toContain('top-pw') // password never sent in cleartext header
  })
})
