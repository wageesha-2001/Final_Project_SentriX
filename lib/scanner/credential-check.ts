/**
 * Authorized credential verification (ACTIVE check).
 *
 * This is the ONLY module that sends authentication traffic to a device. It must
 * only ever run against equipment the operator is explicitly authorized to audit.
 *
 * WHAT IT CHECKS
 *   For each discovered CCTV device it tests whether the device accepts:
 *     1. a known FACTORY DEFAULT credential for its exact vendor (from the
 *        Default Credentials database), then
 *     2. a common WEAK password (built-in list) for the usual admin usernames.
 *   The first accepted credential wins and testing stops.
 *
 * RESULTS (authentication_status)
 *   CONFIRMED_DEFAULT_CREDENTIALS - a factory default worked        (Critical)
 *   CONFIRMED_WEAK_PASSWORD       - a weak/common password worked   (Low)
 *   AUTHENTICATION_REJECTED       - nothing worked                  (good)
 *   NOT_TESTED                    - no interface / nothing to try
 *   AUTHENTICATION_ERROR          - timeout / lockout / service error
 *
 * SAFETY (non-negotiable)
 *   - Runs only on a REAL scan with Safe Scan Mode OFF and the check enabled.
 *   - Tries the full candidate set but STOPS IMMEDIATELY on any lockout /
 *     throttling signal (HTTP 429/403/503) so it cannot keep hammering an
 *     account. Testing many passwords can still lock out real accounts — this is
 *     an authorized-lab feature.
 *   - Reliable success signal: a protected endpoint that answers 401
 *     unauthenticated and 2xx only when a credential is accepted. A 200 login
 *     page is NOT success.
 *   - NEVER logs, stores, returns or reports a password. Only vendor + username
 *     (and whether it was a default or a weak password) are surfaced.
 *
 * Written against an injectable HTTP probe so it is unit-testable without a network.
 */
import crypto from 'crypto'
import type { AuthenticationStatus } from '@/types'

export interface StoredCredential {
  vendor: string
  username: string
  password: string
  risk_level: string
}

export interface AuthProbeResult {
  status: number
  /** WWW-Authenticate header, when the server sent a challenge. */
  wwwAuthenticate?: string
}

/** GET a path with an optional Authorization header. Resolves null on no answer. */
export type AuthProbe = (opts: {
  ip: string
  port: number
  tls: boolean
  path: string
  authorization?: string
  timeoutMs: number
}) => Promise<AuthProbeResult | null>

export interface CredCheckInput {
  ip: string
  vendor: string
  /** Open ports, to choose the management interface. */
  open_ports: { port: number; service?: string }[]
}

export interface CredCheckOutcome {
  status: AuthenticationStatus
  /** Safe-to-log explanation. Never contains a password. */
  reason: string
  /** Present only for a CONFIRMED finding; never includes the password. */
  attempted?: { vendor: string; username: string; kind: 'default' | 'weak' }
  /** How many login attempts were sent (for diagnostics; no secrets). */
  attempts: number
}

/** Common weak / easily guessed passwords (NOT vendor-specific). */
export const WEAK_PASSWORDS = [
  '12345', '123456', '1234', '12345678', '123456789', '111111', '000000',
  'password', 'admin', 'root', 'pass', 'default', '1111', '888888', '666666',
  '54321', 'admin123', '123123', 'qwerty', 'abc123',
]
/** Usernames weak passwords are tried against when the vendor list gives none. */
const FALLBACK_USERNAMES = ['admin', 'root']

/** Protected endpoints that return 401 unauthenticated on each vendor's web UI. */
const PROTECTED_PATHS: { vendor: RegExp; path: string }[] = [
  { vendor: /hikvision/i, path: '/ISAPI/Security/userCheck' },
  { vendor: /dahua|amcrest|lorex|imou/i, path: '/cgi-bin/global.cgi?action=getCurrentTime' },
  { vendor: /axis/i, path: '/axis-cgi/pwdgrp.cgi?action=get' },
  { vendor: /.*/, path: '/onvif/device_service' },
]

/** On by default for real scans; disabled whenever Safe Scan Mode is on. */
export function isCredentialCheckAllowed(safeScanMode: boolean): boolean {
  return !safeScanMode
}

/** All stored credentials for this exact vendor, highest risk first, de-duplicated. */
export function selectVendorCredentials(vendor: string, creds: StoredCredential[]): StoredCredential[] {
  const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
  const v = vendor.trim().toLowerCase()
  const seen = new Set<string>()
  return creds
    .filter(c => c.vendor.trim().toLowerCase() === v)
    .filter(c => { const k = `${c.username}\u0000${c.password}`; if (seen.has(k)) return false; seen.add(k); return true })
    .sort((a, b) =>
      (RANK[a.risk_level] ?? 9) - (RANK[b.risk_level] ?? 9) ||
      a.username.localeCompare(b.username) ||
      a.password.localeCompare(b.password))
}

function basicHeader(username: string, password: string): string {
  return 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64')
}

/** Build a single Digest (MD5, qop=auth) Authorization header from a challenge. */
function digestHeader(challenge: string, method: string, uri: string, username: string, password: string): string | null {
  const get = (k: string) => new RegExp(`${k}="?([^",]+)"?`, 'i').exec(challenge)?.[1]
  const realm = get('realm')
  const nonce = get('nonce')
  if (!realm || !nonce) return null
  const qop = get('qop')
  const opaque = get('opaque')
  const md5 = (s: string) => crypto.createHash('md5').update(s).digest('hex')
  const ha1 = md5(`${username}:${realm}:${password}`)
  const ha2 = md5(`${method}:${uri}`)
  const cnonce = crypto.randomBytes(8).toString('hex')
  const nc = '00000001'
  const response = qop ? md5(`${ha1}:${nonce}:${nc}:${cnonce}:auth:${ha2}`) : md5(`${ha1}:${nonce}:${ha2}`)
  let h = `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}"`
  if (qop) h += `, qop=auth, nc=${nc}, cnonce="${cnonce}"`
  if (opaque) h += `, opaque="${opaque}"`
  return h
}

const isAuthSuccess = (status: number) => status >= 200 && status < 300
/** Lockout / throttling / forbidden signals — stop, never keep trying. */
const isLockout = (status: number) => status === 429 || status === 403 || status === 503

/**
 * Perform an authorized credential audit against one device: all vendor default
 * credentials, then common weak passwords, stopping on the first success or any
 * lockout signal. Returns NOT_TESTED when there is nothing to try or no
 * supported management interface is reachable.
 */
export async function verifyCredentials(
  input: CredCheckInput,
  defaultCreds: StoredCredential[],
  probe: AuthProbe,
  opts: { timeoutMs?: number; weakPasswords?: string[] } = {},
): Promise<CredCheckOutcome> {
  const timeoutMs = opts.timeoutMs ?? 2500
  const weakList = opts.weakPasswords ?? WEAK_PASSWORDS
  const vendorDefaults = selectVendorCredentials(input.vendor, defaultCreds)

  const ports = new Set(input.open_ports.map(p => p.port))
  const tls = ports.has(443) ? true : ports.has(80) || ports.has(8080) ? false : null
  const port = ports.has(443) ? 443 : ports.has(80) ? 80 : ports.has(8080) ? 8080 : null
  if (tls === null || port === null) return { status: 'NOT_TESTED', reason: 'no HTTP(S) management interface open', attempts: 0 }

  const path = (PROTECTED_PATHS.find(p => p.vendor.test(input.vendor)) ?? PROTECTED_PATHS[PROTECTED_PATHS.length - 1]).path

  // 1) Unauthenticated probe: confirm this endpoint actually requires auth.
  const unauth = await probe({ ip: input.ip, port, tls, path, timeoutMs })
  if (!unauth) return { status: 'AUTHENTICATION_ERROR', reason: 'no response from management interface', attempts: 0 }
  if (isLockout(unauth.status)) return { status: 'AUTHENTICATION_ERROR', reason: `throttled (HTTP ${unauth.status})`, attempts: 0 }
  if (isAuthSuccess(unauth.status)) return { status: 'NOT_TESTED', reason: 'management endpoint does not require authentication', attempts: 0 }
  if (unauth.status !== 401) return { status: 'NOT_TESTED', reason: `unsupported auth interface (HTTP ${unauth.status})`, attempts: 0 }

  const challenge = unauth.wwwAuthenticate ?? ''
  const buildAuth = (u: string, p: string) =>
    challenge.toLowerCase().startsWith('digest') ? digestHeader(challenge, 'GET', path, u, p) : basicHeader(u, p)

  // Build the ordered candidate list: vendor defaults first, then weak passwords
  // against the admin usernames. De-duplicate identical (username,password) pairs.
  type Cand = { username: string; password: string; kind: 'default' | 'weak' }
  const tried = new Set<string>()
  const candidates: Cand[] = []
  const add = (username: string, password: string, kind: 'default' | 'weak') => {
    const key = `${username}\u0000${password}`
    if (tried.has(key)) return
    tried.add(key); candidates.push({ username, password, kind })
  }
  for (const c of vendorDefaults) add(c.username, c.password, 'default')
  const usernames = vendorDefaults.length > 0 ? Array.from(new Set(vendorDefaults.map(c => c.username))) : FALLBACK_USERNAMES
  for (const u of usernames) for (const pw of weakList) add(u, pw, 'weak')

  let attempts = 0
  for (const cand of candidates) {
    const authorization = buildAuth(cand.username, cand.password)
    if (!authorization) continue // challenge could not be built for this scheme
    attempts++
    const res = await probe({ ip: input.ip, port, tls, path, authorization, timeoutMs })
    if (!res) return { status: 'AUTHENTICATION_ERROR', reason: 'no response during verification', attempts }
    if (isLockout(res.status)) return { status: 'AUTHENTICATION_ERROR', reason: `lockout/throttle after ${attempts} attempt(s) (HTTP ${res.status})`, attempts }
    if (isAuthSuccess(res.status)) {
      return {
        status: cand.kind === 'default' ? 'CONFIRMED_DEFAULT_CREDENTIALS' : 'CONFIRMED_WEAK_PASSWORD',
        reason: cand.kind === 'default'
          ? `default credential accepted for user "${cand.username}"`
          : `weak password accepted for user "${cand.username}"`,
        attempted: { vendor: input.vendor, username: cand.username, kind: cand.kind },
        attempts,
      }
    }
    // 401 → wrong credential, keep going
  }
  return { status: 'AUTHENTICATION_REJECTED', reason: `all ${attempts} credential(s) rejected`, attempts }
}
