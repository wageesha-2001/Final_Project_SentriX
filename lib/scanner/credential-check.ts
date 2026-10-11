/**
 * Authorized default-credential verification (ACTIVE check).
 *
 * This is the ONLY module that sends authentication traffic to a device. It is
 * deliberately conservative and must only ever run against equipment the
 * operator is explicitly authorized to audit:
 *
 *   - Disabled by default. Runs only when SENTRIX_ALLOW_CRED_CHECK=1 AND the
 *     scan is not in Safe Scan Mode AND the admin-enabled check is on.
 *   - ONE verification attempt per device, using a single vendor-matched
 *     credential (the highest-risk entry for that exact vendor). It does NOT
 *     cycle through every stored password and does NOT try other vendors.
 *   - Stops immediately on lockout / throttling / service error (never retries).
 *   - Uses a reliable success signal: a protected endpoint that answers 401
 *     unauthenticated and 2xx only when the credential is accepted. A bare 200
 *     from a login page is NOT treated as success.
 *   - NEVER logs, stores, returns or reports the password. Only the vendor and
 *     username are surfaced, and only for a confirmed finding.
 *
 * It is written against an injectable HTTP probe so it is unit-testable without
 * touching a network.
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
  attempted?: { vendor: string; username: string }
}

/** Protected endpoints that return 401 unauthenticated on each vendor's web UI. */
const PROTECTED_PATHS: { vendor: RegExp; path: string }[] = [
  { vendor: /hikvision/i, path: '/ISAPI/Security/userCheck' },
  { vendor: /dahua|amcrest|lorex|imou/i, path: '/cgi-bin/global.cgi?action=getCurrentTime' },
  { vendor: /axis/i, path: '/axis-cgi/pwdgrp.cgi?action=get' },
  { vendor: /.*/, path: '/onvif/device_service' },
]

export function isCredentialCheckAllowed(safeScanMode: boolean): boolean {
  return process.env.SENTRIX_ALLOW_CRED_CHECK === '1' && !safeScanMode
}

/** Pick ONE credential for this exact vendor: highest risk first, deterministic. */
export function selectVendorCredential(vendor: string, creds: StoredCredential[]): StoredCredential | null {
  const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
  const v = vendor.trim().toLowerCase()
  const matches = creds.filter(c => c.vendor.trim().toLowerCase() === v)
  if (matches.length === 0) return null
  return [...matches].sort(
    (a, b) =>
      (RANK[a.risk_level] ?? 9) - (RANK[b.risk_level] ?? 9) ||
      a.username.localeCompare(b.username) ||
      a.password.localeCompare(b.password),
  )[0]
}

function basicHeader(username: string, password: string): string {
  return 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64')
}

/** Build a single Digest (MD5, qop=auth) Authorization header from a challenge. */
function digestHeader(
  challenge: string,
  method: string,
  uri: string,
  username: string,
  password: string,
): string | null {
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
  const response = qop
    ? md5(`${ha1}:${nonce}:${nc}:${cnonce}:auth:${ha2}`)
    : md5(`${ha1}:${nonce}:${ha2}`)
  let h = `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}"`
  if (qop) h += `, qop=auth, nc=${nc}, cnonce="${cnonce}"`
  if (opaque) h += `, opaque="${opaque}"`
  return h
}

/** A 2xx on the protected path means the credential was accepted. */
const isAuthSuccess = (status: number) => status >= 200 && status < 300
/** Lockout / throttling signals — stop, never retry. */
const isLockout = (status: number) => status === 429 || status === 503

/**
 * Perform at most ONE authorized credential verification against a device.
 * Returns NOT_TESTED when the check is not allowed, no credential exists for the
 * vendor, or no supported management interface is reachable.
 */
export async function verifyDefaultCredential(
  input: CredCheckInput,
  creds: StoredCredential[],
  probe: AuthProbe,
  opts: { timeoutMs?: number } = {},
): Promise<CredCheckOutcome> {
  const timeoutMs = opts.timeoutMs ?? 2500
  const cred = selectVendorCredential(input.vendor, creds)
  if (!cred) return { status: 'NOT_TESTED', reason: `no stored credential for vendor "${input.vendor}"` }

  const ports = new Set(input.open_ports.map(p => p.port))
  const tls = ports.has(443) ? true : ports.has(80) || ports.has(8080) ? false : null
  const port = ports.has(443) ? 443 : ports.has(80) ? 80 : ports.has(8080) ? 8080 : null
  if (tls === null || port === null) {
    return { status: 'NOT_TESTED', reason: 'no HTTP(S) management interface open' }
  }

  const path = (PROTECTED_PATHS.find(p => p.vendor.test(input.vendor)) ?? PROTECTED_PATHS[PROTECTED_PATHS.length - 1]).path

  // 1) Unauthenticated probe: establish that this endpoint actually requires auth.
  const unauth = await probe({ ip: input.ip, port, tls, path, timeoutMs })
  if (!unauth) return { status: 'AUTHENTICATION_ERROR', reason: 'no response from management interface' }
  if (isLockout(unauth.status)) return { status: 'AUTHENTICATION_ERROR', reason: `throttled (HTTP ${unauth.status})` }
  if (isAuthSuccess(unauth.status)) {
    // Endpoint open without auth → cannot conclude anything about credentials.
    return { status: 'NOT_TESTED', reason: 'management endpoint does not require authentication' }
  }
  if (unauth.status !== 401 && unauth.status !== 403) {
    return { status: 'NOT_TESTED', reason: `unsupported auth interface (HTTP ${unauth.status})` }
  }

  // 2) ONE authenticated attempt, matching the server's advertised scheme.
  const scheme = (unauth.wwwAuthenticate ?? '').toLowerCase()
  const authorization = scheme.startsWith('digest')
    ? digestHeader(unauth.wwwAuthenticate!, 'GET', path, cred.username, cred.password)
    : basicHeader(cred.username, cred.password)
  if (!authorization) return { status: 'AUTHENTICATION_ERROR', reason: 'could not build auth challenge response' }

  const authed = await probe({ ip: input.ip, port, tls, path, authorization, timeoutMs })
  if (!authed) return { status: 'AUTHENTICATION_ERROR', reason: 'no response to authenticated request' }
  if (isLockout(authed.status)) return { status: 'AUTHENTICATION_ERROR', reason: `lockout/throttle (HTTP ${authed.status})` }
  if (isAuthSuccess(authed.status)) {
    return {
      status: 'CONFIRMED_DEFAULT_CREDENTIALS',
      reason: `default credential accepted for user "${cred.username}"`,
      attempted: { vendor: cred.vendor, username: cred.username },
    }
  }
  if (authed.status === 401 || authed.status === 403) {
    return { status: 'AUTHENTICATION_REJECTED', reason: `credential rejected (HTTP ${authed.status})` }
  }
  return { status: 'AUTHENTICATION_ERROR', reason: `unexpected response (HTTP ${authed.status})` }
}
