import { z } from 'zod'

export const loginSchema = z.object({
  email: z.string().trim().email('Invalid email address').max(254),
  password: z.string().min(6, 'Password must be at least 6 characters').max(200),
})

/**
 * bcrypt only uses the first 72 bytes of a password; anything after that is
 * silently ignored, so longer passwords are rejected instead of truncated.
 */
export const BCRYPT_MAX_BYTES = 72
export const byteLength = (s: string) => new TextEncoder().encode(s).length

export const passwordPolicy = z.string()
  .min(10, 'Password must be at least 10 characters')
  .refine(p => byteLength(p) <= BCRYPT_MAX_BYTES, `Password must be at most ${BCRYPT_MAX_BYTES} bytes`)
  .refine(p => /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p),
    'Password must contain upper- and lower-case letters, a number and a symbol')

export const createUserSchema = z.object({
  name: z.string().trim().min(2, 'Name must be at least 2 characters').max(100, 'Name must be at most 100 characters'),
  email: z.string().trim().email('Invalid email').max(254, 'Email must be at most 254 characters'),
  password: passwordPolicy,
  role: z.enum(['admin', 'technician']),
})

// Minimum CIDR prefix a scan is allowed to target — anything broader (a /8,
// a /0) isn't a legitimate CCTV-network audit target and this scanner has no
// per-target authorization/denylist, so it's rejected outright rather than
// relying on the scan engine to bound it.
const MIN_CIDR_PREFIX = 16

// First octets that can never be a CCTV network to audit: "this network" (0),
// loopback (127), and multicast/reserved (224 and above).
const UNSCANNABLE_FIRST_OCTET = (o: number) => o === 0 || o === 127 || o >= 224

function isValidCidr(value: string): boolean {
  const parts = value.trim().split('/')
  if (parts.length > 2) return false
  const octets = parts[0].split('.')
  if (octets.length !== 4) return false
  // No leading zeros ("070" is octal in some tools, decimal in others)
  if (!octets.every(o => /^(0|[1-9]\d{0,2})$/.test(o) && parseInt(o, 10) <= 255)) return false
  if (UNSCANNABLE_FIRST_OCTET(parseInt(octets[0], 10))) return false
  if (parts.length === 2) {
    const prefix = parseInt(parts[1], 10)
    if (!/^\d{1,2}$/.test(parts[1]) || prefix < MIN_CIDR_PREFIX || prefix > 32) return false
  }
  return true
}

/**
 * Store the range that will really be scanned: host bits are cleared, so
 * "192.168.70.60/16" is saved (and shown) as "192.168.0.0/16".
 */
export function normalizeCidr(value: string): string {
  const [ip, prefixStr] = value.trim().split('/')
  if (prefixStr === undefined) return ip
  const prefix = parseInt(prefixStr, 10)
  const n = ip.split('.').reduce((acc, o) => (acc * 256) + parseInt(o, 10), 0)
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0
  const net = (n & mask) >>> 0
  return `${[24, 16, 8, 0].map(sh => (net >>> sh) & 255).join('.')}/${prefix}`
}

export const createScanSchema = z.object({
  scan_name: z.string().trim().min(3, 'Scan name must be at least 3 characters').max(100),
  network_range: z.string().refine(isValidCidr, {
    message: `Invalid network range. Use a valid IPv4 CIDR like 192.168.1.0/24 (prefix ${MIN_CIDR_PREFIX}–32)`,
  }).transform(normalizeCidr),
  authorized: z.literal(true, {
    errorMap: () => ({ message: 'You must confirm authorization to scan this network' })
  }),
})

export const settingsSchema = z.object({
  safe_scan_mode: z.boolean(),
  scan_timeout: z.number({ invalid_type_error: 'Scan timeout is required' })
    .int('Scan timeout must be a whole number').min(60, 'Scan timeout must be at least 60 seconds').max(3600, 'Scan timeout must be at most 3600 seconds'),
  login_attempt_limit: z.number({ invalid_type_error: 'Login attempt limit is required' })
    .int('Login attempt limit must be a whole number').min(3, 'Login attempt limit must be at least 3').max(20, 'Login attempt limit must be at most 20'),
})

export const credentialSchema = z.object({
  vendor: z.string().min(1, 'Vendor is required'),
  username: z.string(),
  password: z.string(),
  risk_level: z.enum(['low', 'medium', 'high', 'critical']),
})

export type LoginInput = z.infer<typeof loginSchema>
export type CreateScanInput = z.infer<typeof createScanSchema>
export type SettingsInput = z.infer<typeof settingsSchema>
export type CredentialInput = z.infer<typeof credentialSchema>
