import { z } from 'zod'

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
})

// Minimum CIDR prefix a scan is allowed to target — anything broader (a /8,
// a /0) isn't a legitimate CCTV-network audit target and this scanner has no
// per-target authorization/denylist, so it's rejected outright rather than
// relying on the scan engine to bound it.
const MIN_CIDR_PREFIX = 16

function isValidCidr(value: string): boolean {
  const parts = value.split('/')
  if (parts.length > 2) return false
  const octets = parts[0].split('.')
  if (octets.length !== 4) return false
  if (!octets.every(o => /^\d{1,3}$/.test(o) && parseInt(o, 10) <= 255)) return false
  if (parts.length === 2) {
    const prefix = parseInt(parts[1], 10)
    if (!/^\d{1,2}$/.test(parts[1]) || prefix < MIN_CIDR_PREFIX || prefix > 32) return false
  }
  return true
}

export const createScanSchema = z.object({
  scan_name: z.string().min(3, 'Scan name must be at least 3 characters').max(100),
  network_range: z.string().refine(isValidCidr, {
    message: `Invalid network range. Use a valid IPv4 CIDR like 192.168.1.0/24 (prefix ${MIN_CIDR_PREFIX}–32)`,
  }),
  authorized: z.literal(true, {
    errorMap: () => ({ message: 'You must confirm authorization to scan this network' })
  }),
})

export const settingsSchema = z.object({
  safe_scan_mode: z.boolean(),
  scan_timeout: z.number().min(60).max(3600),
  login_attempt_limit: z.number().min(3).max(20),
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
