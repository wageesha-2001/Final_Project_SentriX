/**
 * Community vulnerability matching engine.
 *
 * Pure and deterministic: compares an already-discovered device description
 * against records loaded from data/vulnerabilities.txt. It never contacts the
 * device and never invents records.
 *
 * MATCHING RULE (authoritative — see also the header of vulnerabilities.txt):
 *   A record applies to a device only when the device's EXACT model is listed
 *   in the record's Models AND the firmware is consistent with the record's
 *   Firmware. Records with `Models: *` or a series/wildcard pattern (e.g.
 *   DS-2CD2*) never match: they say nothing about one specific model, and a
 *   vendor/port/protocol signal alone is not evidence of a known vulnerability.
 *
 *   Confirmed (High)   — exact model listed AND (firmware is `*` OR the device's
 *                        known firmware matches the record's firmware range).
 *   Unverified (Low)   — exact model listed, the record names a specific firmware
 *                        range, but the device's firmware is Unknown so the range
 *                        cannot be checked. Reported as a potential match, never
 *                        counted as a confirmed vulnerability.
 *   No match           — anything else (different/absent model, firmware known to
 *                        be outside the range, different vendor or device type).
 */
import type { CommunityVulnerability, MatchConfidence, OpenPort } from '@/types'
import { CONFIDENCE_FACTOR, SEVERITIES } from './constants'

export interface MatchableDevice {
  vendor: string
  model: string
  firmware_version: string
  device_type: string
  open_ports: OpenPort[]
  protocols: string[]
  /** Address the device was scanned at; used for exposure evidence. */
  ip_address?: string
}

export type MatchableRecord = Pick<
  CommunityVulnerability,
  'id' | 'vendor' | 'affected_models' | 'affected_firmware' | 'device_type' | 'category' | 'severity' |
  'risk_score' | 'affected_ports' | 'affected_protocols' | 'detection_keywords' | 'match_fields'
>

export interface MatchResult {
  vulnerability_id: string
  category: string
  match_type: string
  match_confidence: MatchConfidence
  matched_fields: string[]
  matched_reason: string
  risk_score_added: number
  /** True only for a confirmed (model + firmware) match; false for unverified. */
  confirmed: boolean
}

const CONFIDENCE_RANK: Record<MatchConfidence, number> = { High: 3, Medium: 2, Low: 1 }
const EXPOSURE_CATEGORY = 'internet exposure'

const norm = (s: unknown) => String(s ?? '').trim().toLowerCase()
const normVersion = (s: string) => norm(s).replace(/^v(?=\d)/, '')
const isUnknown = (s: string) => { const v = norm(s); return v === '' || v === 'unknown' }
const isWildcard = (list: string[]) => list.length === 0 || list.every(x => ['*', 'any'].includes(norm(x)))
/** A record vendor of "", "any" or "Generic…"/"Unknown…" applies to any vendor (the model still pins the device). */
const isGenericVendor = (v: string) => { const n = norm(v); return n === '' || n === 'any' || /^(generic|unknown)/.test(n) }

/** RFC1918, loopback, link-local and CGNAT addresses are not internet-reachable. */
export function isPrivateIp(ip: string): boolean {
  const o = ip.trim().split('.').map(Number)
  if (o.length !== 4 || o.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true
  const [a, b] = o
  return a === 10 || a === 127 || a === 0 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
}

/** Case-insensitive glob where '*' matches any run of characters. */
export function globMatch(pattern: string, value: string, normalize: (s: string) => string = norm): boolean {
  const p = normalize(pattern)
  const v = normalize(value)
  if (!p.includes('*')) return p === v
  const re = new RegExp('^' + p.split('*').map(s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$')
  return re.test(v)
}

export function applyConfidenceFactor(riskScore: number, confidence: MatchConfidence): number {
  return Math.round(riskScore * CONFIDENCE_FACTOR[confidence])
}

/** True when the device's exact model appears in the record's model list (no patterns). */
function modelIsListed(rec: MatchableRecord, model: string): boolean {
  if (isUnknown(model)) return false
  return rec.affected_models.some(m => !m.includes('*') && norm(m) !== 'any' && norm(m) === norm(model))
}

function evaluate(device: MatchableDevice, rec: MatchableRecord): MatchResult | null {
  const reasons: string[] = []
  const matched: string[] = []

  // Internet exposure is only evidenced by a public address. A device scanned
  // on a private LAN shows nothing about reachability from the internet.
  if (norm(rec.category) === EXPOSURE_CATEGORY && (!device.ip_address || isPrivateIp(device.ip_address))) {
    return null
  }

  // ── Vendor: if the record names a vendor and the device's vendor is known and
  //    different, the record does not apply. (An Unknown device vendor does not
  //    block a model match — the model is the authoritative key.) ──────────────
  if (!isGenericVendor(rec.vendor) && !isUnknown(device.vendor)) {
    if (norm(device.vendor) !== norm(rec.vendor)) return null
    matched.push('vendor'); reasons.push(`vendor ${device.vendor} matches`)
  }

  // ── Device type: a specific record type must agree with a known device type ─
  if (rec.device_type !== 'any' && !isUnknown(device.device_type)) {
    if (norm(rec.device_type) !== norm(device.device_type)) return null
    matched.push('device_type'); reasons.push(`device type ${device.device_type} matches`)
  }

  // ── Model (REQUIRED): the device's exact model must be listed. ──────────────
  if (!modelIsListed(rec, device.model)) return null
  matched.push('model'); reasons.push(`model ${device.model} is listed`)

  // ── Firmware ───────────────────────────────────────────────────────────────
  let confirmed: boolean
  if (isWildcard(rec.affected_firmware)) {
    confirmed = true
    reasons.push('all firmware versions affected')
  } else if (!isUnknown(device.firmware_version)) {
    const hit = rec.affected_firmware.find(f => globMatch(f, device.firmware_version, normVersion))
    if (!hit) return null // firmware known and outside the affected range → no match
    confirmed = true
    matched.push('firmware'); reasons.push(`firmware ${device.firmware_version} matches ${hit}`)
  } else {
    // Model listed, specific firmware range, but device firmware is Unknown:
    // cannot confirm → report as an unverified potential match.
    confirmed = false
    reasons.push(`firmware unknown; affected range ${rec.affected_firmware.join(', ')} could not be verified`)
  }

  const confidence: MatchConfidence = confirmed ? 'High' : 'Low'
  const matchType = confirmed
    ? (matched.includes('firmware') ? 'vendor_model_firmware' : 'exact_model')
    : 'unverified_firmware'
  const prefix = confirmed ? '' : 'Potential match (unverified firmware): '
  const reason = `${prefix}${reasons.join('; ')}.`.replace(/^(.)/, c => c.toUpperCase())

  return {
    vulnerability_id: rec.id,
    category: rec.category,
    match_type: matchType,
    match_confidence: confidence,
    matched_fields: Array.from(new Set(matched)),
    matched_reason: reason,
    risk_score_added: confirmed ? applyConfidenceFactor(rec.risk_score, confidence) : 0,
    confirmed,
  }
}

/**
 * Match one device against the database. To avoid scoring the same weakness
 * twice, only the strongest match per category is kept (confirmed over
 * unverified, then higher risk score). Results are sorted most severe first.
 * Records are de-duplicated by category.
 */
export function matchDevice(device: MatchableDevice, records: MatchableRecord[]): MatchResult[] {
  const byCategory = new Map<string, { result: MatchResult; rec: MatchableRecord }>()
  for (const rec of records) {
    const result = evaluate(device, rec)
    if (!result) continue
    const current = byCategory.get(rec.category)
    if (
      !current ||
      CONFIDENCE_RANK[result.match_confidence] > CONFIDENCE_RANK[current.result.match_confidence] ||
      (result.match_confidence === current.result.match_confidence && rec.risk_score > current.rec.risk_score)
    ) {
      byCategory.set(rec.category, { result, rec })
    }
  }
  return Array.from(byCategory.values())
    .sort((a, b) =>
      SEVERITIES.indexOf(a.rec.severity) - SEVERITIES.indexOf(b.rec.severity) ||
      b.result.risk_score_added - a.result.risk_score_added)
    .map(x => x.result)
}

/** Known-vulnerability status for a device, from its matches. */
export function knownVulnerabilityStatus(matches: MatchResult[]): 'MATCHED' | 'NO_MATCH' | 'UNVERIFIED' {
  if (matches.some(m => m.confirmed)) return 'MATCHED'
  if (matches.length > 0) return 'UNVERIFIED'
  return 'NO_MATCH'
}
