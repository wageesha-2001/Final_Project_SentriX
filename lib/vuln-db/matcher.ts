/**
 * Community vulnerability matching engine.
 *
 * Pure and deterministic: compares an already-discovered device description
 * against stored records. It never contacts the device.
 *
 * Confidence (deliberately conservative — never overclaims):
 *   High   — vendor + exact model (or model pattern + firmware) match
 *   Medium — vendor match plus a model-pattern, firmware, port or protocol match
 *   Low    — broad match (generic record, vendor-only, device type, keyword);
 *            always presented to users as a "Potential Match"
 */
import type { CommunityVulnerability, MatchConfidence, CommunityMatchField, OpenPort } from '@/types'
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
}

/** Maximum low-confidence (Potential Match) results kept per device. */
export const MAX_LOW_CONFIDENCE_MATCHES = 3

const CONFIDENCE_RANK: Record<MatchConfidence, number> = { High: 3, Medium: 2, Low: 1 }
const WEB_MANAGEMENT_PORTS = new Set([80, 443, 8080, 8443])
const WEB_MANAGEMENT_PROTOCOLS = new Set(['http', 'https', 'http-alt'])
const ALL_FIELDS: CommunityMatchField[] = ['vendor', 'model', 'firmware', 'device_type', 'port', 'protocol', 'keyword']

const norm = (s: unknown) => String(s ?? '').trim().toLowerCase()
const normVersion = (s: string) => norm(s).replace(/^v(?=\d)/, '')
const isWildcard = (list: string[]) => list.length === 0 || list.every(x => ['*', 'any'].includes(norm(x)))
const isGenericVendor = (v: string) => /^(generic|unknown)/.test(norm(v))
// A device whose vendor could not be identified is not "aligned" with generic
// records: knowing less about a device must never produce a stronger claim.
const isGenericDevice = (v: string) => /^generic/.test(norm(v))
const EXPOSURE_CATEGORY = 'internet exposure'

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

function evaluate(device: MatchableDevice, rec: MatchableRecord): MatchResult | null {
  const fields = new Set<string>(rec.match_fields.length > 0 ? rec.match_fields : ALL_FIELDS)
  const reasons: string[] = []
  const matched: string[] = []

  // Internet exposure is only evidenced by a public address. A device scanned
  // on a private LAN shows nothing about reachability from the internet.
  if (norm(rec.category) === EXPOSURE_CATEGORY && (!device.ip_address || isPrivateIp(device.ip_address))) {
    return null
  }

  // ── Vendor ────────────────────────────────────────────────────────────────
  const vendorSpecific = !isGenericVendor(rec.vendor)
  const deviceGeneric = isGenericDevice(device.vendor)
  let vendorAligned: boolean
  if (vendorSpecific) {
    vendorAligned = norm(device.vendor) === norm(rec.vendor)
    if (!vendorAligned && fields.has('vendor')) return null
    if (vendorAligned) { matched.push('vendor'); reasons.push(`vendor ${device.vendor} matches`) }
  } else {
    vendorAligned = deviceGeneric
  }

  // ── Device type ───────────────────────────────────────────────────────────
  const typeSpecific = rec.device_type !== 'any'
  const typeKnown = norm(device.device_type) !== 'unknown' && device.device_type !== ''
  let typeHit = false
  if (typeSpecific && typeKnown && fields.has('device_type')) {
    if (norm(rec.device_type) !== norm(device.device_type)) return null
    typeHit = true
    matched.push('device_type'); reasons.push(`device type ${device.device_type} matches`)
  }

  // ── Model ─────────────────────────────────────────────────────────────────
  const modelSpecific = !isWildcard(rec.affected_models) && fields.has('model')
  let modelHit = false
  let modelExact = false
  if (modelSpecific) {
    const hit = rec.affected_models.find(m => globMatch(m, device.model))
    if (!hit) return null
    modelHit = true
    modelExact = !hit.includes('*')
    matched.push('model')
    reasons.push(modelExact ? `model ${device.model} is listed` : `model ${device.model} matches pattern ${hit}`)
  }

  // ── Firmware ──────────────────────────────────────────────────────────────
  const fwSpecific = !isWildcard(rec.affected_firmware) && fields.has('firmware')
  let fwHit = false
  if (fwSpecific) {
    const hit = rec.affected_firmware.find(f => globMatch(f, device.firmware_version, normVersion))
    if (!hit) return null
    fwHit = true
    matched.push('firmware'); reasons.push(`firmware ${device.firmware_version} matches ${hit}`)
  }

  // ── Services: ports / protocols ───────────────────────────────────────────
  const openPorts = new Set(device.open_ports.map(p => p.port))
  const protoSet = new Set([
    ...device.protocols.map(norm),
    ...device.open_ports.map(p => norm(p.service)),
  ])
  const usePorts = rec.affected_ports.length > 0 && fields.has('port')
  const useProtos = rec.affected_protocols.length > 0 && fields.has('protocol')
  const portHits = usePorts ? rec.affected_ports.filter(p => openPorts.has(p)) : []
  const protoHits = useProtos ? rec.affected_protocols.filter(p => protoSet.has(norm(p))) : []
  if ((usePorts || useProtos) && portHits.length === 0 && protoHits.length === 0) return null
  if (portHits.length > 0) { matched.push('port'); reasons.push(`open port${portHits.length > 1 ? 's' : ''} ${portHits.join(', ')} in affected ports`) }
  if (protoHits.length > 0) { matched.push('protocol'); reasons.push(`protocol ${protoHits.join(', ')} detected`) }
  const serviceHit = portHits.length > 0 || protoHits.length > 0

  // ── Keywords (never gate, only add evidence) ──────────────────────────────
  const haystack = norm([
    device.vendor, device.model, device.firmware_version,
    ...device.protocols, ...device.open_ports.map(p => p.service),
  ].join(' '))
  const kwHits = fields.has('keyword') ? rec.detection_keywords.filter(k => k && haystack.includes(norm(k))) : []
  if (kwHits.length > 0) { matched.push('keyword'); reasons.push(`keyword ${kwHits.join(', ')} observed`) }

  // ── Confidence ────────────────────────────────────────────────────────────
  let confidence: MatchConfidence
  let matchType: string
  if (vendorAligned && modelHit && (modelExact || fwHit)) {
    confidence = 'High'
    matchType = fwHit ? 'vendor_model_firmware' : 'exact_model'
  } else if (vendorAligned && (vendorSpecific || deviceGeneric) && (modelHit || fwHit || serviceHit)) {
    confidence = 'Medium'
    matchType = modelHit ? 'vendor_model_pattern' : fwHit ? 'vendor_firmware' : 'vendor_service'
  } else if (vendorSpecific && vendorAligned) {
    confidence = 'Low'
    matchType = 'vendor_only'
  } else if (typeHit || serviceHit || kwHits.length > 0) {
    // Every CCTV device has a web management interface, so a generic record
    // matching only on 80/443/8080 (HTTP/HTTPS) is no evidence of the weakness.
    const strongServiceHit =
      portHits.some(p => !WEB_MANAGEMENT_PORTS.has(p)) ||
      protoHits.some(p => !WEB_MANAGEMENT_PROTOCOLS.has(norm(p)))
    if (!strongServiceHit && kwHits.length === 0) return null // device type / web port alone is too weak
    confidence = 'Low'
    matchType = serviceHit ? 'generic_service' : 'keyword'
  } else {
    return null
  }

  const prefix = confidence === 'Low' ? 'Potential match: ' : ''
  const reason = `${prefix}${reasons.join('; ')}.`.replace(/^(.)/, c => c.toUpperCase())
  return {
    vulnerability_id: rec.id,
    category: rec.category,
    match_type: matchType,
    match_confidence: confidence,
    matched_fields: Array.from(new Set(matched)),
    matched_reason: reason,
    risk_score_added: applyConfidenceFactor(rec.risk_score, confidence),
  }
}

/**
 * Match one device against the database. To avoid scoring the same weakness
 * twice, only the strongest match per category is kept (higher confidence
 * first, then higher risk score). Results are sorted most severe first.
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
  const ranked = Array.from(byCategory.values())
    .sort((a, b) =>
      SEVERITIES.indexOf(a.rec.severity) - SEVERITIES.indexOf(b.rec.severity) ||
      b.result.risk_score_added - a.result.risk_score_added)
  // Broad "Potential Match" results are noisy: keep only the strongest few per device.
  let lowKept = 0
  return ranked
    .filter(x => x.result.match_confidence !== 'Low' || ++lowKept <= MAX_LOW_CONFIDENCE_MATCHES)
    .map(x => x.result)
}
