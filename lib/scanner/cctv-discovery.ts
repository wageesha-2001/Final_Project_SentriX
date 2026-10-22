/**
 * CCTV discovery & host classification (SIMULATION, non-intrusive).
 *
 * The scanner only audits IP CCTV equipment. Host discovery may see other
 * hosts on the network (gateway, PCs, printers, ...); those are classified
 * as non-CCTV and skipped — they are never stored or vulnerability-checked.
 *
 * IMPORTANT — this module sends NO network traffic. Every "signal" below is
 * DERIVED from the simulated service model of a host (its known open ports,
 * advertised protocols, vendor and MAC prefix). In a real deployment these
 * same signals would come from lightweight, non-destructive probes
 * (an RTSP OPTIONS request, an ONVIF WS-Discovery broadcast, a Hikvision
 * ISAPI/SADP lookup, a MAC-OUI table, etc.). The scoring is written so that
 * a live-probe layer could later feed the exact same weights — but nothing
 * here claims a probe actually ran. Evidence text is worded as "service
 * model" facts, not as live-probe results.
 */

export interface DiscoveredService {
  port: number
  service: string
  protocol: string
}

export interface DiscoveredHost {
  vendor: string
  model: string
  open_ports: DiscoveredService[]
  protocols: string[]
  /** Optional MAC (or OUI prefix) used for vendor OUI matching, when known. */
  mac_address?: string
  mac_prefix?: string
  /** Optional device-type hint from the host model, used for NVR/DVR calls. */
  device_type?: string
}

// ── Evidence vocabulary ──────────────────────────────────────────────────────

/** Ports that only CCTV equipment normally exposes. */
const CCTV_PORTS: Record<number, string> = {
  554: 'RTSP video streaming',
  8000: 'Hikvision SDK',
  37777: 'Dahua SDK',
}

/** Generic web-management ports — never CCTV evidence on their own. */
const WEB_PORTS = new Set([80, 443, 8080, 8443])

/** Protocols / services that identify video-surveillance equipment. */
const CCTV_PROTOCOLS = ['rtsp', 'onvif', 'vapix', 'hikvision-sdk', 'dahua-sdk', 'isapi', 'sadp']

/** Manufacturers whose products are dedicated video-surveillance equipment. */
const CCTV_VENDORS = [
  'hikvision', 'dahua', 'axis', 'uniview', 'hanwha', 'bosch', 'reolink',
  'amcrest', 'avigilon', 'tp-link vigi', 'vivotek', 'milestone',
]

/**
 * Static MAC-OUI → vendor table for common CCTV manufacturers.
 *
 * NOTE: this is a helpful but deliberately PARTIAL list. Large vendors own many
 * OUI blocks and sometimes reuse ODM blocks, so a MAC-OUI hit is vendor
 * *evidence*, never final proof by itself — it is weighted, then combined with
 * the other signals below.
 */
const CCTV_MAC_OUI: Record<string, string> = {
  'E8:B7:48': 'Hikvision', '44:19:B6': 'Hikvision', 'BC:AD:28': 'Hikvision', 'C0:56:E3': 'Hikvision',
  'BC:32:5F': 'Dahua', '3C:EF:8C': 'Dahua', '90:02:A9': 'Dahua', 'E0:50:8B': 'Dahua',
  'AC:CC:8E': 'Axis', '00:40:8C': 'Axis', 'B8:A4:4F': 'Axis',
  'C4:B3:01': 'Uniview', '48:EA:63': 'Uniview',
  '00:09:18': 'Hanwha', '00:16:6C': 'Hanwha',
  '00:07:5F': 'Bosch', '00:1C:44': 'Bosch',
  'EC:71:DB': 'Reolink',
  'B0:C5:54': 'Amcrest', '3C:B5:9A': 'Amcrest',
  'A4:14:37': 'TP-Link VIGI',
  '00:18:85': 'Avigilon',
  '00:02:D1': 'Vivotek',
}

// ── Public types ─────────────────────────────────────────────────────────────

export type HostClassification =
  | 'IP_CAMERA' | 'NVR' | 'DVR' | 'CCTV_DEVICE'
  | 'POSSIBLE_CCTV_DEVICE' | 'NETWORK_DEVICE' | 'UNKNOWN'

export type ClassificationConfidence = 'Low' | 'Medium' | 'High'

export interface EvidenceItem {
  /** Short machine-ish signal name, e.g. "rtsp_service". */
  signal: string
  /** Weight contributed to the classification score. */
  weight: number
  /** Human-readable note shown in the evidence list / debug output. */
  note: string
}

export interface CctvClassification {
  /** Backward-compatible: true when the host should be treated as CCTV and scanned. */
  cctv: boolean
  /** Backward-compatible: flat, de-duplicated human-readable evidence list. */
  evidence: string[]
  classification: HostClassification
  confidence: ClassificationConfidence
  /** 0–100 weighted evidence score. */
  score: number
  /** Resolved vendor (from vendor name and/or MAC OUI), or '' if unknown. */
  vendor: string
  /** One-line summary, handy for logs. */
  evidence_summary: string
  /** Full weighted breakdown, for debug output / audit detail. */
  evidence_details: EvidenceItem[]
}

/** A host must reach this score to be treated as CCTV and stored/scanned. */
export const CCTV_SCORE_THRESHOLD = 35

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Normalise a MAC or OUI to an upper-case `XX:XX:XX` prefix, or '' if unusable. */
function ouiPrefix(mac?: string): string {
  if (!mac) return ''
  const parts = mac.toUpperCase().split(/[:-]/)
  return parts.length >= 3 ? parts.slice(0, 3).join(':') : ''
}

/** Vendor evidence from a MAC OUI. Helpful but not proof — see CCTV_MAC_OUI note. */
export function matchMacOui(mac?: string): { prefix: string; vendor: string } | null {
  const prefix = ouiPrefix(mac)
  if (prefix && CCTV_MAC_OUI[prefix]) return { prefix, vendor: CCTV_MAC_OUI[prefix] }
  return null
}

function isKnownCctvVendor(vendor: string): boolean {
  const v = vendor.toLowerCase().trim()
  return CCTV_VENDORS.some(c => v === c || v.startsWith(c + ' '))
}

// ── Classification ───────────────────────────────────────────────────────────

/**
 * Classify a host from its (simulated) service model using weighted evidence.
 *
 * Evidence weights mirror a real evidence-based fingerprint:
 *   strong  — RTSP confirmed (+35), ONVIF (+35), vendor SDK/API (+25),
 *             known CCTV vendor (+40), CCTV MAC OUI (+25)
 *   medium  — SDK port open (+20), 554 open but RTSP unconfirmed (+15),
 *             several CCTV ports together (+15)
 *   weak    — generic web port alongside a strong signal (+5); generic web
 *             ports alone contribute nothing (they are not CCTV evidence).
 */
export function classifyHost(host: DiscoveredHost): CctvClassification {
  const ev: EvidenceItem[] = []
  const add = (signal: string, weight: number, note: string) => ev.push({ signal, weight, note })

  const ports = new Set(host.open_ports.map(p => p.port))
  const protocols = new Set(
    [...host.protocols, ...host.open_ports.map(p => p.service)].map(s => s.toLowerCase()),
  )

  // Vendor resolution: explicit vendor name and/or MAC OUI.
  const oui = matchMacOui(host.mac_address ?? host.mac_prefix)
  const vendorKnown = isKnownCctvVendor(host.vendor)
  const vendor = vendorKnown ? host.vendor : oui?.vendor ?? ''

  // 1) Streaming / protocol evidence (strong).
  const has554 = ports.has(554)
  const rtspConfirmed = has554 && protocols.has('rtsp')
  if (rtspConfirmed) add('rtsp_service', 35, 'RTSP service on TCP 554 (video streaming)')
  else if (has554) add('port_554_open', 15, 'TCP 554 open, RTSP not confirmed')

  const onvif = protocols.has('onvif')
  if (onvif) add('onvif_service', 35, 'ONVIF device service present')

  // Vendor SDK / HTTP-API protocols (Hikvision SDK/ISAPI, Dahua SDK, Axis VAPIX).
  const sdkProto = ['hikvision-sdk', 'dahua-sdk', 'vapix', 'isapi'].find(p => protocols.has(p))
  if (sdkProto) add('vendor_api', 25, `${sdkProto.toUpperCase()} vendor API present`)

  // 2) SDK port evidence (medium) — the port is open in the service model.
  const has8000 = ports.has(8000)
  const has37777 = ports.has(37777)
  if (has8000) add('port_8000_open', 20, 'Hikvision SDK port 8000 open')
  if (has37777) add('port_37777_open', 20, 'Dahua SDK port 37777 open')

  // Several CCTV-specific ports open together reinforce each other.
  const cctvPortCount = [has554, has8000, has37777].filter(Boolean).length
  if (cctvPortCount >= 2) add('multi_cctv_ports', 15, `${cctvPortCount} CCTV ports open together`)

  // 3) Vendor evidence (strong).
  if (vendorKnown) add('cctv_vendor', 40, `Vendor "${host.vendor}" is a CCTV manufacturer`)
  if (oui) add('mac_oui', 25, `MAC OUI ${oui.prefix} → ${oui.vendor}`)

  // 4) Generic web ports — secondary only. Count a small amount ONLY when a
  //    strong CCTV signal already exists; alone they are not CCTV evidence.
  const strongSoFar = ev.some(e => e.weight >= 25)
  const webPort = Array.from(ports).find(p => WEB_PORTS.has(p))
  if (webPort && strongSoFar) add('web_mgmt', 5, `Web management on port ${webPort} (secondary)`)

  const score = Math.min(100, ev.reduce((s, e) => s + e.weight, 0))

  // Device-type call (NVR / DVR vs camera) from the model text.
  const text = `${host.model} ${host.device_type ?? ''}`.toLowerCase()
  const isNvr = /\bnvr\b|network video recorder/.test(text)
  const isDvr = /\bdvr\b|digital video recorder/.test(text)
  const hasDeviceSignal = rtspConfirmed || onvif || !!sdkProto || !!oui || vendorKnown

  let classification: HostClassification
  let confidence: ClassificationConfidence
  if (score >= 75 && hasDeviceSignal) {
    classification = isNvr ? 'NVR' : isDvr ? 'DVR' : 'IP_CAMERA'
    confidence = 'High'
  } else if (score >= 60) {
    classification = isNvr ? 'NVR' : isDvr ? 'DVR' : 'CCTV_DEVICE'
    confidence = 'Medium'
  } else if (score >= CCTV_SCORE_THRESHOLD) {
    classification = 'POSSIBLE_CCTV_DEVICE'
    confidence = 'Low'
  } else {
    // Below the CCTV threshold: a known service port makes it a NETWORK_DEVICE,
    // otherwise there is nothing to go on.
    classification = ports.size > 0 ? 'NETWORK_DEVICE' : 'UNKNOWN'
    confidence = 'Low'
  }

  const cctv = score >= CCTV_SCORE_THRESHOLD
  const evidence = Array.from(new Set(ev.map(e => e.note)))
  const evidence_summary = `${classification} · ${confidence} · score ${score}${vendor ? ` · ${vendor}` : ''}`

  return { cctv, evidence, classification, confidence, score, vendor, evidence_summary, evidence_details: ev }
}

// ── IPv4 range helpers ───────────────────────────────────────────────────────

export function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => ((acc << 8) | (parseInt(o, 10) & 0xff)) >>> 0, 0)
}

export function intToIp(n: number): string {
  return [24, 16, 8, 0].map(s => (n >>> s) & 0xff).join('.')
}

/** Usable host addresses of a CIDR (a bare IP is treated as /32). */
export function cidrHostRange(cidr: string): { first: number; last: number } {
  const [ip, prefixStr] = cidr.trim().split('/')
  const prefix = prefixStr === undefined ? 32 : parseInt(prefixStr, 10)
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  const network = (ipToInt(ip) & mask) >>> 0
  const broadcast = (network | (~mask >>> 0)) >>> 0
  if (prefix >= 31) return { first: network, last: broadcast }
  return { first: network + 1, last: broadcast - 1 }
}

/**
 * Address of a simulated host: host number `hostNumber` inside the /24 that
 * starts the scanned range. Returns null if that address is outside the range,
 * so smaller ranges only find the devices that are actually inside them.
 */
export function simulatedHostIp(cidr: string, hostNumber: number): string | null {
  const { first, last } = cidrHostRange(cidr)
  const ip = ((first & 0xffffff00) >>> 0) + hostNumber
  return ip >= first && ip <= last ? intToIp(ip) : null
}
