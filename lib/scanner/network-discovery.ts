/**
 * Real, NON-DESTRUCTIVE network discovery for IP CCTV equipment.
 *
 * This module sends real traffic, so it must only run against networks the
 * operator is authorized to audit (enforced by the "authorized" flag on scan
 * creation). Everything here is lightweight and read-only:
 *   - TCP connect() to see which ports answer (no payload)
 *   - one RTSP OPTIONS request (protocol check, no stream opened)
 *   - unauthenticated HTTP GETs that read status + headers only
 * There is NO credential guessing, NO brute force and NO exploit traffic.
 * A 401/403 from a vendor endpoint is treated as positive *existence* evidence,
 * never as something to bypass.
 *
 * Honest limitations (documented so results are not mis-read):
 *   - MAC address and SADP/ONVIF multicast only work on the SAME L2 segment.
 *     A routed subnet (scanned via a gateway) will usually have no MAC and no
 *     multicast reply — that is a network fact, not a failure.
 *   - Exact model / firmware on Hikvision needs an authenticated ISAPI call,
 *     which we do not perform. Those fields stay "Unknown" when a device does
 *     not expose them without login.
 */

import net from 'net'
import http from 'http'
import https from 'https'
import { cidrHostRange, intToIp, DiscoveredHost } from './cctv-discovery'

/** Ports worth checking: CCTV-specific plus a few generic ones for triage. */
const SCAN_PORTS: { port: number; service: string }[] = [
  { port: 23, service: 'Telnet' },
  { port: 80, service: 'HTTP' },
  { port: 443, service: 'HTTPS' },
  { port: 554, service: 'RTSP' },
  { port: 8000, service: 'SDK' },
  { port: 8080, service: 'HTTP-ALT' },
  { port: 37777, service: 'Dahua-SDK' },
]

export interface DiscoveryOptions {
  connectTimeoutMs?: number
  readTimeoutMs?: number
  concurrency?: number
  /** Called after each host is swept, for progress reporting (0..1). */
  onProgress?: (done: number, total: number) => void | Promise<void>
  /** Return true to abort early (e.g. the scan was stopped). */
  shouldStop?: () => boolean | Promise<boolean>
}

export interface RealDiscoveredHost extends DiscoveredHost {
  ip_address: string
  mac_address: string
  firmware_version: string
  device_type: 'camera' | 'nvr' | 'dvr' | 'router' | 'unknown'
  /** Response signals, kept for evidence/debug. */
  http_server?: string
  missing_security_headers?: boolean
  rtsp_confirmed?: boolean
  vendor_endpoints?: { path: string; status: number }[]
}

// ── Low-level probes ─────────────────────────────────────────────────────────

/** TCP connect check. Resolves true if the port accepts a connection. */
export function probeTcpPort(ip: string, port: number, timeoutMs = 600): Promise<boolean> {
  return new Promise(resolve => {
    const socket = new net.Socket()
    let done = false
    const finish = (open: boolean) => {
      if (done) return
      done = true
      socket.destroy()
      resolve(open)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(true))
    socket.once('timeout', () => finish(false))
    socket.once('error', () => finish(false))
    socket.connect(port, ip)
  })
}

/** One RTSP OPTIONS request. Any RTSP/1.0 status line (incl. 401) confirms RTSP. */
export function probeRtspOptions(ip: string, timeoutMs = 1200): Promise<{ confirmed: boolean; status?: number }> {
  return new Promise(resolve => {
    const socket = new net.Socket()
    let data = ''
    let done = false
    const finish = (confirmed: boolean, status?: number) => {
      if (done) return
      done = true
      socket.destroy()
      resolve({ confirmed, status })
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => {
      socket.write(`OPTIONS rtsp://${ip}:554/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: SentriX-Audit\r\n\r\n`)
    })
    socket.on('data', chunk => {
      data += chunk.toString('latin1')
      const m = /^RTSP\/1\.0\s+(\d{3})/.exec(data)
      if (m) finish(true, parseInt(m[1], 10))
      else if (data.length > 2048) finish(false)
    })
    socket.once('timeout', () => finish(false))
    socket.once('error', () => finish(false))
    socket.connect(554, ip)
  })
}

interface HttpResult { status: number; headers: Record<string, string | string[] | undefined>; body: string }

/** Unauthenticated HTTP(S) GET. Reads status + headers and a small body slice. */
export function probeHttp(ip: string, port: number, tls: boolean, path = '/', timeoutMs = 1500): Promise<HttpResult | null> {
  return new Promise(resolve => {
    const lib = tls ? https : http
    const req = lib.request(
      {
        host: ip, port, path, method: 'GET', timeout: timeoutMs,
        rejectUnauthorized: false, // self-signed device certs are normal
        headers: { 'User-Agent': 'SentriX-Audit', Accept: '*/*' },
      },
      res => {
        let body = ''
        res.on('data', c => { if (body.length < 4096) body += c.toString('utf8') })
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }))
      },
    )
    req.once('error', () => resolve(null))
    req.once('timeout', () => { req.destroy(); resolve(null) })
    req.end()
  })
}

/** probeHttp with one retry (longer timeout) when the request got no answer at all. */
async function probeHttpRetry(ip: string, port: number, tls: boolean, path: string, timeoutMs: number): Promise<HttpResult | null> {
  return (await probeHttp(ip, port, tls, path, timeoutMs)) ?? probeHttp(ip, port, tls, path, timeoutMs * 2)
}

// ── Fingerprinting ───────────────────────────────────────────────────────────

/** Map an HTTP Server header to a vendor. Embedded servers are weak hints. */
export function vendorFromServerHeader(server: string): { vendor: string; strong: boolean } | null {
  const s = server.toLowerCase()
  if (s.includes('app-webs') || s.includes('hikvision') || s.includes('dvrdvs')) return { vendor: 'Hikvision', strong: true }
  if (s.includes('dahua') || s.includes('webs') && s.includes('dh')) return { vendor: 'Dahua', strong: true }
  if (s.includes('uc-httpd')) return { vendor: 'Generic IP Camera', strong: false } // Xiongmai-family ODM
  if (s.includes('boa') || s.includes('goahead') || s.includes('thttpd') || s.includes('rompager') || s.includes('lighttpd'))
    return { vendor: 'Embedded Device', strong: false }
  return null
}

/** Unauthenticated vendor endpoints. 200/401/403 = endpoint exists (evidence). */
const VENDOR_PATHS: { vendor: string; path: string }[] = [
  // Hikvision login page leaks model + web version WITHOUT auth (read-only).
  { vendor: 'Hikvision', path: '/doc/page/login.asp' },
  { vendor: 'Hikvision', path: '/ISAPI/System/deviceInfo' },
  { vendor: 'Hikvision', path: '/SDK/webLanguage' },
  { vendor: 'Dahua', path: '/cgi-bin/magicBox.cgi?action=getSystemInfo' },
  { vendor: 'Axis', path: '/axis-cgi/param.cgi?action=list&group=Brand' },
  { vendor: 'Generic', path: '/onvif/device_service' },
]

/**
 * Device type from a model string. Handles Hikvision naming (e.g. DS-7608NI = NVR,
 * DS-2CD/DS-2DE = camera) plus generic NVR/DVR keywords. Returns "unknown" when
 * the model is unavailable rather than guessing camera-vs-recorder.
 */
const DEVICE_TYPE_FROM_MODEL = (model: string): RealDiscoveredHost['device_type'] => {
  const m = model.toLowerCase().trim()
  if (!m || m === 'unknown') return 'unknown'
  // Hikvision recorders: DS-7xxx / DS-8xxx / DS-9xxx with an "NI" (network) family.
  if (/ds-[789]\d{2,3}\w*ni/.test(m) || /\bnvr\b|network video recorder/.test(m)) return 'nvr'
  // Hikvision Turbo-HD recorders (HGHI/HQHI/HUHI/HTHI) are DVRs.
  if (/ds-[789]\d{2,3}\w*(hghi|hqhi|huhi|hthi)/.test(m) || /\bdvr\b|digital video recorder/.test(m)) return 'dvr'
  // Hikvision cameras (DS-2CD fixed, DS-2DE/DS-2DF PTZ) and generic IPC.
  if (/ds-2cd|ds-2de|ds-2df|\bipc\b|camera/.test(m)) return 'camera'
  return 'camera'
}

/** Fingerprint a single live host from its open ports (read-only probes). */
export async function fingerprintHost(
  ip: string,
  openPorts: { port: number; service: string }[],
  opts: DiscoveryOptions = {},
): Promise<RealDiscoveredHost> {
  const readTimeout = opts.readTimeoutMs ?? 1500
  const ports = new Set(openPorts.map(p => p.port))
  const protocols = new Set<string>()
  const vendorEndpoints: { path: string; status: number }[] = []
  let vendor = ''
  let vendorStrong = false
  let model = ''
  let firmware = ''
  let httpServer = ''
  let missingHeaders: boolean | undefined

  // RTSP
  let rtspConfirmed = false
  if (ports.has(554)) {
    let rtsp = await probeRtspOptions(ip, readTimeout)
    if (!rtsp.confirmed) rtsp = await probeRtspOptions(ip, readTimeout * 2)
    rtspConfirmed = rtsp.confirmed
    if (rtsp.confirmed) protocols.add('RTSP')
  }

  // HTTP / HTTPS root
  const webPort = ports.has(80) ? 80 : ports.has(8080) ? 8080 : null
  const tlsPort = ports.has(443) ? 443 : ports.has(8443) ? 8443 : null
  const root = tlsPort
    ? await probeHttpRetry(ip, tlsPort, true, '/', readTimeout)
    : webPort
      ? await probeHttpRetry(ip, webPort, false, '/', readTimeout)
      : null
  let headerFirmware = ''
  if (root) {
    httpServer = String(root.headers['server'] ?? '')
    const v = vendorFromServerHeader(httpServer)
    if (v) { vendor = v.vendor; vendorStrong = v.strong }
    // Some Hikvision firmware advertises the version in a response header (unauth).
    const xfw = root.headers['x-firmware-version']
    if (xfw) headerFirmware = String(Array.isArray(xfw) ? xfw[0] : xfw).trim()
    // Security-header hygiene (read-only)
    const h = root.headers
    missingHeaders = !h['strict-transport-security'] && !h['x-frame-options'] && !h['content-security-policy']
  }

  // Vendor endpoints (status only; parse body on 200)
  if (webPort || tlsPort) {
    const usePort = (tlsPort ?? webPort) as number
    const useTls = !!tlsPort
    for (const vp of VENDOR_PATHS) {
      if (await maybeStop(opts)) break
      const res = await probeHttpRetry(ip, usePort, useTls, vp.path, readTimeout)
      if (res && [200, 401, 403].includes(res.status)) {
        vendorEndpoints.push({ path: vp.path, status: res.status })
        if (vp.vendor === 'Hikvision') { vendor ||= 'Hikvision'; vendorStrong = true; protocols.add('ISAPI') }
        if (vp.vendor === 'Dahua') { vendor ||= 'Dahua'; vendorStrong = true; protocols.add('Dahua-SDK') }
        if (vp.vendor === 'Axis') { vendor ||= 'Axis'; vendorStrong = true; protocols.add('VAPIX') }
        if (vp.vendor === 'Generic') protocols.add('ONVIF')
        // Only unauthenticated 200 bodies are parsed for identity.
        if (res.status === 200) {
          const parsed = parseIdentity(vp.vendor, res.body)
          model ||= parsed.model
          firmware ||= parsed.firmware
          if (parsed.vendor) { vendor = parsed.vendor; vendorStrong = true }
        }
      }
    }
  }

  // Fall back to the firmware advertised in the response header.
  if (!firmware && headerFirmware) firmware = headerFirmware

  const device_type = DEVICE_TYPE_FROM_MODEL(model)
  const open_ports = openPorts.map(p => ({ port: p.port, service: p.service, protocol: 'tcp' }))
  // An open 8000/37777 is weighed by classifyHost as a port signal only. It is NOT
  // added as a vendor-SDK protocol: many non-CCTV services listen on 8000, and
  // counting the bare port twice pushed unrelated hosts over the CCTV threshold.

  return {
    ip_address: ip,
    mac_address: await readArpMac(ip), // '' on a routed subnet — see module note
    vendor: vendor || (vendorStrong ? vendor : 'Unknown'),
    model: model || 'Unknown',
    firmware_version: firmware || 'Unknown',
    device_type,
    open_ports,
    protocols: Array.from(protocols),
    http_server: httpServer || undefined,
    missing_security_headers: missingHeaders,
    rtsp_confirmed: rtspConfirmed,
    vendor_endpoints: vendorEndpoints,
  }
}

/** Best-effort identity parse from an UNAUTHENTICATED 200 body only. */
export function parseIdentity(vendor: string, body: string): { vendor: string; model: string; firmware: string } {
  const out = { vendor: '', model: '', firmware: '' }
  if (!body) return out
  // Hikvision ISAPI XML
  const model = /<model>\s*([^<]+?)\s*<\/model>/i.exec(body)
  const fw = /<firmwareVersion>\s*([^<]+?)\s*<\/firmwareVersion>/i.exec(body)
  if (model) { out.model = model[1]; out.vendor = out.vendor || 'Hikvision' }
  if (fw) out.firmware = fw[1]
  // Hikvision login page: <div class="model">DS-7608NI-K2 &nbsp;|&nbsp; Web Version: V5.7.3 build 210721</div>
  const liModel = /class=["']?model["']?[^>]*>\s*([A-Za-z0-9][A-Za-z0-9-]+)/i.exec(body)
  const liVer = /Web Version:\s*([^<&]+?)\s*(?:<|&nbsp;|$)/i.exec(body)
  if (liModel) { out.model = out.model || liModel[1].trim(); out.vendor = out.vendor || 'Hikvision' }
  if (liVer) out.firmware = out.firmware || liVer[1].trim()
  // Dahua key=value
  const dModel = /deviceType=([^\r\n]+)/i.exec(body)
  const dFw = /(?:version|softwareVersion)=([^\r\n]+)/i.exec(body)
  if (dModel) { out.model = out.model || dModel[1].trim(); out.vendor = out.vendor || 'Dahua' }
  if (dFw) out.firmware = out.firmware || dFw[1].trim()
  return out
}

/** Read the OS ARP/neighbour table for a MAC (same L2 segment only). */
export async function readArpMac(ip: string): Promise<string> {
  try {
    const fs = await import('fs/promises')
    const arp = await fs.readFile('/proc/net/arp', 'utf8').catch(() => '')
    for (const line of arp.split('\n')) {
      const cols = line.trim().split(/\s+/)
      if (cols[0] === ip && cols[3] && cols[3] !== '00:00:00:00:00:00') return cols[3].toUpperCase()
    }
  } catch {
    /* ignore — MAC is optional */
  }
  return ''
}

// ── Sweep ────────────────────────────────────────────────────────────────────

async function maybeStop(opts: DiscoveryOptions): Promise<boolean> {
  return opts.shouldStop ? !!(await opts.shouldStop()) : false
}

/** Enumerate every usable address in the CIDR. Capped to keep scans bounded. */
export function enumerateHosts(cidr: string, max = 1024): string[] {
  const { first, last } = cidrHostRange(cidr)
  const ips: string[] = []
  for (let n = first; n <= last && ips.length < max; n++) ips.push(intToIp(n))
  return ips
}

type PortProbe = (ip: string, port: number, timeoutMs: number) => Promise<boolean>

/** Ports that every IP camera / NVR answers on; used to re-check silent addresses. */
const LIVENESS_PORTS = [80, 554]

/**
 * Find the open ports of one address. A single connect attempt is not
 * reliable: a dropped SYN (busy device, lossy or routed link) made whole
 * ports, or whole cameras, disappear from one scan to the next. So:
 *   1. quick sweep of every port (connectTimeout);
 *   2. if the host answered, re-check each closed port up to `retries`
 *      more times with a longer timeout;
 *   3. if nothing answered, give the core CCTV ports (80/554) one longer try
 *      before calling the address dead, and if one answers, treat it as (2).
 * Dead addresses cost only step 3, so large ranges stay reasonably fast.
 */
export async function sweepHostPorts(
  ip: string,
  opts: { connectTimeoutMs?: number; confirmTimeoutMs?: number; retries?: number; probe?: PortProbe } = {},
): Promise<{ port: number; service: string }[]> {
  const probe = opts.probe ?? probeTcpPort
  const quick = opts.connectTimeoutMs ?? 600
  const confirm = opts.confirmTimeoutMs ?? 1500
  const retries = opts.retries ?? 2
  const open = new Set<number>()

  for (const sp of SCAN_PORTS) if (await probe(ip, sp.port, quick)) open.add(sp.port)

  if (open.size === 0) {
    for (const port of LIVENESS_PORTS) if (await probe(ip, port, confirm)) open.add(port)
    if (open.size === 0) return []
  }

  for (const sp of SCAN_PORTS) {
    for (let attempt = 0; attempt < retries && !open.has(sp.port); attempt++) {
      if (await probe(ip, sp.port, confirm)) open.add(sp.port)
    }
  }
  return SCAN_PORTS.filter(sp => open.has(sp.port))
}

/**
 * Discover live CCTV-capable hosts in a range. For each address we TCP-connect
 * to the port set (with confirmation retries, see sweepHostPorts); any host
 * with at least one open port is fingerprinted.
 * Classification (CCTV vs not) is done by the caller via classifyHost.
 */
export async function discoverHosts(cidr: string, opts: DiscoveryOptions = {}): Promise<RealDiscoveredHost[]> {
  const concurrency = Math.max(1, opts.concurrency ?? 32)
  const ips = enumerateHosts(cidr)
  const results: RealDiscoveredHost[] = []
  let index = 0
  let done = 0

  const worker = async () => {
    while (index < ips.length) {
      if (await maybeStop(opts)) return
      const ip = ips[index++]
      const open = await sweepHostPorts(ip, { connectTimeoutMs: opts.connectTimeoutMs })
      if (open.length > 0) {
        const host = await fingerprintHost(ip, open, opts)
        results.push(host)
      }
      done++
      if (opts.onProgress) await opts.onProgress(done, ips.length)
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, ips.length) }, () => worker()))
  return results.sort((a, b) => a.ip_address.localeCompare(b.ip_address, undefined, { numeric: true }))
}

/** Derive which (existing) vulnerability checks apply from observed evidence. */
export function deriveChecksFromEvidence(host: RealDiscoveredHost): string[] {
  const checks: string[] = []
  const ports = new Set(host.open_ports.map(p => p.port))
  const hasHttp = ports.has(80) || ports.has(8080)
  const hasHttps = ports.has(443) || ports.has(8443)
  if (hasHttp && !hasHttps) checks.push('http_only')
  if (ports.has(554)) checks.push('rtsp_exposed')
  if (ports.has(23)) checks.push('telnet_open')
  if (host.missing_security_headers) checks.push('missing_headers')
  if (host.open_ports.length >= 4) checks.push('open_ports')
  return checks
}
