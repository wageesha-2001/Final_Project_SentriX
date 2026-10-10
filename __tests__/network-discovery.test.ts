/**
 * @jest-environment node
 *
 * Pure-logic tests for real network discovery. These do NOT touch the network;
 * they exercise the fingerprint parsing, vendor mapping, evidence→checks
 * mapping and range enumeration that drive the live probes.
 */
import {
  vendorFromServerHeader,
  parseIdentity,
  deriveChecksFromEvidence,
  enumerateHosts,
  fingerprintHost,
  RealDiscoveredHost,
} from '@/lib/scanner/network-discovery'
import { classifyHost } from '@/lib/scanner/cctv-discovery'

const host = (over: Partial<RealDiscoveredHost>): RealDiscoveredHost => ({
  ip_address: '192.168.70.50', mac_address: '', vendor: 'Hikvision', model: 'Unknown',
  firmware_version: 'Unknown', device_type: 'unknown',
  open_ports: [{ port: 80, service: 'HTTP', protocol: 'tcp' }, { port: 554, service: 'RTSP', protocol: 'tcp' }],
  protocols: ['RTSP', 'ISAPI'], ...over,
})

describe('vendorFromServerHeader', () => {
  it('maps Hikvision App-webs as strong vendor evidence', () => {
    expect(vendorFromServerHeader('App-webs ')).toEqual({ vendor: 'Hikvision', strong: true })
  })
  it('maps generic embedded servers as weak evidence', () => {
    expect(vendorFromServerHeader('Boa/0.94')).toEqual({ vendor: 'Embedded Device', strong: false })
    expect(vendorFromServerHeader('uc-httpd 1.0.0')).toEqual({ vendor: 'Generic IP Camera', strong: false })
  })
  it('returns null for an unknown server', () => {
    expect(vendorFromServerHeader('nginx/1.24')).toBeNull()
  })
})

describe('parseIdentity', () => {
  it('reads Hikvision ISAPI deviceInfo XML (only from an unauthenticated 200)', () => {
    const body = '<DeviceInfo><model>DS-7608NI-K2</model><firmwareVersion>V5.7.3</firmwareVersion></DeviceInfo>'
    expect(parseIdentity('Hikvision', body)).toMatchObject({ vendor: 'Hikvision', model: 'DS-7608NI-K2', firmware: 'V5.7.3' })
  })
  it('reads the Hikvision login page (unauthenticated) for model + web version', () => {
    const body = '<h1>HIKCAM-SIM</h1><div class="model">DS-7608NI-K2 &nbsp;|&nbsp; Web Version: V5.7.3 build 210721</div>'
    expect(parseIdentity('Hikvision', body)).toMatchObject({ vendor: 'Hikvision', model: 'DS-7608NI-K2', firmware: 'V5.7.3 build 210721' })
  })
  it('reads Dahua getSystemInfo key=value', () => {
    expect(parseIdentity('Dahua', 'deviceType=IPC-HFW1230S\r\nversion=2.420')).toMatchObject({ model: 'IPC-HFW1230S' })
  })
  it('returns empty on an empty body', () => {
    expect(parseIdentity('Hikvision', '')).toEqual({ vendor: '', model: '', firmware: '' })
  })
})

describe('deriveChecksFromEvidence', () => {
  it('flags http-only + RTSP exposure for a plain-HTTP camera with 554 open', () => {
    const checks = deriveChecksFromEvidence(host({}))
    expect(checks).toEqual(expect.arrayContaining(['http_only', 'rtsp_exposed']))
  })
  it('does not flag http_only when HTTPS is present', () => {
    const checks = deriveChecksFromEvidence(host({
      open_ports: [{ port: 443, service: 'HTTPS', protocol: 'tcp' }, { port: 554, service: 'RTSP', protocol: 'tcp' }],
    }))
    expect(checks).not.toContain('http_only')
    expect(checks).toContain('rtsp_exposed')
  })
  it('flags telnet and missing headers when observed', () => {
    const checks = deriveChecksFromEvidence(host({
      open_ports: [{ port: 23, service: 'Telnet', protocol: 'tcp' }, { port: 80, service: 'HTTP', protocol: 'tcp' }],
      missing_security_headers: true,
    }))
    expect(checks).toEqual(expect.arrayContaining(['telnet_open', 'missing_headers', 'http_only']))
  })
})

describe('enumerateHosts', () => {
  it('lists usable hosts of a /29', () => {
    expect(enumerateHosts('192.168.70.48/29')).toEqual([
      '192.168.70.49', '192.168.70.50', '192.168.70.51', '192.168.70.52', '192.168.70.53', '192.168.70.54',
    ])
  })
  it('treats a bare IP as a single host', () => {
    expect(enumerateHosts('192.168.70.50')).toEqual(['192.168.70.50'])
  })
})

describe('real discovery output classifies as CCTV via the weighted engine', () => {
  it('a Hikvision host (App-webs + RTSP + ISAPI) is kept as CCTV', () => {
    const h = host({ protocols: ['RTSP', 'ISAPI'], vendor: 'Hikvision' })
    const verdict = classifyHost(h)
    expect(verdict.cctv).toBe(true)
    expect(verdict.vendor).toBe('Hikvision')
  })

  it('a host with only web + port 8000 open (no RTSP/ISAPI/vendor) is NOT CCTV', async () => {
    // Regression: 192.168.70.236 (80 + 8000, no vendor evidence) was listed as a
    // CCTV device because the bare 8000 port was also counted as a Hikvision SDK protocol.
    // Probes target closed loopback ports, so no real traffic leaves the box.
    const h = await fingerprintHost('127.0.0.1', [
      { port: 1, service: 'HTTP' }, { port: 8000, service: 'SDK' },
    ], { readTimeoutMs: 200 })
    expect(h.protocols).not.toContain('Hikvision-SDK')
    const verdict = classifyHost(h)
    expect(verdict.cctv).toBe(false)
  })
})
