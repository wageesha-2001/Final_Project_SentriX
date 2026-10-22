/**
 * @jest-environment node
 */
jest.mock('@/lib/auth/middleware', () => ({
  getAuthUser: async () => ({ sub: 'a0000000-0000-0000-0000-000000000001', role: 'admin' }),
  requireAuth: () => null,
}))

import { NextRequest } from 'next/server'
import { classifyHost, cidrHostRange, intToIp, ipToInt, simulatedHostIp } from '@/lib/scanner/cctv-discovery'
import { runMockScan } from '@/lib/scanner/mock-scanner'
import { createServerSupabase } from '@/lib/supabase/server'
import { POST as createScan } from '@/app/api/scans/route'

describe('classifyHost', () => {
  const host = (vendor: string, ports: [number, string][], protocols: string[] = []) =>
    ({ vendor, model: 'x', open_ports: ports.map(([port, service]) => ({ port, service, protocol: 'tcp' })), protocols })

  it('identifies CCTV equipment by RTSP / ONVIF / SDK ports or CCTV manufacturer', () => {
    expect(classifyHost(host('Generic', [[554, 'RTSP']])).cctv).toBe(true)
    expect(classifyHost(host('Unknown', [[80, 'HTTP']], ['ONVIF'])).cctv).toBe(true)
    expect(classifyHost(host('Unknown', [[37777, 'Dahua-SDK']])).cctv).toBe(true)
    expect(classifyHost(host('Bosch', [[443, 'HTTPS']])).cctv).toBe(true)
    expect(classifyHost(host('TP-Link VIGI', [[443, 'HTTPS']])).cctv).toBe(true)
  })

  it('skips routers, PCs, printers, NAS and TVs', () => {
    expect(classifyHost(host('TP-Link', [[53, 'DNS'], [80, 'HTTP']])).cctv).toBe(false)
    expect(classifyHost(host('Dell', [[445, 'SMB'], [3389, 'RDP']])).cctv).toBe(false)
    expect(classifyHost(host('HP', [[80, 'HTTP'], [631, 'IPP'], [9100, 'JetDirect']])).cctv).toBe(false)
    expect(classifyHost(host('Synology', [[5000, 'HTTP'], [445, 'SMB']])).cctv).toBe(false)
    expect(classifyHost(host('Samsung', [[8001, 'HTTP']])).cctv).toBe(false)
  })
})

describe('classifyHost — weighted evidence classification', () => {
  // Richer host builder: ports, protocols, MAC prefix (OUI) and model text.
  const rich = (
    vendor: string,
    ports: [number, string][],
    protocols: string[] = [],
    extra: { mac_prefix?: string; device_type?: string; model?: string } = {},
  ) => ({
    vendor,
    model: extra.model ?? 'x',
    open_ports: ports.map(([port, service]) => ({ port, service, protocol: 'tcp' })),
    protocols,
    mac_prefix: extra.mac_prefix,
    device_type: extra.device_type,
  })

  it('1) Hikvision camera (RTSP + SDK + vendor + OUI) → IP_CAMERA, High, Hikvision', () => {
    const r = classifyHost(rich('Hikvision',
      [[80, 'HTTP'], [554, 'RTSP'], [8000, 'SDK']],
      ['HTTP', 'RTSP', 'ONVIF', 'Hikvision-SDK'],
      { mac_prefix: 'E8:B7:48', device_type: 'camera', model: 'DS-2CD2043G0-I' }))
    expect(r.cctv).toBe(true)
    expect(r.classification).toBe('IP_CAMERA')
    expect(r.confidence).toBe('High')
    expect(r.vendor).toBe('Hikvision')
  })

  it('2) Dahua camera (RTSP + 37777 + OUI) → camera-class, High, Dahua', () => {
    const r = classifyHost(rich('Dahua',
      [[80, 'HTTP'], [554, 'RTSP'], [37777, 'Dahua-SDK']],
      ['HTTP', 'RTSP', 'ONVIF', 'Dahua-SDK'],
      { mac_prefix: 'BC:32:5F', device_type: 'camera', model: 'IPC-HFW1230S' }))
    expect(r.cctv).toBe(true)
    expect(['IP_CAMERA', 'CCTV_DEVICE']).toContain(r.classification)
    expect(r.confidence).toBe('High')
    expect(r.vendor).toBe('Dahua')
  })

  it('3) Axis camera (HTTPS + VAPIX + RTSP) → IP_CAMERA, High, Axis', () => {
    const r = classifyHost(rich('Axis',
      [[443, 'HTTPS'], [554, 'RTSP']],
      ['HTTPS', 'RTSP', 'ONVIF', 'VAPIX'],
      { mac_prefix: 'AC:CC:8E', device_type: 'camera', model: 'M3045-V' }))
    expect(r.classification).toBe('IP_CAMERA')
    expect(r.confidence).toBe('High')
    expect(r.vendor).toBe('Axis')
  })

  it('4) generic web server (80 only) → not CCTV, low score', () => {
    const r = classifyHost(rich('Generic', [[80, 'HTTP']], ['HTTP']))
    expect(r.cctv).toBe(false)
    expect(r.score).toBeLessThan(35)
    expect(['NETWORK_DEVICE', 'UNKNOWN']).toContain(r.classification)
  })

  it('5) router/NAS (web + SSH, no CCTV evidence) → NETWORK_DEVICE, not CCTV', () => {
    const r = classifyHost(rich('Synology', [[22, 'SSH'], [80, 'HTTP'], [443, 'HTTPS']], ['HTTP', 'HTTPS', 'SSH']))
    expect(r.cctv).toBe(false)
    expect(r.classification).toBe('NETWORK_DEVICE')
  })

  it('6) NVR (RTSP + management ports + model says NVR) → NVR, High', () => {
    const r = classifyHost(rich('Hikvision',
      [[80, 'HTTP'], [554, 'RTSP'], [8000, 'SDK']],
      ['HTTP', 'RTSP', 'Hikvision-SDK'],
      { mac_prefix: 'E8:B7:48', device_type: 'nvr', model: 'DS-7608NI-K2 Network Video Recorder' }))
    expect(r.classification).toBe('NVR')
    expect(r.confidence).toBe('High')
  })

  it('7) missing ONVIF must not disqualify a host with RTSP + vendor evidence', () => {
    const r = classifyHost(rich('Dahua',
      [[554, 'RTSP'], [37777, 'Dahua-SDK']],
      ['RTSP', 'Dahua-SDK'], // no ONVIF
      { mac_prefix: 'BC:32:5F', device_type: 'camera', model: 'IPC-HFW1230S' }))
    expect(r.cctv).toBe(true)
    expect(['IP_CAMERA', 'CCTV_DEVICE']).toContain(r.classification)
  })

  it('HTTPS-only known CCTV vendor (Bosch/Hanwha) is still recognised via vendor + OUI', () => {
    const bosch = classifyHost(rich('Bosch', [[443, 'HTTPS']], ['HTTPS'],
      { mac_prefix: '00:07:5F', device_type: 'camera', model: 'FLEXIDOME IP 5000i' }))
    expect(bosch.cctv).toBe(true)
    expect(bosch.vendor).toBe('Bosch')
  })
})

describe('IPv4 range helpers', () => {
  it('converts addresses both ways', () => {
    expect(intToIp(ipToInt('192.168.1.64'))).toBe('192.168.1.64')
  })
  it('returns the usable host range of a CIDR', () => {
    expect(cidrHostRange('192.168.1.0/24')).toEqual({ first: ipToInt('192.168.1.1'), last: ipToInt('192.168.1.254') })
    expect(cidrHostRange('192.168.1.77/28')).toEqual({ first: ipToInt('192.168.1.65'), last: ipToInt('192.168.1.78') })
    expect(cidrHostRange('10.0.0.5')).toEqual({ first: ipToInt('10.0.0.5'), last: ipToInt('10.0.0.5') })
  })
  it('places simulated hosts only inside the scanned range', () => {
    expect(simulatedHostIp('192.168.1.0/24', 64)).toBe('192.168.1.64')
    expect(simulatedHostIp('10.20.0.0/16', 10)).toBe('10.20.0.10')
    expect(simulatedHostIp('192.168.1.64/28', 64)).toBeNull() // network address is not a host
    expect(simulatedHostIp('192.168.1.64/28', 65)).toBe('192.168.1.65')
    expect(simulatedHostIp('192.168.1.0/28', 64)).toBeNull()
    expect(simulatedHostIp('192.168.1.64/32', 64)).toBe('192.168.1.64')
    expect(simulatedHostIp('192.168.1.128/25', 64)).toBeNull()
  })
})

async function scan(range: string) {
  const res = await createScan(new NextRequest('http://localhost/api/scans', {
    method: 'POST', body: JSON.stringify({ scan_name: 'Discovery', network_range: range, authorized: true }),
  }))
  const { data } = await res.json()
  await runMockScan(data.id, range, true)
  const db = createServerSupabase()
  const { data: devices } = await db.from('devices').select('*').eq('scan_id', data.id)
  const { data: scanRow } = await db.from('scans').select('*').eq('id', data.id).single()
  const { data: logs } = await db.from('audit_logs').select('*').eq('action', 'cctv_discovery_completed')
  const log = logs.find((l: { details: { scan_id: string } }) => l.details.scan_id === data.id)
  return { devices, scanRow, log }
}

test('a /24 scan stores only CCTV cameras and NVRs, all inside the range', async () => {
  const { devices, scanRow, log } = await scan('192.168.1.0/24')
  const { first, last } = cidrHostRange('192.168.1.0/24')
  expect(devices.length).toBe(9)
  expect(scanRow.total_devices).toBe(9)
  for (const d of devices) {
    expect(['camera', 'nvr', 'dvr']).toContain(d.device_type)
    expect(classifyHost(d).cctv).toBe(true)
    expect(ipToInt(d.ip_address)).toBeGreaterThanOrEqual(first)
    expect(ipToInt(d.ip_address)).toBeLessThanOrEqual(last)
  }
  const vendors = devices.map((d: { vendor: string }) => d.vendor)
  for (const nonCctv of ['Dell', 'HP', 'Synology', 'Samsung', 'TP-Link']) expect(vendors).not.toContain(nonCctv)
  expect(log.details).toMatchObject({ hosts_discovered: 14, cctv_devices_identified: 9, non_cctv_hosts_skipped: 5 })
}, 60000)

test('a smaller range only finds the CCTV devices actually inside it', async () => {
  const { devices } = await scan('192.168.5.64/29') // hosts .65 - .70
  expect(devices.map((d: { ip_address: string }) => d.ip_address).sort())
    .toEqual(['192.168.5.65', '192.168.5.66', '192.168.5.67', '192.168.5.68', '192.168.5.69'])
  const single = await scan('192.168.5.11/32')
  expect(single.devices).toHaveLength(1)
  expect(single.devices[0]).toMatchObject({ ip_address: '192.168.5.11', device_type: 'nvr' })
  const none = await scan('192.168.5.200/29')
  expect(none.devices).toHaveLength(0)
  expect(none.scanRow.status).toBe('completed')
}, 60000)
