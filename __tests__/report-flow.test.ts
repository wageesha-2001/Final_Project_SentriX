/**
 * @jest-environment node
 */
jest.mock('@/lib/auth/middleware', () => ({
  getAuthUser: async () => ({ sub: 'a0000000-0000-0000-0000-000000000001', role: 'admin' }),
  requireAuth: () => null,
}))

import { NextRequest } from 'next/server'
import { runMockScan } from '@/lib/scanner/mock-scanner'
import { getSecurityStatus } from '@/lib/risk/calculator'
import { POST as createScan } from '@/app/api/scans/route'
import { GET as listDevices } from '@/app/api/devices/route'
import { GET as listReports } from '@/app/api/reports/route'
import { GET as getReport } from '@/app/api/reports/[scanId]/route'
import { POST as generate } from '@/app/api/reports/[scanId]/generate/route'
import { DeviceListItem } from '@/types'

describe('getSecurityStatus', () => {
  it('classifies findings, confident matches and potential-only matches', () => {
    expect(getSecurityStatus(0, [])).toBe('secure')
    expect(getSecurityStatus(0, [{ match_confidence: 'Low' }])).toBe('potential')
    expect(getSecurityStatus(0, [{ match_confidence: 'Low' }, { match_confidence: 'Medium' }])).toBe('vulnerable')
    expect(getSecurityStatus(2, [])).toBe('vulnerable')
  })
})

test('scan -> all devices listed -> report list (none) -> generate -> list (one) -> view', async () => {
  const before = Date.now()
  const created = await createScan(new NextRequest('http://localhost/api/scans', {
    method: 'POST', body: JSON.stringify({ scan_name: 'Flow', network_range: '192.168.1.0/24', authorized: true }),
  }))
  expect(created.status).toBe(201)
  const { data: scan } = await created.json()
  // Scan date comes from the server clock, so the report never shows "Invalid Date"
  const startedAt = new Date(scan.started_at).getTime()
  expect(startedAt).toBeGreaterThanOrEqual(before)
  expect(startedAt).toBeLessThanOrEqual(Date.now())
  const result = await runMockScan(scan.id, '192.168.1.0/24', true)
  const req = new NextRequest('http://localhost/api/reports')
  const params = { params: { scanId: scan.id } }

  // Every identified IP camera and NVR is listed, not only vulnerable ones
  const devices: DeviceListItem[] = (await (await listDevices(req)).json()).data
    .filter((d: DeviceListItem) => d.scan_id === scan.id)
  expect(devices).toHaveLength(result.devices)
  expect(devices.filter(d => d.device_type === 'camera').length).toBeGreaterThanOrEqual(6)
  expect(devices.filter(d => d.device_type === 'nvr').length).toBeGreaterThanOrEqual(3)
  expect(new Set(devices.map(d => d.ip_address)).size).toBe(devices.length)
  for (const d of devices) {
    expect(d.status).toBe('active')
    expect(['vulnerable', 'potential', 'secure']).toContain(d.security_status)
    expect(typeof d.findings_count).toBe('number')
  }
  // Hardened devices have no failed checks, so they are never marked vulnerable
  for (const vendor of ['Bosch', 'Hanwha']) {
    const d = devices.find(x => x.vendor === vendor)!
    expect(d.findings_count).toBe(0)
    expect(d.security_status).not.toBe('vulnerable')
  }

  let list = await (await listReports(req)).json()
  expect(list.data.find((r: { scan_id: string }) => r.scan_id === scan.id)).toBeUndefined()
  expect((await getReport(req, params)).status).toBe(404)

  const gen = await generate(req, params)
  expect(gen.status).toBe(201)

  list = await (await listReports(req)).json()
  const entry = list.data.find((r: { scan_id: string }) => r.scan_id === scan.id)
  expect(entry).toBeDefined()
  expect(entry.report_html).toBeUndefined()
  expect(entry.created_at).toBeTruthy()

  const view = await (await getReport(req, params)).json()
  expect(view.data.report_html).toContain('COMMUNITY VULNERABILITY SUMMARY')
  expect(view.data.report_html).not.toContain('Invalid Date')
}, 60000)
