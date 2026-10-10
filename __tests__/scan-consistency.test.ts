/**
 * @jest-environment node
 *
 * Same network + same settings + same vulnerability file => same scan output.
 */
jest.mock('@/lib/auth/middleware', () => ({
  getAuthUser: async () => ({ sub: 'a0000000-0000-0000-0000-000000000001', role: 'admin' }),
  requireAuth: () => null,
}))

import { NextRequest } from 'next/server'
import { runMockScan } from '@/lib/scanner/mock-scanner'
import { createServerSupabase } from '@/lib/supabase/server'
import { POST as createScan } from '@/app/api/scans/route'

async function scanSnapshot(safeScanMode: boolean) {
  const res = await createScan(new NextRequest('http://localhost/api/scans', {
    method: 'POST', body: JSON.stringify({ scan_name: 'Consistency', network_range: '192.168.1.0/24', authorized: true }),
  }))
  const { data: scan } = await res.json()
  await runMockScan(scan.id, scan.network_range, safeScanMode)

  const db = createServerSupabase()
  const { data: scanRow } = await db.from('scans').select('*').eq('id', scan.id).single()
  const { data: devices } = await db.from('devices').select('*').eq('scan_id', scan.id)
  const out = []
  for (const d of [...devices].sort((a, b) => a.ip_address.localeCompare(b.ip_address))) {
    const { data: vulns } = await db.from('vulnerabilities').select('*').eq('device_id', d.id)
    const { data: matches } = await db.from('device_vulnerability_matches').select('*').eq('device_id', d.id)
    out.push({
      ip: d.ip_address, mac: d.mac_address, vendor: d.vendor, model: d.model, firmware: d.firmware_version,
      type: d.device_type, status: d.status, risk: d.risk_score, level: d.risk_level,
      findings: vulns.map((v: { title: string }) => v.title).sort(),
      matches: matches.map((m: { vulnerability_id: string; match_confidence: string; risk_score_added: number }) =>
        `${m.vulnerability_id}:${m.match_confidence}:${m.risk_score_added}`).sort(),
    })
  }
  return {
    totals: {
      status: scanRow.status, total: scanRow.total_devices, vulnerable: scanRow.vulnerable_devices,
      critical: scanRow.critical_devices, overall: scanRow.overall_risk,
    },
    devices: out,
  }
}

test('repeated scans with unchanged devices and settings give identical results', async () => {
  const first = await scanSnapshot(true)
  expect(first.totals.status).toBe('completed')
  expect(first.devices.length).toBe(first.totals.total)
  for (let i = 0; i < 2; i++) {
    expect(await scanSnapshot(true)).toEqual(first)
  }
}, 120000)

test('only the Safe Scan Mode setting changes the default-credential finding', async () => {
  const safe = await scanSnapshot(true)
  const full = await scanSnapshot(false)
  const credTitle = (d: { findings: string[] }) => d.findings.filter(f => /credential/i.test(f))
  expect(safe.devices.flatMap(credTitle)).toHaveLength(0)
  expect(full.devices.flatMap(credTitle).length).toBeGreaterThan(0)
  // Same devices are identified either way
  expect(full.devices.map(d => d.ip)).toEqual(safe.devices.map(d => d.ip))
}, 120000)
