/**
 * @jest-environment node
 *
 * Regression tests for the POC review: every screen must show correct,
 * consistent data for the same scan.
 */
const ADMIN = { sub: 'a0000000-0000-0000-0000-000000000001', role: 'admin' }
jest.mock('@/lib/auth/middleware', () => ({
  getAuthUser: async () => ADMIN,
  requireAuth: () => null,
  requireRole: () => null,
}))

import { NextRequest } from 'next/server'
import { runMockScan } from '@/lib/scanner/mock-scanner'
import { createServerSupabase } from '@/lib/supabase/server'
import { resetLocalDb } from '@/lib/supabase/local-db'
import { resetVulnStore } from '@/lib/vuln-db/store'
import { getSecurityStatus } from '@/lib/risk/calculator'
import { POST as createScan } from '@/app/api/scans/route'
import { POST as startScan } from '@/app/api/scans/[id]/start/route'
import { POST as stopScan } from '@/app/api/scans/[id]/stop/route'
import { GET as getResults } from '@/app/api/scans/[id]/results/route'
import { GET as listDevices } from '@/app/api/devices/route'
import { GET as getDashboard } from '@/app/api/dashboard/route'
import { POST as generate } from '@/app/api/reports/[scanId]/generate/route'
import { POST as createUser } from '@/app/api/users/route'
import { DeviceListItem } from '@/types'

const db = () => createServerSupabase()
const get = (url: string) => new NextRequest(url)
const post = (url: string, body?: unknown) =>
  new NextRequest(url, { method: 'POST', ...(body ? { body: JSON.stringify(body) } : {}) })

async function newScan(range = '192.168.1.0/24') {
  const res = await createScan(post('http://localhost/api/scans', { scan_name: 'POC', network_range: range, authorized: true }))
  return (await res.json()).data as { id: string; status: string }
}
async function completedScan(range = '192.168.1.0/24') {
  const scan = await newScan(range)
  await runMockScan(scan.id, range, true)
  return scan.id
}
const scanDevices = async (id: string): Promise<DeviceListItem[]> =>
  (await (await listDevices(get(`http://localhost/api/devices?scan=${id}`))).json()).data

beforeEach(() => { resetLocalDb(); resetVulnStore() })

test('devices whose model is not in vulnerabilities.txt are Healthy (an open port is not a finding)', async () => {
  const devices = await scanDevices(await completedScan())
  // These demo models are not listed in the shipped file, so they are Healthy.
  for (const model of ['FLEXIDOME IP 5000i', 'XNV-8080R', 'NVR4108HS-4KS2']) {
    const d = devices.find(x => x.model === model)!
    expect(d).toMatchObject({
      overall_security_status: 'HEALTHY', security_status: 'secure',
      risk_score: 0, risk_level: 'secure', known_vulnerability_count: 0,
    })
  }
  const dash = (await (await getDashboard(get('http://localhost/api/dashboard'))).json()).data
  expect(dash.healthy_devices).toBe(3)
  expect(dash.not_verified_devices).toBe(0)
}, 60000)

test('scan results, devices, dashboard and report all agree on the same scan', async () => {
  const id = await completedScan()
  const { data } = await (await getResults(get('http://localhost'), { params: { id } })).json()
  const devices = await scanDevices(id)
  // The results API and the devices list agree on each device's overall status.
  const resById = new Map(data.devices.map((d: { id: string; overall_security_status: string }) => [d.id, d.overall_security_status]))
  for (const d of devices) expect(resById.get(d.id)).toBe(d.overall_security_status)

  const vulnerable = devices.filter(d => d.security_status === 'vulnerable').length
  const potential = devices.filter(d => d.security_status === 'potential').length
  const secure = devices.filter(d => d.security_status === 'secure').length
  expect(data.scan.vulnerable_devices).toBe(vulnerable)
  expect(data.scan.total_devices).toBe(devices.length)
  expect(data.scan.critical_devices).toBe(devices.filter(d => d.risk_level === 'critical').length)

  const dash = (await (await getDashboard(get('http://localhost/api/dashboard'))).json()).data
  expect([dash.vulnerable_devices, dash.potential_devices, dash.secure_devices]).toEqual([vulnerable, potential, secure])

  const report = (await (await generate(get('http://localhost'), { params: { scanId: id } })).json()).data.report_html as string
  const stat = (label: string) => Number(new RegExp(`>(\\d+)</div><div class="stat-label">${label}<`).exec(report)?.[1])
  expect(stat('CCTV Devices')).toBe(devices.length)
  expect(stat('Secure Devices')).toBe(secure)
  expect(stat('Potential Issues')).toBe(potential)
  expect(stat('Vulnerable Devices')).toBe(vulnerable)
  // Key findings list each issue once with its device count
  const keyFindings = report.match(/<li style="color:#(?:ff3b5c|fb923c)">(?:CRITICAL|HIGH): [^<]+/g) ?? []
  expect(new Set(keyFindings).size).toBe(keyFindings.length)
  expect(report).not.toMatch(/Invalid Date|NaN|undefined/)
}, 60000)

test('a scan only runs once: completed scans cannot be restarted or stopped', async () => {
  const id = await completedScan()
  const before = (await scanDevices(id)).length
  const restart = await startScan(post('http://localhost'), { params: { id } })
  expect(restart.status).toBe(400)
  const stop = await stopScan(post('http://localhost'), { params: { id } })
  expect(stop.status).toBe(400)
  const { data: scan } = await db().from('scans').select('*').eq('id', id).single()
  expect(scan.status).toBe('completed')
  expect((await scanDevices(id)).length).toBe(before)
}, 60000)

test('stopping a running scan keeps totals consistent with saved devices', async () => {
  const scan = await newScan()
  await db().from('scans').update({ status: 'running' }).eq('id', scan.id)
  const run = runMockScan(scan.id, '192.168.1.0/24', true)
  await new Promise(r => setTimeout(r, 1500))
  expect((await stopScan(post('http://localhost'), { params: { id: scan.id } })).status).toBe(200)
  await run
  const { data: row } = await db().from('scans').select('*').eq('id', scan.id).single()
  const { data: devices } = await db().from('devices').select('*').eq('scan_id', scan.id)
  expect(row.status).toBe('stopped')
  expect(row.total_devices).toBe(devices.length)
  // Stopped scans are excluded from the dashboard and inventory, and cannot be reported
  const dash = (await (await getDashboard(get('http://localhost/api/dashboard'))).json()).data
  expect(dash.total_devices).toBe(0)
  expect((await generate(get('http://localhost'), { params: { scanId: scan.id } })).status).toBe(400)
}, 60000)

test('disabling every check really runs no checks', async () => {
  await db().from('vulnerability_checks').update({ enabled: false }).neq('id', '')
  const devices = await scanDevices(await completedScan())
  expect(devices.length).toBe(9)
  expect(devices.every(d => d.findings_count === 0 && d.community_match_count === 0)).toBe(true)
  expect(devices.every(d => d.risk_score === 0 && d.security_status === 'secure')).toBe(true)
}, 60000)

test('creating a user never returns the password hash', async () => {
  const res = await createUser(post('http://localhost/api/users', {
    name: 'New Tech', email: 'new.tech@sentrix.local', password: 'Strong@Passw0rd!', role: 'technician',
  }))
  const body = await res.json()
  expect(res.status).toBeLessThan(300)
  expect(body.data.password_hash).toBeUndefined()
  expect(body.data.email).toBe('new.tech@sentrix.local')
})
