/**
 * @jest-environment node
 *
 * Dashboard + Devices must describe the real device inventory: re-scanning the
 * same network must not multiply devices, and every number must agree.
 */
const ADMIN = { sub: 'a0000000-0000-0000-0000-000000000001', role: 'admin' }
const TECH = { sub: 'a0000000-0000-0000-0000-000000000002', role: 'technician' }
let currentUser = ADMIN
jest.mock('@/lib/auth/middleware', () => ({
  getAuthUser: async () => currentUser,
  requireAuth: () => null,
}))

import { NextRequest } from 'next/server'
import { runMockScan } from '@/lib/scanner/mock-scanner'
import { resetLocalDb } from '@/lib/supabase/local-db'
import { POST as createScan } from '@/app/api/scans/route'
import { GET as getDashboard } from '@/app/api/dashboard/route'
import { GET as listDevices } from '@/app/api/devices/route'
import { DeviceListItem } from '@/types'

const req = (url: string) => new NextRequest(url)

async function scan(range: string, safe = true) {
  const res = await createScan(new NextRequest('http://localhost/api/scans', {
    method: 'POST', body: JSON.stringify({ scan_name: `Scan ${range}`, network_range: range, authorized: true }),
  }))
  const { data } = await res.json()
  await runMockScan(data.id, range, safe)
  return data.id as string
}

const dashboard = async () => (await (await getDashboard(req('http://localhost/api/dashboard'))).json()).data
const devices = async (q = ''): Promise<DeviceListItem[]> =>
  (await (await listDevices(req(`http://localhost/api/devices${q}`))).json()).data

beforeEach(() => { resetLocalDb(); currentUser = ADMIN })

test('re-scanning the same network does not multiply devices', async () => {
  const ids = [await scan('192.168.1.0/24'), await scan('192.168.1.0/24'), await scan('192.168.1.0/24')]
  const d = await dashboard()
  expect(d.total_scans).toBe(3)
  expect(d.total_devices).toBe(9)
  expect(d.camera_devices).toBe(6)
  expect(d.nvr_devices).toBe(3)

  const inventory = await devices()
  expect(inventory).toHaveLength(9)
  expect(new Set(inventory.map(x => x.ip_address)).size).toBe(9)
  // Inventory shows the latest scan's observation of each device
  expect(new Set(inventory.map(x => x.scan_id))).toEqual(new Set([ids[2]]))

  // A single scan's view lists exactly that scan's devices
  const one = await devices(`?scan=${ids[0]}`)
  expect(one).toHaveLength(9)
  expect(one.every(x => x.scan_id === ids[0])).toBe(true)
}, 90000)

test('every dashboard number agrees with the device inventory', async () => {
  await scan('192.168.1.0/24')
  await scan('10.0.0.0/24')
  const d = await dashboard()
  const inv = await devices()
  expect(d.total_devices).toBe(inv.length)
  expect(d.total_devices).toBe(18)
  expect(d.secure_devices + d.potential_devices + d.vulnerable_devices).toBe(d.total_devices)
  expect(d.vulnerable_devices).toBe(inv.filter(x => x.security_status === 'vulnerable').length)
  expect(d.potential_devices).toBe(inv.filter(x => x.security_status === 'potential').length)
  expect(d.secure_devices).toBe(inv.filter(x => x.security_status === 'secure').length)
  expect(d.critical_devices).toBe(inv.filter(x => x.risk_level === 'critical').length)
  const chartTotal = d.risk_distribution.reduce((s: number, r: { value: number }) => s + r.value, 0)
  expect(chartTotal).toBe(d.total_devices)
  for (const r of d.risk_distribution) {
    expect(r.value).toBe(inv.filter(x => x.risk_level === r.name.toLowerCase()).length)
  }
}, 90000)

test('technicians only see their own scans and devices', async () => {
  await scan('192.168.1.0/24') // admin's scan
  currentUser = TECH
  expect((await dashboard()).total_devices).toBe(0)
  expect(await devices()).toHaveLength(0)
  await scan('192.168.7.0/28') // tech's scan: hosts .1-.14 -> NVRs .10-.12
  const d = await dashboard()
  expect(d.total_devices).toBe(3)
  expect(d.nvr_devices).toBe(3)
  expect((await devices()).every(x => x.ip_address.startsWith('192.168.7.'))).toBe(true)
  currentUser = ADMIN
  expect((await dashboard()).total_devices).toBe(12)
}, 90000)
