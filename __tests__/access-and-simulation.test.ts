/**
 * @jest-environment node
 *
 * Admin-only scanner settings and default-credential list, and the
 * "simulated data" flag carried from scan start to results, devices,
 * dashboard and the HTML report.
 */
const ADMIN = { sub: 'a0000000-0000-0000-0000-000000000001', role: 'admin' }
const TECH = { sub: 'a0000000-0000-0000-0000-000000000002', role: 'technician' }
let currentUser: { sub: string; role: string } = ADMIN
jest.mock('@/lib/auth/middleware', () => ({
  getAuthUser: async () => currentUser,
  requireAuth: () => null,
  requireRole: () => null,
}))

import { NextRequest } from 'next/server'
import { runMockScan } from '@/lib/scanner/mock-scanner'
import { generateReportHtml } from '@/lib/scanner/report-generator'
import { createServerSupabase } from '@/lib/supabase/server'
import { resetLocalDb } from '@/lib/supabase/local-db'
import { resetVulnStore } from '@/lib/vuln-db/store'
import { getGlobalSettings } from '@/lib/settings/global'
import { GET as getSettings, PUT as putSettings } from '@/app/api/settings/route'
import { GET as listCreds } from '@/app/api/default-credentials/route'
import { POST as createScan } from '@/app/api/scans/route'
import { POST as startScan } from '@/app/api/scans/[id]/start/route'
import { GET as listDevices } from '@/app/api/devices/route'
import { GET as getDashboard } from '@/app/api/dashboard/route'
import { Scan } from '@/types'

const db = () => createServerSupabase()
const get = (url: string) => new NextRequest(url)
const send = (method: string, url: string, body?: unknown) =>
  new NextRequest(url, { method, ...(body ? { body: JSON.stringify(body) } : {}) })
const SETTINGS_URL = 'http://localhost/api/settings'

beforeEach(() => { resetLocalDb(); resetVulnStore(); currentUser = ADMIN })

describe('scanner settings are global and admin-managed', () => {
  it('technicians cannot change settings; admins can', async () => {
    currentUser = TECH
    const denied = await putSettings(send('PUT', SETTINGS_URL, { safe_scan_mode: false, scan_timeout: 300, login_attempt_limit: 20 }))
    expect(denied.status).toBe(403)
    currentUser = ADMIN
    const ok = await putSettings(send('PUT', SETTINGS_URL, { safe_scan_mode: true, scan_timeout: 600, login_attempt_limit: 7 }))
    expect(ok.status).toBe(200)
  })

  it('every user reads the admin values, and technician rows are ignored', async () => {
    await putSettings(send('PUT', SETTINGS_URL, { safe_scan_mode: true, scan_timeout: 600, login_attempt_limit: 7 }))
    // A newer technician-owned row must not become the effective setting
    await db().from('settings').update({ safe_scan_mode: false, login_attempt_limit: 20, updated_at: new Date(Date.now() + 60_000).toISOString() })
      .eq('user_id', TECH.sub)
    expect(await getGlobalSettings(db())).toEqual({ safe_scan_mode: true, scan_timeout: 600, login_attempt_limit: 7 })
    currentUser = TECH
    const res = await (await getSettings(get(SETTINGS_URL))).json()
    expect(res.data).toEqual({ safe_scan_mode: true, scan_timeout: 600, login_attempt_limit: 7 })
  })
})

describe('default-credential list', () => {
  it('is readable by admins only', async () => {
    expect((await listCreds(get('http://localhost/api/default-credentials'))).status).toBe(200)
    currentUser = TECH
    expect((await listCreds(get('http://localhost/api/default-credentials'))).status).toBe(403)
  })
})

describe('simulated data flag', () => {
  async function newScan(range = '192.168.1.0/24') {
    const res = await createScan(send('POST', 'http://localhost/api/scans', { scan_name: 'Sim', network_range: range, authorized: true }))
    return (await res.json()).data as { id: string }
  }

  it('records the scan mode when a scan starts', async () => {
    const prev = process.env.SENTRIX_REAL_SCAN
    delete process.env.SENTRIX_REAL_SCAN
    try {
      const { id } = await newScan()
      expect((await startScan(send('POST', `http://localhost/api/scans/${id}/start`), { params: { id } })).status).toBe(200)
      const { data } = await db().from('scans').select('*').eq('id', id).single()
      expect(data!.scan_mode).toBe('simulated')
      await db().from('scans').update({ status: 'stopped' }).eq('id', id)
    } finally {
      if (prev !== undefined) process.env.SENTRIX_REAL_SCAN = prev
    }
  })

  it('devices and dashboard flag simulated scans', async () => {
    const { id } = await newScan()
    await db().from('scans').update({ scan_mode: 'simulated' }).eq('id', id)
    await runMockScan(id, '192.168.1.0/24', true)
    const devices = (await (await listDevices(get(`http://localhost/api/devices?scan=${id}`))).json()).data
    expect(devices.length).toBeGreaterThan(0)
    expect(devices.every((d: { simulated: boolean }) => d.simulated)).toBe(true)
    const inventory = (await (await listDevices(get('http://localhost/api/devices'))).json()).data
    expect(inventory.every((d: { simulated: boolean }) => d.simulated)).toBe(true)
    const dash = (await (await getDashboard(get('http://localhost/api/dashboard'))).json()).data
    expect(dash.has_simulated_data).toBe(true)
  }, 60000)

  it('real scans are not flagged', async () => {
    const { id } = await newScan()
    await db().from('scans').update({ scan_mode: 'real' }).eq('id', id)
    await runMockScan(id, '192.168.1.0/24', true) // simulated discovery, but the scan is labelled real
    const dash = (await (await getDashboard(get('http://localhost/api/dashboard'))).json()).data
    expect(dash.has_simulated_data).toBe(false)
  }, 60000)

  it('the HTML report carries a SIMULATED DATA banner only for simulated scans', () => {
    const base = {
      id: 's1', user_id: ADMIN.sub, scan_name: 'Demo', network_range: '192.168.1.0/24', status: 'completed',
      total_devices: 0, vulnerable_devices: 0, critical_devices: 0, overall_risk: 'secure', started_at: new Date().toISOString(),
    } as Scan
    expect(generateReportHtml({ ...base, scan_mode: 'simulated' }, [])).toContain('SIMULATED DATA')
    expect(generateReportHtml({ ...base, scan_mode: 'real' }, [])).not.toContain('SIMULATED DATA')
    expect(generateReportHtml(base, [])).not.toContain('SIMULATED DATA')
  })
})
