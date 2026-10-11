/**
 * @jest-environment node
 *
 * Regression tests for the Low-severity QA findings (2026-10-10).
 * Route handlers are called directly against the in-memory local DB.
 */
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-for-jest-at-least-32-characters'

import fs from 'fs'
import path from 'path'
import { NextRequest } from 'next/server'
import { resetLocalDb } from '@/lib/supabase/local-db'
import { createServerSupabase } from '@/lib/supabase/server'
import { createScanSchema, createUserSchema, settingsSchema, normalizeCidr } from '@/lib/validators/schemas'
import { discountOverlappingMatches, VULNERABILITY_DEFINITIONS } from '@/lib/risk/calculator'

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { signToken } = require('@/lib/auth/jwt')

const ADMIN = { sub: 'a0000000-0000-0000-0000-000000000001', email: 'admin@sentrix.local', role: 'admin', name: 'Admin' }
const TECH = { sub: 'a0000000-0000-0000-0000-000000000002', email: 'tech@sentrix.local', role: 'technician', name: 'Tech' }
const req = async (who: typeof ADMIN | null, url: string, init: { method?: string; body?: string } = {}) =>
  new NextRequest('http://localhost' + url, {
    method: init.method ?? 'GET',
    body: init.body,
    headers: { 'content-type': 'application/json', ...(who ? { cookie: `sentrix_token=${await signToken(who)}` } : {}) },
  })
const route = (p: string) => require(`@/app/api/${p}/route`)

beforeEach(() => resetLocalDb())

describe('auth-01: malformed login body', () => {
  it.each(['{bad', '', 'email=a&password=b'])('returns 400, not 500, for body %p', async body => {
    const res = await route('auth/login').POST(await req(null, '/api/auth/login', { method: 'POST', body }))
    expect(res.status).toBe(400)
  })
})

describe('auth-06 / auth-07: password policy and field limits', () => {
  const user = (o: object) => createUserSchema.safeParse({ name: 'QA User', email: 'qa@sentrix.local', password: 'Strong#Pass2026', role: 'technician', ...o })

  it('accepts a strong password', () => expect(user({}).success).toBe(true))
  it.each(['password', 'Password1', 'password#2026', 'PASSWORD#2026', 'Pass#2026'])('rejects weak password %p', pw => {
    expect(user({ password: pw }).success).toBe(false)
  })
  it('rejects passwords over 72 bytes instead of truncating them', () => {
    expect(user({ password: 'Aa1#' + 'L'.repeat(68) }).success).toBe(true) // exactly 72
    expect(user({ password: 'Aa1#' + 'L'.repeat(69) }).success).toBe(false)
    expect(user({ password: 'Aa1#' + 'é'.repeat(35) }).success).toBe(false) // 74 bytes, 39 chars
  })
  it('limits name and email length', () => {
    expect(user({ name: 'x'.repeat(10000) }).success).toBe(false)
    expect(user({ email: 'a'.repeat(250) + '@x.io' }).success).toBe(false)
  })

  it('login never accepts a >72-byte password that shares its first 72 bytes with the real one', async () => {
    const pw = 'Aa1#' + 'L'.repeat(68)
    const created = await route('users').POST(await req(ADMIN, '/api/users', { method: 'POST', body: JSON.stringify({ name: 'Long', email: 'long@sentrix.local', password: pw, role: 'technician' }) }))
    expect(created.status).toBe(201)
    const login = (password: string) => route('auth/login').POST(new NextRequest('http://localhost/api/auth/login', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'long@sentrix.local', password }),
    }))
    expect((await login(pw)).status).toBe(200)
    expect((await login(pw + 'ZZZZ')).status).toBe(401)
  }, 30000)
})

describe('auth-08: deleting something that does not exist', () => {
  it('user → 404 and no audit entry', async () => {
    const id = '00000000-0000-0000-0000-00000000beef'
    const res = await route('users/[id]').DELETE(await req(ADMIN, `/api/users/${id}`, { method: 'DELETE' }), { params: { id } })
    expect(res.status).toBe(404)
    const { data } = await createServerSupabase().from('audit_logs').select('*').eq('action', 'user_deleted')
    expect(data).toEqual([])
  })
  it('existing user still deletes', async () => {
    const res = await route('users/[id]').DELETE(await req(ADMIN, `/api/users/${TECH.sub}`, { method: 'DELETE' }), { params: { id: TECH.sub } })
    expect(res.status).toBe(200)
  })
  it('credential → 404', async () => {
    const id = 'not-a-real-credential'
    const res = await route('default-credentials/[id]').DELETE(await req(ADMIN, `/api/default-credentials/${id}`, { method: 'DELETE' }), { params: { id } })
    expect(res.status).toBe(404)
  })
})

describe('auth-10 / ui-10: scan name and range validation', () => {
  const scan = (o: object) => createScanSchema.safeParse({ scan_name: 'Office audit', network_range: '192.168.70.0/24', authorized: true, ...o })

  it('rejects a whitespace-only name and trims real names', () => {
    expect(scan({ scan_name: '     ' }).success).toBe(false)
    const ok = scan({ scan_name: '  Office audit  ' })
    expect(ok.success && ok.data.scan_name).toBe('Office audit')
  })
  it.each(['0.0.0.0/16', '127.0.0.1/32', '224.0.0.0/24', '192.168.070.060/32', '01.2.3.4/32'])('rejects %p', r => {
    expect(scan({ network_range: r }).success).toBe(false)
  })
  it('stores the network that will really be scanned (host bits cleared)', () => {
    const r = scan({ network_range: '192.168.70.60/16' })
    expect(r.success && r.data.network_range).toBe('192.168.0.0/16')
    expect(normalizeCidr('192.168.70.56/32')).toBe('192.168.70.56/32')
    expect(normalizeCidr('192.168.70.200/24')).toBe('192.168.70.0/24')
    expect(normalizeCidr('192.168.70.56')).toBe('192.168.70.56')
  })
})

describe('auth-11 / ui-04: settings validation', () => {
  const settings = (o: object) => settingsSchema.safeParse({ safe_scan_mode: true, scan_timeout: 300, login_attempt_limit: 5, ...o })
  it('rejects fractional values', () => {
    expect(settings({ scan_timeout: 300.5 }).success).toBe(false)
    expect(settings({ login_attempt_limit: 3.5 }).success).toBe(false)
  })
  it('an empty number field gives a readable message, not "Expected number, received nan"', () => {
    const r = settings({ login_attempt_limit: NaN })
    expect(r.success).toBe(false)
    if (!r.success) expect(r.error.errors[0].message).toBe('Login attempt limit is required')
    const t = settings({ scan_timeout: NaN })
    if (!t.success) expect(t.error.errors[0].message).toBe('Scan timeout is required')
  })
  it('the settings page renders the login-limit error', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'app', '(dashboard)', 'settings', 'page.tsx'), 'utf8')
    expect(src).toMatch(/errors\.login_attempt_limit\.message/)
  })
})

describe('auth-12 / flow-06: audit-log limit', () => {
  beforeEach(async () => {
    const rows = Array.from({ length: 260 }, (_, i) => ({ user_id: ADMIN.sub, action: 'test', details: { i } }))
    await createServerSupabase().from('audit_logs').insert(rows)
  })
  it.each([['-1', 50], ['-5', 50], ['abc', 50], ['', 50], ['0', 50], ['2.5', 50], ['10', 10], ['500', 200]])('limit=%p → %p rows', async (limit, rows) => {
    const res = await route('audit-logs').GET(await req(ADMIN, `/api/audit-logs?limit=${limit}`))
    expect((await res.json()).data).toHaveLength(rows)
  })
})

describe('flow-07: settings changes are audit-logged', () => {
  it('records what changed, and nothing when nothing changed', async () => {
    const put = async (body: object) => route('settings').PUT(await req(ADMIN, '/api/settings', { method: 'PUT', body: JSON.stringify(body) }))
    const base = { safe_scan_mode: true, scan_timeout: 300, login_attempt_limit: 5 }
    await put(base)
    const db = createServerSupabase()
    const before = (await db.from('audit_logs').select('*').eq('action', 'settings_updated')).data!.length
    expect((await put({ ...base, safe_scan_mode: false })).status).toBe(200)
    const logs = (await db.from('audit_logs').select('*').eq('action', 'settings_updated')).data!
    expect(logs).toHaveLength(before + 1)
    expect(logs[logs.length - 1].details).toEqual({ changes: { safe_scan_mode: { from: true, to: false } } })
    await put({ ...base, safe_scan_mode: false })
    expect((await db.from('audit_logs').select('*').eq('action', 'settings_updated')).data).toHaveLength(before + 1)
  })
})

describe('flow-02: a weakness is scored once', () => {
  const def = (k: string) => VULNERABILITY_DEFINITIONS.find(v => v.checkKey === k)!
  const m = (category: string, risk_score_added: number) => ({ category, risk_score_added, matched_reason: 'Matched.', vulnerability_id: category })

  it('a community match only adds what exceeds the built-in check for the same weakness', () => {
    const [rtsp, headers, other] = discountOverlappingMatches(
      [def('rtsp_exposed'), def('missing_headers')],
      [m('RTSP Exposure', 17), m('Missing Security Headers', 12), m('Snapshot URL Exposure', 15)],
    )
    expect(rtsp.risk_score_added).toBe(0) // RTSP check already +25
    expect(rtsp.matched_reason).toMatch(/already counted by the built-in "Exposed RTSP Stream/)
    expect(headers.risk_score_added).toBe(12 - def('missing_headers').score)
    expect(other).toEqual(m('Snapshot URL Exposure', 15)) // no overlapping check
  })
  it('without the check, the match keeps its full score', () => {
    expect(discountOverlappingMatches([], [m('RTSP Exposure', 17)])[0].risk_score_added).toBe(17)
  })
})

describe('flow-05: progress of a stopped scan stays put', () => {
  it('the scanner only writes progress while the scan is running', async () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'scanner', 'mock-scanner.ts'), 'utf8')
    const progressWrites = src.match(/update\(\{ progress[^\n]*\n?[^\n]*/g) ?? []
    expect(progressWrites.length).toBeGreaterThanOrEqual(4)
    for (const w of progressWrites) expect(w).toMatch(/\.eq\('status', 'running'\)/)
    // and the guard really works against the DB layer
    const db = createServerSupabase()
    const { data: scan } = await db.from('scans').insert({ user_id: ADMIN.sub, scan_name: 's', network_range: '10.0.0.0/24', status: 'stopped', progress: 20 }).select().single()
    await db.from('scans').update({ progress: 38 }).eq('id', scan!.id).eq('status', 'running')
    expect((await db.from('scans').select('progress').eq('id', scan!.id).single()).data!.progress).toBe(20)
  })
})

describe('auth-09 / ui-05 / OBS-flow-15: live progress stream refuses with real statuses', () => {
  it('404 for a missing scan, 403 for someone else\'s, 200 for your own', async () => {
    const { GET } = route('scans/[id]/events')
    const db = createServerSupabase()
    const { data: scan } = await db.from('scans').insert({ user_id: ADMIN.sub, scan_name: 's', network_range: '10.0.0.0/24', status: 'completed', progress: 100 }).select().single()
    expect((await GET(await req(ADMIN, '/api/scans/nope/events'), { params: { id: 'nope' } })).status).toBe(404)
    expect((await GET(await req(TECH, `/api/scans/${scan!.id}/events`), { params: { id: scan!.id } })).status).toBe(403)
    const own = await GET(await req(ADMIN, `/api/scans/${scan!.id}/events`), { params: { id: scan!.id } })
    expect(own.status).toBe(200)
    await own.body?.cancel()
  })
  it('the progress page stops and explains instead of reconnecting forever', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'app', '(dashboard)', 'scans', '[id]', 'progress', 'page.tsx'), 'utf8')
    expect(src).toMatch(/EventSource\.CLOSED/)
    expect(src).toMatch(/Scan not found/)
  })
})

describe('ui-06: report page for a missing scan', () => {
  it('the API tells "scan not found" apart from "report not generated"', async () => {
    const { GET } = route('reports/[scanId]')
    const missing = await GET(await req(ADMIN, '/api/reports/nope'), { params: { scanId: 'nope' } })
    expect(missing.status).toBe(404)
    expect((await missing.json()).reason).toBe('scan_not_found')
    const { data: scan } = await createServerSupabase().from('scans').insert({ user_id: ADMIN.sub, scan_name: 's', network_range: '10.0.0.0/24', status: 'stopped', progress: 30 }).select().single()
    const noReport = await GET(await req(ADMIN, `/api/reports/${scan!.id}`), { params: { scanId: scan!.id } })
    expect(await noReport.json()).toMatchObject({ reason: 'report_not_found', scan_status: 'stopped' })
  })
})

describe('UI source checks', () => {
  const read = (...p: string[]) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8')

  it('ui-02: only the most specific nav item is active', () => {
    expect(read('components', 'layout', 'Sidebar.tsx')).toMatch(/const isActive = item\.href === activeHref/)
  })
  it('ui-11: collapsed state is remembered across pages', () => {
    expect(read('components', 'layout', 'Sidebar.tsx')).toMatch(/localStorage\.setItem\(COLLAPSED_KEY/)
  })
  it('ui-03: settings group header is not a <button> wrapping buttons', () => {
    const src = read('app', '(dashboard)', 'settings', 'page.tsx')
    expect(src).toMatch(/role="button"\s+tabIndex=\{0\}/)
  })
  it('ui-07: progress page shows the status, not a risk badge, until the scan completes', () => {
    expect(read('app', '(dashboard)', 'scans', '[id]', 'progress', 'page.tsx')).toMatch(/scan\.status === 'completed' \? \(\s*<RiskBadge/)
  })
  it('ui-09: a signed-in user is sent from /login to the dashboard', () => {
    expect(read('app', '(auth)', 'login', 'page.tsx')).toMatch(/if \(res\.ok\) router\.replace\('\/dashboard'\)/)
  })
  it('ui-12: New Scan describes the mode that is really in use', async () => {
    expect(read('app', '(dashboard)', 'scans', 'new', 'page.tsx')).not.toMatch(/Uses mock scanner/)
    const prev = process.env.SENTRIX_REAL_SCAN
    process.env.SENTRIX_REAL_SCAN = '1'
    expect((await (await route('scanner').GET(await req(TECH, '/api/scanner'))).json()).data.mode).toBe('real')
    delete process.env.SENTRIX_REAL_SCAN
    expect((await (await route('scanner').GET(await req(TECH, '/api/scanner'))).json()).data.mode).toBe('simulated')
    if (prev !== undefined) process.env.SENTRIX_REAL_SCAN = prev
  })
})
