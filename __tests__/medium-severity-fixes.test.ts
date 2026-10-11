/**
 * @jest-environment node
 *
 * Regression tests for the Medium-severity QA findings (2026-10-10):
 *   auth-02  a token kept working after logout (no server-side revocation)
 *   auth-04  the login lockout counter was lost whenever the route re-evaluated
 *   flow-01  "Internet Exposure" records matched devices on a private LAN
 *   flow-08  an Unknown-vendor device got a stronger match than an identified one
 *   ui-08    report said "rated CRITICAL. No critical issues were detected."
 *   ui-01    no mobile layout (sidebar took 62% of a phone screen)
 */
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-for-jest-at-least-32-characters'

import fs from 'fs'
import path from 'path'
import { NextRequest } from 'next/server'
import { SignJWT } from 'jose'
import { resetLocalDb } from '@/lib/supabase/local-db'
import { matchDevice, isPrivateIp, MatchableDevice, MatchableRecord } from '@/lib/vuln-db/matcher'
import { generateReportHtml } from '@/lib/scanner/report-generator'
import type { Scan, Device, Vulnerability, EnrichedMatch } from '@/types'

// Imported after JWT_SECRET is set (jwt.ts reads it at module load).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { signToken, verifyToken } = require('@/lib/auth/jwt')
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { getAuthUser } = require('@/lib/auth/middleware')
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { POST: logout } = require('@/app/api/auth/logout/route')

const TECH_ID = 'a0000000-0000-0000-0000-000000000002'
const TECH = { sub: TECH_ID, email: 'tech@sentrix.local', role: 'technician', name: 'Tech' }
const reqWith = (token: string, url = 'http://localhost/api/scans') =>
  new NextRequest(url, { method: 'POST', headers: { cookie: `sentrix_token=${token}` } })

describe('auth-02: logout revokes the token server-side', () => {
  beforeEach(() => resetLocalDb())

  it('every token gets a unique id', async () => {
    const a = await verifyToken(await signToken(TECH))
    const b = await verifyToken(await signToken(TECH))
    expect(a.jti).toBeTruthy()
    expect(a.jti).not.toBe(b.jti)
  })

  it('a copied token is rejected after logout', async () => {
    const token = await signToken(TECH)
    expect(await getAuthUser(reqWith(token))).not.toBeNull()
    const res = await logout(reqWith(token, 'http://localhost/api/auth/logout'))
    expect(res.status).toBe(200)
    expect(await getAuthUser(reqWith(token))).toBeNull()
  })

  it('logging out one session leaves the user\'s other sessions working', async () => {
    const laptop = await signToken(TECH)
    const phone = await signToken(TECH)
    await logout(reqWith(laptop, 'http://localhost/api/auth/logout'))
    expect(await getAuthUser(reqWith(laptop))).toBeNull()
    expect((await getAuthUser(reqWith(phone)))?.sub).toBe(TECH_ID)
  })

  it('rejects a token without an id (cannot be revoked)', async () => {
    const legacy = await new SignJWT({ ...TECH })
      .setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('1h')
      .sign(new TextEncoder().encode(process.env.JWT_SECRET))
    expect(await getAuthUser(reqWith(legacy))).toBeNull()
  })
})

describe('auth-04: login lockout survives route re-evaluation', () => {
  beforeEach(() => {
    resetLocalDb()
    delete (globalThis as Record<string, unknown>).__sentrixLoginAttempts
  })

  const attempt = (password: string) => {
    // A fresh module instance each time, like a dev recompile / route disposal
    let POST: (req: NextRequest) => Promise<Response> = async () => new Response()
    jest.isolateModules(() => { POST = require('@/app/api/auth/login/route').POST })
    return POST(new NextRequest('http://localhost/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'tech@sentrix.local', password }),
    }))
  }

  it('locks after the limit even when every attempt hits a new module instance, and blocks the right password', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 5; i++) statuses.push((await attempt('Wrong-password-1')).status)
    expect(statuses).toEqual([401, 401, 401, 401, 401])
    expect((await attempt('Wrong-password-1')).status).toBe(429)
    expect((await attempt('Tech@SentriX2024')).status).toBe(429)
  }, 30000)

  it('a correct password before the limit still logs in and clears the counter', async () => {
    for (let i = 0; i < 3; i++) await attempt('Wrong-password-1')
    expect((await attempt('Tech@SentriX2024')).status).toBe(200)
    for (let i = 0; i < 4; i++) expect((await attempt('Wrong-password-1')).status).toBe(401)
  }, 30000)
})

// ─── Matching ────────────────────────────────────────────────────────────────

const rec = (o: Partial<MatchableRecord>): MatchableRecord => ({
  id: 'R', vendor: 'Generic IP Camera', affected_models: ['*'], affected_firmware: ['*'], device_type: 'any',
  category: 'RTSP Exposure', severity: 'Critical', risk_score: 30, affected_ports: [80, 443, 554, 8080],
  affected_protocols: ['HTTP', 'HTTPS'], detection_keywords: ['public ip', 'internet exposed'], match_fields: [], ...o,
})
const nvr = (o: Partial<MatchableDevice> = {}): MatchableDevice => ({
  vendor: 'Hikvision', model: 'DS-7608NI-K2', firmware_version: 'Unknown', device_type: 'nvr',
  open_ports: [{ port: 80, service: 'HTTP', protocol: 'tcp' }, { port: 554, service: 'RTSP', protocol: 'tcp' }],
  protocols: ['HTTP', 'RTSP'], ip_address: '192.168.70.56', ...o,
})

describe('flow-01: Internet Exposure needs a public address', () => {
  const hikExposure = rec({
    vendor: 'Hikvision', affected_models: ['DS-7608NI-K2', 'DS-7616NI-K2'], device_type: 'nvr',
    category: 'Internet Exposure', severity: 'High', risk_score: 26, affected_ports: [80, 443, 8000],
  })
  const genericExposure = rec({ category: 'Internet Exposure' })

  it('does not match a recorder scanned on the private LAN (was High, +26)', () => {
    expect(matchDevice(nvr(), [hikExposure, genericExposure])).toEqual([])
  })

  it('does not match when the address is unknown', () => {
    expect(matchDevice(nvr({ ip_address: undefined }), [hikExposure])).toEqual([])
  })

  it('still matches a device found at a public address', () => {
    const [m] = matchDevice(nvr({ ip_address: '203.0.113.10' }), [hikExposure])
    expect(m).toMatchObject({ vulnerability_id: 'R', match_confidence: 'High' })
  })

  it('only the exposure category is gated', () => {
    expect(matchDevice(nvr(), [rec({ category: 'RTSP Exposure', affected_ports: [554] })])).toHaveLength(1)
  })

  it.each([
    ['10.1.2.3', true], ['172.16.0.1', true], ['172.31.255.255', true], ['192.168.70.50', true],
    ['127.0.0.1', true], ['169.254.1.1', true], ['100.64.0.1', true], ['not-an-ip', true],
    ['172.32.0.1', false], ['8.8.8.8', false], ['203.0.113.10', false],
  ])('isPrivateIp(%s) = %s', (ip, expected) => {
    expect(isPrivateIp(ip as string)).toBe(expected)
  })
})

describe('flow-08: knowing less never gives a stronger match', () => {
  const generic = rec({ category: 'RTSP Exposure', affected_ports: [554], affected_protocols: ['RTSP'] })

  it('an Unknown-vendor device gets the same Low confidence as an identified Hikvision', () => {
    const [unknown] = matchDevice(nvr({ vendor: 'Unknown', model: 'Unknown', device_type: 'unknown' }), [generic])
    const [hik] = matchDevice(nvr(), [generic])
    expect(hik.match_confidence).toBe('Low')
    expect(unknown.match_confidence).toBe('Low') // was Medium / vendor_service, +23
    expect(unknown.risk_score_added).toBeLessThanOrEqual(hik.risk_score_added)
  })

  it('a device identified as a generic brand still aligns with generic records', () => {
    const [m] = matchDevice(nvr({ vendor: 'Generic', model: 'NVR-8CH-4K' }), [generic])
    expect(m.match_confidence).toBe('Medium')
  })
})

// ─── Report ──────────────────────────────────────────────────────────────────

describe('ui-08: report summary agrees with the overall rating', () => {
  const scan: Scan = {
    id: 's', user_id: 'u', scan_name: 'Scan', network_range: '192.168.70.0/24', status: 'completed', total_devices: 1,
    vulnerable_devices: 1, critical_devices: 1, overall_risk: 'critical', started_at: '2026-01-01T00:00:00Z',
  }
  const match = (severity: 'Critical' | 'High', confidence: 'Low' | 'High'): EnrichedMatch => ({
    id: `m-${severity}-${confidence}`, device_id: 'd', scan_id: 's', vulnerability_id: 'v', match_type: 'x',
    match_confidence: confidence, matched_fields: [], matched_reason: 'r', risk_score_added: 15,
    created_at: '2026-01-01T00:00:00Z',
    vulnerability: {
      vuln_id: `SXV-${severity}-${confidence}`, title: `${severity} thing`, description: 'd', vendor: 'Generic', category: 'RTSP Exposure',
      severity, cvss_score: 9, risk_score: 30, recommendation: 'Fix', remediation_steps: [], source_type: 'SIMULATED',
      reference_url: '', confidence_note: 'n',
    },
  })
  const dev = (matches: EnrichedMatch[]): Device & { vulnerabilities: Vulnerability[]; community_matches: EnrichedMatch[] } => ({
    id: 'd', scan_id: 's', ip_address: '192.168.70.51', mac_address: '', vendor: 'Hikvision', model: 'DS-2CD2042WD-I',
    firmware_version: 'Unknown', device_type: 'camera', open_ports: [], protocols: [], risk_score: 80, risk_level: 'critical',
    status: 'active', created_at: '2026-01-01T00:00:00Z', vulnerabilities: [], community_matches: matches,
  })

  it('does not claim "No critical issues were detected" under a CRITICAL rating', () => {
    const html = generateReportHtml(scan, [dev([match('Critical', 'Low'), match('High', 'High')])])
    expect(html).not.toContain('No critical issues were detected.')
    expect(html).toContain('No confirmed critical issues were detected; the critical rating comes from')
    expect(html).toContain('1 potential critical match')
    expect(html).toContain('Potential Critical Matches')
    expect(html).toContain('Confirmed Critical Issues')
  })

  it('reports confirmed critical issues when there are some', () => {
    const html = generateReportHtml(scan, [dev([match('Critical', 'High')])])
    expect(html).toMatch(/1 confirmed critical issue<\/strong> that requires immediate attention/)
  })

  it('keeps the plain sentence for a low-risk scan', () => {
    const html = generateReportHtml({ ...scan, overall_risk: 'low' }, [dev([])])
    expect(html).toContain('No critical issues were detected.')
    expect(html).not.toContain('Potential Critical Matches')
  })
})

// ─── Layout ──────────────────────────────────────────────────────────────────

describe('ui-01: dashboard layout works on phones', () => {
  const read = (f: string) => fs.readFileSync(path.join(__dirname, '..', 'components', 'layout', f), 'utf8')

  it('the fixed-width sidebar is desktop-only; phones get a drawer', () => {
    const src = read('Sidebar.tsx')
    expect(src).toMatch(/hidden md:flex/)
    expect(src).toMatch(/md:hidden fixed inset-y-0 left-0/)
  })

  it('the top bar has a menu button and the layout wires it to the drawer', () => {
    expect(read('Topbar.tsx')).toMatch(/aria-label="Open menu"/)
    expect(read('DashboardLayout.tsx')).toMatch(/mobileOpen=\{menuOpen\}/)
  })
})
