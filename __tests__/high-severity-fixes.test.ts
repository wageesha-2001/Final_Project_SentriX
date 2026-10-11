/**
 * @jest-environment node
 *
 * Regression tests for the three High-severity QA findings (2026-10-10):
 *   1. a deleted user's token kept working (getAuthUser trusted the JWT alone)
 *   2. demo passwords were always printed on the public login page
 *   3. live discovery lost ports / whole hosts on a single dropped connect
 * No network traffic: discovery is exercised through an injected port probe.
 */
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-for-jest-at-least-32-characters'

import fs from 'fs'
import path from 'path'
import { NextRequest } from 'next/server'
import { resetLocalDb } from '@/lib/supabase/local-db'
import { createServerSupabase } from '@/lib/supabase/server'
import { sweepHostPorts } from '@/lib/scanner/network-discovery'

// Imported after JWT_SECRET is set (jwt.ts reads it at module load).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { signToken } = require('@/lib/auth/jwt')
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { getAuthUser } = require('@/lib/auth/middleware')

const TECH_ID = 'a0000000-0000-0000-0000-000000000002'
const reqWith = (token: string) =>
  new NextRequest('http://localhost/api/scans', { headers: { cookie: `sentrix_token=${token}` } })

describe('BUG-01: sessions end when the account is deleted', () => {
  beforeEach(() => resetLocalDb())

  it('accepts a valid token for an existing user', async () => {
    const token = await signToken({ sub: TECH_ID, email: 'tech@sentrix.local', role: 'technician', name: 'Tech' })
    const user = await getAuthUser(reqWith(token))
    expect(user?.sub).toBe(TECH_ID)
  })

  it('rejects a validly signed token once the user is deleted', async () => {
    const token = await signToken({ sub: TECH_ID, email: 'tech@sentrix.local', role: 'technician', name: 'Tech' })
    await createServerSupabase().from('users').delete().eq('id', TECH_ID)
    expect(await getAuthUser(reqWith(token))).toBeNull()
  })

  it('takes the role from the database, not from the token', async () => {
    // A technician token that claims admin must not grant admin.
    const forged = await signToken({ sub: TECH_ID, email: 'tech@sentrix.local', role: 'admin', name: 'Tech' })
    const user = await getAuthUser(reqWith(forged))
    expect(user?.role).toBe('technician')
  })

  it('rejects a token for an id that never existed', async () => {
    const token = await signToken({ sub: '00000000-0000-0000-0000-00000000dead', email: 'x@y.z', role: 'admin', name: 'X' })
    expect(await getAuthUser(reqWith(token))).toBeNull()
  })
})

describe('BUG-02: demo credentials are opt-in on the login page', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'app', '(auth)', 'login', 'page.tsx'), 'utf8')
  it('renders the demo block only behind NEXT_PUBLIC_SHOW_DEMO_CREDENTIALS', () => {
    expect(src).toMatch(/NEXT_PUBLIC_SHOW_DEMO_CREDENTIALS === '1'/)
    expect(src).toMatch(/\{SHOW_DEMO_CREDENTIALS && \(/)
  })
})

describe('BUG-03: port sweep survives dropped connection attempts', () => {
  /** Fake network: `open` ports answer, but only from attempt `failFirst + 1` on. */
  const flaky = (open: number[], failFirst: Record<number, number> = {}) => {
    const calls: { port: number; timeout: number }[] = []
    const seen: Record<number, number> = {}
    const probe = async (_ip: string, port: number, timeout: number) => {
      calls.push({ port, timeout })
      seen[port] = (seen[port] ?? 0) + 1
      return open.includes(port) && seen[port] > (failFirst[port] ?? 0)
    }
    return { probe, calls }
  }

  it('recovers a port whose first connect was dropped (camera kept RTSP)', async () => {
    const net = flaky([80, 554], { 554: 1 })
    const ports = await sweepHostPorts('192.168.70.51', { probe: net.probe })
    expect(ports.map(p => p.port)).toEqual([80, 554])
  })

  it('recovers a port that drops twice (two confirmation retries)', async () => {
    const net = flaky([80, 554], { 554: 2 })
    const ports = await sweepHostPorts('192.168.70.58', { probe: net.probe })
    expect(ports.map(p => p.port)).toEqual([80, 554])
  })

  it('finds a host whose whole quick sweep was dropped (no more "0 devices, secure")', async () => {
    const net = flaky([80, 554], { 80: 1, 554: 1 })
    const ports = await sweepHostPorts('192.168.70.56', { probe: net.probe })
    expect(ports.map(p => p.port)).toEqual([80, 554])
  })

  it('confirmation attempts use the longer timeout', async () => {
    const net = flaky([80, 554], { 554: 1 })
    await sweepHostPorts('192.168.70.51', { probe: net.probe, connectTimeoutMs: 600, confirmTimeoutMs: 1500 })
    const retries554 = net.calls.filter(c => c.port === 554).slice(1)
    expect(retries554.length).toBeGreaterThan(0)
    expect(retries554.every(c => c.timeout === 1500)).toBe(true)
  })

  it('a dead address costs only one extra check of the core CCTV ports', async () => {
    const net = flaky([])
    const ports = await sweepHostPorts('192.168.70.200', { probe: net.probe })
    expect(ports).toEqual([])
    // 7 quick probes + 2 liveness probes (80, 554), no per-port retries.
    expect(net.calls).toHaveLength(9)
  })

  it('does not invent ports that are really closed', async () => {
    const net = flaky([80])
    const ports = await sweepHostPorts('192.168.70.66', { probe: net.probe })
    expect(ports.map(p => p.port)).toEqual([80])
  })
})
