/**
 * Device inventory: every physical CCTV device appears exactly once, using
 * its most recent completed scan. Scanning the same network repeatedly must
 * not multiply the device counts on the dashboard or the Devices page.
 */
import { createServerSupabase } from '@/lib/supabase/server'
import { getSecurityStatus } from '@/lib/risk/calculator'
import { DeviceListItem, MatchConfidence } from '@/types'

type Db = ReturnType<typeof createServerSupabase>
type Row = Record<string, unknown>

/** A device is the same physical device if it reports the same MAC (or, without one, the same IP). */
export function deviceKey(d: { mac_address?: unknown; ip_address?: unknown }): string {
  const mac = String(d.mac_address ?? '').trim().toUpperCase()
  return mac ? `mac:${mac}` : `ip:${String(d.ip_address ?? '')}`
}

/** Attach per-device finding / match counts and the derived security status. */
export async function withSecuritySummary(db: Db, devices: Row[]): Promise<DeviceListItem[]> {
  const ids = devices.map(d => d.id as string)
  if (ids.length === 0) return []
  const [{ data: vulns }, { data: matches }] = await Promise.all([
    db.from('vulnerabilities').select('device_id').in('device_id', ids),
    db.from('device_vulnerability_matches').select('device_id, match_confidence').in('device_id', ids),
  ])
  return devices.map(d => {
    const findings = (vulns || []).filter((v: Row) => v.device_id === d.id).length
    const deviceMatches = (matches || []).filter((m: Row) => m.device_id === d.id) as { match_confidence: MatchConfidence }[]
    return {
      ...(d as unknown as DeviceListItem),
      findings_count: findings,
      community_match_count: deviceMatches.length,
      security_status: getSecurityStatus(findings, deviceMatches),
    }
  })
}

/** Completed scans visible to the user (admins see all), newest first. */
export async function getVisibleCompletedScans(db: Db, user: { sub: string; role: string }): Promise<Row[]> {
  let q = db.from('scans').select('*').eq('status', 'completed')
  if (user.role !== 'admin') q = q.eq('user_id', user.sub)
  const { data } = await q
  const ts = (s: Row) => new Date(String(s.completed_at ?? s.started_at ?? 0)).getTime() || 0
  return [...(data || [])].sort((a, b) => ts(b) - ts(a))
}

/** Latest observation of each device across the given (newest-first) completed scans. */
export async function getDeviceInventory(db: Db, completedScans: Row[]): Promise<DeviceListItem[]> {
  const scanIds = completedScans.map(s => s.id as string)
  if (scanIds.length === 0) return []
  const { data: devices } = await db.from('devices').select('*').in('scan_id', scanIds)
  const scanOrder = new Map(scanIds.map((id, i) => [id, i]))
  const latest = new Map<string, Row>()
  for (const d of devices || []) {
    const key = deviceKey(d)
    const current = latest.get(key)
    if (!current || scanOrder.get(d.scan_id as string)! < scanOrder.get(current.scan_id as string)!) latest.set(key, d)
  }
  const simulatedScans = new Set(completedScans.filter(s => s.scan_mode === 'simulated').map(s => s.id as string))
  const list = (await withSecuritySummary(db, Array.from(latest.values())))
    .map(d => ({ ...d, simulated: simulatedScans.has(d.scan_id) }))
  return list.sort((a, b) => b.risk_score - a.risk_score || a.ip_address.localeCompare(b.ip_address, undefined, { numeric: true }))
}
