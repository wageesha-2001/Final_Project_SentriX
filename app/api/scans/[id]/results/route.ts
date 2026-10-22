import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { getEnrichedMatches } from '@/lib/vuln-db/queries'

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  const { data: scan } = await supabase.from('scans').select('*').eq('id', params.id).single()
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  if (user!.role !== 'admin' && scan.user_id !== user!.sub) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  const { data: devices } = await supabase
    .from('devices')
    .select('*')
    .eq('scan_id', params.id)
    .order('risk_score', { ascending: false })
  const deviceIds = (devices || []).map((d: Record<string, unknown>) => d.id)
  let vulnerabilities: unknown[] = []
  if (deviceIds.length > 0) {
    const { data: vulns } = await supabase
      .from('vulnerabilities')
      .select('*')
      .in('device_id', deviceIds)
    vulnerabilities = vulns || []
  }
  const community_matches = await getEnrichedMatches(supabase, deviceIds)

  // Discovery summary (mode, hosts that responded) so the UI can explain an empty result
  const { data: logs } = await supabase.from('audit_logs').select('details').eq('action', 'cctv_discovery_completed')
  const d = (logs || [])
    .map((l: { details?: Record<string, unknown> }) => l.details)
    .find((det: Record<string, unknown> | undefined) => det?.scan_id === params.id)
  const discovery = d ? {
    mode: (d.mode as string) ?? 'simulated',
    hosts_discovered: Number(d.hosts_discovered ?? 0),
    cctv_devices_identified: Number(d.cctv_devices_identified ?? 0),
  } : null

  return NextResponse.json({ data: { scan, devices: devices || [], vulnerabilities, community_matches, discovery } })
}
