import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

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
  return NextResponse.json({ data: { scan, devices: devices || [], vulnerabilities } })
}
