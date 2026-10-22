import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { getEnrichedMatches } from '@/lib/vuln-db/queries'

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  const { data: device } = await supabase.from('devices').select('*').eq('id', params.id).single()
  if (!device) return NextResponse.json({ error: 'Device not found' }, { status: 404 })
  const { data: scan } = await supabase.from('scans').select('user_id, scan_name, status, started_at').eq('id', device.scan_id).single()
  if (user!.role !== 'admin' && scan?.user_id !== user!.sub) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  const { data: vulnerabilities } = await supabase
    .from('vulnerabilities')
    .select('*')
    .eq('device_id', params.id)
    .order('score', { ascending: false })
  const community_matches = await getEnrichedMatches(supabase, [params.id])
  return NextResponse.json({
    data: {
      device, vulnerabilities: vulnerabilities || [], community_matches,
      scan: scan ? { id: device.scan_id, scan_name: scan.scan_name, status: scan.status, started_at: scan.started_at } : null,
    },
  })
}
