import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

export async function GET(req: NextRequest, { params }: { params: { scanId: string } }) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()

  // Verify the user owns (or is admin for) the scan before returning its report
  // select('*') rather than naming scan_mode: databases without that column must still work
  const { data: scan } = await supabase.from('scans').select('*').eq('id', params.scanId).single()
  if (!scan) return NextResponse.json({ error: 'Scan not found', reason: 'scan_not_found' }, { status: 404 })
  if (user!.role !== 'admin' && scan.user_id !== user!.sub) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const { data, error } = await supabase
    .from('reports')
    .select('*')
    .eq('scan_id', params.scanId)
    .single()
  // scan_status lets the page say why there is no report (not generated vs. scan not finished)
  if (error || !data) return NextResponse.json({ error: 'Report not found', reason: 'report_not_found', scan_status: scan.status }, { status: 404 })
  return NextResponse.json({ data, scan_mode: scan.scan_mode ?? null })
}
