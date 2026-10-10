import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

// Lists which scans already have a generated report (metadata only, no HTML)
export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()

  let scanQuery = supabase.from('scans').select('id')
  if (user!.role !== 'admin') scanQuery = scanQuery.eq('user_id', user!.sub)
  const { data: scans } = await scanQuery
  const scanIds = (scans || []).map((s: { id: string }) => s.id)
  if (scanIds.length === 0) return NextResponse.json({ data: [] })

  const { data, error } = await supabase.from('reports').select('*').in('scan_id', scanIds)
  if (error) {
    console.error('Reports fetch error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
  const reports = (data || []).map((r: Record<string, unknown>) => ({
    id: r.id, scan_id: r.scan_id, report_title: r.report_title, created_at: r.created_at,
  }))
  return NextResponse.json({ data: reports })
}
