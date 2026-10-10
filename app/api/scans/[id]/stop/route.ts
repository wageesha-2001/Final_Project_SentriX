import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  const { data: scan } = await supabase.from('scans').select('*').eq('id', params.id).single()
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  if (user!.role !== 'admin' && scan.user_id !== user!.sub) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  // Only a pending or running scan can be stopped — never overwrite a finished one
  if (scan.status !== 'running' && scan.status !== 'pending') {
    return NextResponse.json({ error: `Scan is already ${scan.status}` }, { status: 400 })
  }
  await supabase.from('scans').update({
    status: 'stopped',
    completed_at: new Date().toISOString(),
  }).eq('id', params.id).in('status', ['running', 'pending'])
  await supabase.from('audit_logs').insert({
    user_id: user!.sub,
    action: 'scan_stopped',
    details: { scan_id: params.id, scan_name: scan.scan_name, network_range: scan.network_range },
  })
  return NextResponse.json({ message: 'Scan stopped' })
}
