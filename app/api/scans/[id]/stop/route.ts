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
  await supabase.from('scans').update({
    status: 'stopped',
    completed_at: new Date().toISOString(),
  }).eq('id', params.id)
  await supabase.from('audit_logs').insert({
    user_id: user!.sub,
    action: 'scan_stopped',
    details: { scan_id: params.id },
  })
  return NextResponse.json({ message: 'Scan stopped' })
}
