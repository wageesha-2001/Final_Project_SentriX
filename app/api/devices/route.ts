import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  const isAdmin = user!.role === 'admin'

  if (isAdmin) {
    const { data, error } = await supabase
      .from('devices')
      .select('*')
      .order('risk_score', { ascending: false })
    if (error) {
      console.error('Devices fetch error:', error)
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    }
    return NextResponse.json({ data: data || [] })
  }

  // Technician: fetch only their own scan IDs first
  const { data: scans } = await supabase
    .from('scans')
    .select('id')
    .eq('user_id', user!.sub)

  const scanIds = (scans || []).map((s: Record<string, unknown>) => s.id as string)
  if (scanIds.length === 0) return NextResponse.json({ data: [] })

  const { data, error } = await supabase
    .from('devices')
    .select('*')
    .in('scan_id', scanIds)
    .order('risk_score', { ascending: false })
  if (error) {
    console.error('Devices fetch error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
  return NextResponse.json({ data: data || [] })
}
