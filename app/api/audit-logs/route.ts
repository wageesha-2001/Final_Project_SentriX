import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  if (user.role !== 'admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 })

  const { searchParams } = new URL(req.url)
  // Whole number 1..200; anything else (NaN, 0, negatives) falls back to 50
  const requested = Number(searchParams.get('limit') ?? '50')
  const limit = Number.isInteger(requested) && requested >= 1 ? Math.min(requested, 200) : 50
  const action = searchParams.get('action') ?? ''

  const supabase = createServerSupabase()
  let query = supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(limit)
  if (action) query = query.eq('action', action)

  const { data, error } = await query
  if (error) {
    console.error('Audit logs fetch error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
  return NextResponse.json({ data })
}
