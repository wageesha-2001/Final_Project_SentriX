import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { createScanSchema } from '@/lib/validators/schemas'
import { rateLimit } from '@/lib/utils/rate-limiter'
import { v4 as uuidv4 } from 'uuid'

export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  let query = supabase
    .from('scans')
    .select('*')
    .order('started_at', { ascending: false })
    .limit(50)
  if (user!.role !== 'admin') {
    query = query.eq('user_id', user!.sub)
  }
  const { data, error } = await query
  if (error) {
    console.error('Scans fetch error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
  return NextResponse.json({ data })
}

export async function POST(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  if (!rateLimit(`scan:${user!.sub}`, 10, 60_000)) {
    return NextResponse.json({ error: 'Too many requests. Please wait before starting another scan.' }, { status: 429 })
  }
  try {
    const body = await req.json()
    const parsed = createScanSchema.safeParse(body)
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.errors[0].message }, { status: 400 })
    }
    const { scan_name, network_range } = parsed.data
    const supabase = createServerSupabase()
    const { data, error } = await supabase
      .from('scans')
      .insert({
        id: uuidv4(),
        user_id: user!.sub,
        scan_name,
        network_range,
        status: 'pending',
        total_devices: 0,
        vulnerable_devices: 0,
        critical_devices: 0,
        overall_risk: 'secure',
      })
      .select()
      .single()
    if (error) {
      console.error('Scan create error:', error)
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    }
    await supabase.from('audit_logs').insert({
      user_id: user!.sub,
      action: 'scan_created',
      details: { scan_id: data.id, scan_name, network_range },
    })
    return NextResponse.json({ data }, { status: 201 })
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
}
