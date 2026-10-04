import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { settingsSchema } from '@/lib/validators/schemas'

export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  const { data, error } = await supabase.from('settings').select('*').eq('user_id', user!.sub).single()
  if (error || !data) {
    const defaults = {
      user_id: user!.sub,
      safe_scan_mode: true,
      scan_timeout: 300,
      login_attempt_limit: 5,
    }
    const { data: created } = await supabase.from('settings').insert(defaults).select().single()
    return NextResponse.json({ data: created || defaults })
  }
  return NextResponse.json({ data })
}

export async function PUT(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  try {
    const body = await req.json()
    const parsed = settingsSchema.safeParse(body)
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.errors[0].message }, { status: 400 })
    }
    const supabase = createServerSupabase()
    const { data, error } = await supabase
      .from('settings')
      .upsert({ ...parsed.data, user_id: user!.sub, updated_at: new Date().toISOString() }, { onConflict: 'user_id' })
      .select()
      .single()
    if (error) {
      console.error('Settings update error:', error)
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    }
    return NextResponse.json({ data })
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
}
