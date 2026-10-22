import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { settingsSchema } from '@/lib/validators/schemas'
import { getGlobalSettings } from '@/lib/settings/global'

// Scanner settings are global: every user reads the same values, only admins change them.
export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  return NextResponse.json({ data: await getGlobalSettings(supabase) })
}

export async function PUT(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  if (user!.role !== 'admin') return NextResponse.json({ error: 'Forbidden — admin only' }, { status: 403 })
  try {
    const body = await req.json()
    const parsed = settingsSchema.safeParse(body)
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.errors[0].message }, { status: 400 })
    }
    const supabase = createServerSupabase()
    const previous = await getGlobalSettings(supabase)
    const { data, error } = await supabase
      .from('settings')
      .upsert({ ...parsed.data, user_id: user!.sub, updated_at: new Date().toISOString() }, { onConflict: 'user_id' })
      .select()
      .single()
    if (error) {
      console.error('Settings update error:', error)
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    }
    // Record what changed (e.g. safe scan mode turned off) like other admin actions
    const changes: Record<string, { from: unknown; to: unknown }> = {}
    for (const [key, to] of Object.entries(parsed.data)) {
      const from = (previous as unknown as Record<string, unknown>)[key]
      if (from !== to) changes[key] = { from: from ?? null, to }
    }
    if (Object.keys(changes).length > 0) {
      await supabase.from('audit_logs').insert({ user_id: user!.sub, action: 'settings_updated', details: { changes } })
    }
    return NextResponse.json({ data })
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
}
