import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { credentialSchema } from '@/lib/validators/schemas'
import { rateLimit } from '@/lib/utils/rate-limiter'

export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  // The list holds vendor passwords — admin only, like adding and deleting entries
  if (user!.role !== 'admin') return NextResponse.json({ error: 'Forbidden — admin only' }, { status: 403 })
  const supabase = createServerSupabase()
  const { data, error } = await supabase.from('default_credentials').select('*').order('vendor')
  if (error) {
    console.error('Default credentials fetch error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
  return NextResponse.json({ data })
}

export async function POST(req: NextRequest) {
  const user = await getAuthUser(req)
  if (!user || user.role !== 'admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  if (!rateLimit(`cred:${user!.sub}`, 30, 60_000)) {
    return NextResponse.json({ error: 'Too many requests.' }, { status: 429 })
  }
  try {
    const body = await req.json()
    const parsed = credentialSchema.safeParse(body)
    if (!parsed.success) return NextResponse.json({ error: parsed.error.errors[0].message }, { status: 400 })
    const supabase = createServerSupabase()
    const { data, error } = await supabase.from('default_credentials').insert(parsed.data).select().single()
    if (error) {
      console.error('Default credential insert error:', error)
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    }
    return NextResponse.json({ data }, { status: 201 })
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
}
