import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import bcrypt from 'bcryptjs'
import { z } from 'zod'

const createUserSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  role: z.enum(['admin', 'technician']),
})

export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  if (user.role !== 'admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  const supabase = createServerSupabase()
  const { data, error } = await supabase.from('users').select('id, name, email, role, created_at').order('created_at')
  if (error) {
    console.error('Users fetch error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
  return NextResponse.json({ data })
}

export async function POST(req: NextRequest) {
  const user = await getAuthUser(req)
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  if (user.role !== 'admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  try {
    const body = await req.json()
    const parsed = createUserSchema.safeParse(body)
    if (!parsed.success) return NextResponse.json({ error: parsed.error.errors[0].message }, { status: 400 })
    const { name, email, password, role } = parsed.data
    const password_hash = await bcrypt.hash(password, 12)
    const supabase = createServerSupabase()
    // Check duplicate email
    const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).single()
    if (existing) return NextResponse.json({ error: 'Email already in use' }, { status: 409 })
    const { data, error } = await supabase.from('users').insert({ name, email: email.toLowerCase(), password_hash, role }).select('id, name, email, role, created_at').single()
    if (error) {
      console.error('User create error:', error)
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    }
    await supabase.from('audit_logs').insert({ user_id: user.sub, action: 'user_created', details: { email, role } })
    return NextResponse.json({ data }, { status: 201 })
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
}
