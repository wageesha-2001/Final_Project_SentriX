import { NextRequest, NextResponse } from 'next/server'
import bcrypt from 'bcryptjs'
import { createServerSupabase } from '@/lib/supabase/server'
import { signToken } from '@/lib/auth/jwt'
import { loginSchema } from '@/lib/validators/schemas'

// In-memory brute-force tracker keyed by the target account, not client IP.
// X-Forwarded-For can't be trusted for this: no reverse proxy sits in front
// of this deployment to strip client-supplied values, so an IP-keyed lockout
// is trivially bypassed by rotating a spoofed header. Keying on the account
// being attacked can't be spoofed away the same way.
const loginAttempts = new Map<string, { attempts: number; lockedUntil: number }>()
const LOCKOUT_DURATION_MS = 15 * 60 * 1000 // 15 minutes

// A precomputed bcrypt hash with no corresponding real account. Compared
// against on every "account not found" path so that responses take the same
// amount of time whether or not the email is registered — otherwise the
// timing difference (skip vs. run bcrypt) leaks which emails have accounts.
const DUMMY_HASH = '$2a$12$1tyBOmzN/Jgafx5m8v1R4.6pKuCH/y5y2ZJLtBisD3a7OcNzWdnCy'

function getClientIp(req: NextRequest): string {
  // Best-effort, for audit-log context only — not trustworthy for security
  // decisions since no reverse proxy fronts this deployment.
  const forwarded = req.headers.get('x-forwarded-for')
  if (forwarded) {
    const ips = forwarded.split(',').map(s => s.trim())
    const ip = ips[ips.length - 1]
    if (ip && ip !== '') return ip
  }
  return 'unknown'
}

export async function POST(req: NextRequest) {
  const ip = getClientIp(req)
  const now = Date.now()

  const supabase = createServerSupabase()
  const { data: anySettings } = await supabase
    .from('settings')
    .select('login_attempt_limit')
    .limit(1)
  const maxAttempts: number = (anySettings as Array<{ login_attempt_limit: number }> | null)?.[0]?.login_attempt_limit ?? 5

  try {
    const body = await req.json()
    const parsed = loginSchema.safeParse(body)
    if (!parsed.success) {
      return NextResponse.json({ error: parsed.error.errors[0].message }, { status: 400 })
    }
    const { email, password } = parsed.data
    const accountKey = email.toLowerCase()

    const tracker = loginAttempts.get(accountKey)
    if (tracker && tracker.lockedUntil > now) {
      const minutesLeft = Math.ceil((tracker.lockedUntil - now) / 60000)
      return NextResponse.json(
        { error: `Too many failed attempts. Try again in ${minutesLeft} minute${minutesLeft !== 1 ? 's' : ''}.` },
        { status: 429 }
      )
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, name, email, password_hash, role, created_at')
      .eq('email', accountKey)
      .single()

    const isValid = error || !user
      ? await bcrypt.compare(password, DUMMY_HASH).then(() => false)
      : await bcrypt.compare(password, user.password_hash as string)

    if (error || !user || !isValid) {
      const current = loginAttempts.get(accountKey) ?? { attempts: 0, lockedUntil: 0 }
      current.attempts += 1
      if (current.attempts >= maxAttempts) current.lockedUntil = now + LOCKOUT_DURATION_MS
      loginAttempts.set(accountKey, current)
      if (user) {
        await supabase.from('audit_logs').insert({
          user_id: user.id,
          action: 'login_failed',
          details: { email, reason: 'invalid_password', ip, attempts: current.attempts },
        })
      }
      return NextResponse.json({ error: 'Invalid email or password' }, { status: 401 })
    }
    // Clear failed attempts on successful login
    loginAttempts.delete(accountKey)

    const token = await signToken({
      sub: user.id as string,
      email: user.email as string,
      role: user.role as 'admin' | 'technician',
      name: user.name as string,
    })
    await supabase.from('audit_logs').insert({
      user_id: user.id,
      action: 'login_success',
      details: { email, ip },
    })
    const response = NextResponse.json({
      data: { id: user.id, name: user.name, email: user.email, role: user.role, created_at: user.created_at },
    })
    response.cookies.set('sentrix_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 86400,
      path: '/',
    })
    return response
  } catch (err) {
    console.error('Login error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
