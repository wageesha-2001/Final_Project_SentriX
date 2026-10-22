import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

export async function POST(req: NextRequest) {
  const user = await getAuthUser(req)
  if (user) {
    const supabase = createServerSupabase()
    // Revoke this token server-side: clearing the cookie alone leaves a copied
    // token usable until it expires.
    if (user.jti) {
      await supabase.from('revoked_tokens').insert({
        jti: user.jti,
        user_id: user.sub,
        expires_at: new Date(user.exp * 1000).toISOString(),
      })
    }
    await supabase.from('audit_logs').insert({
      user_id: user.sub,
      action: 'logout',
      details: { email: user.email },
    })
  }
  const response = NextResponse.json({ message: 'Logged out' })
  response.cookies.set('sentrix_token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 0,
    path: '/',
  })
  return response
}
