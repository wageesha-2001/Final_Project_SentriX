import { NextRequest, NextResponse } from 'next/server'
import { verifyToken } from './jwt'
import { createServerSupabase } from '@/lib/supabase/server'
import { JWTPayload, UserRole } from '@/types'

/**
 * Resolve the signed-in user. A valid signature is not enough: the account
 * must still exist, so deleting a user ends their sessions immediately.
 * The role always comes from the database, never from the token, so a token
 * minted before a role change cannot keep the old privileges.
 * A token revoked by logout (its jti is in revoked_tokens) is rejected too.
 */
export async function getAuthUser(req: NextRequest): Promise<JWTPayload | null> {
  const token = req.cookies.get('sentrix_token')?.value
  if (!token) return null
  let payload: JWTPayload
  try {
    payload = await verifyToken(token)
  } catch {
    return null
  }
  // Tokens issued before revocation existed carry no jti and cannot be logged out.
  if (!payload.jti) return null
  try {
    const supabase = createServerSupabase()
    const { data: revoked } = await supabase
      .from('revoked_tokens')
      .select('jti')
      .eq('jti', payload.jti)
      .limit(1)
    if (revoked && revoked.length > 0) return null
    const { data: account } = await supabase
      .from('users')
      .select('id, email, role')
      .eq('id', payload.sub)
      .single()
    if (!account) return null
    return { ...payload, email: account.email, role: account.role }
  } catch {
    return null
  }
}

export function requireAuth(user: JWTPayload | null): NextResponse | null {
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  return null
}

export function requireRole(user: JWTPayload | null, role: UserRole): NextResponse | null {
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  if (user.role !== role && user.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  return null
}
