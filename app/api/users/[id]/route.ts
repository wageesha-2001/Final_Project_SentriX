import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

export async function DELETE(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getAuthUser(req)
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  if (user.role !== 'admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  if (params.id === user.sub) return NextResponse.json({ error: 'Cannot delete your own account' }, { status: 400 })
  const supabase = createServerSupabase()
  const { data: target } = await supabase.from('users').select('id').eq('id', params.id).single()
  if (!target) return NextResponse.json({ error: 'User not found' }, { status: 404 })
  const { error } = await supabase.from('users').delete().eq('id', params.id)
  if (error) {
    console.error('User delete error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
  await supabase.from('audit_logs').insert({ user_id: user.sub, action: 'user_deleted', details: { deleted_id: params.id } })
  return NextResponse.json({ message: 'User deleted' })
}
