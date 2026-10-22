import { createLocalClient } from '@/lib/supabase/local-db'

describe('LocalDB QueryBuilder', () => {
  const client = createLocalClient()

  it('inserts a row and retrieves it by eq', async () => {
    const { data: inserted } = await client
      .from('audit_logs')
      .insert({ user_id: 'u1', action: 'test_action', details: {} })
      .select()
      .single()

    expect(inserted).toBeTruthy()
    expect((inserted as Record<string,unknown>).action).toBe('test_action')

    const { data: found } = await client
      .from('audit_logs')
      .select('*')
      .eq('action', 'test_action')
      .single()
    expect((found as Record<string,unknown>).user_id).toBe('u1')
  })

  it('returns error when single() finds nothing', async () => {
    const { data, error } = await client
      .from('audit_logs')
      .select('*')
      .eq('action', 'nonexistent_action_xyz')
      .single()
    expect(data).toBeNull()
    expect(error).toBeTruthy()
  })

  it('filters with multiple eq conditions', async () => {
    await client.from('audit_logs').insert({ user_id: 'u2', action: 'multi_test', details: {} })
    await client.from('audit_logs').insert({ user_id: 'u3', action: 'multi_test', details: {} })

    const { data } = await client
      .from('audit_logs')
      .select('*')
      .eq('action', 'multi_test')
      .eq('user_id', 'u2')
    expect((data as unknown[]).length).toBe(1)
  })

  it('upsert updates existing row on conflict', async () => {
    const { data: row } = await client
      .from('settings')
      .select('*')
      .eq('user_id', 'a0000000-0000-0000-0000-000000000001')
      .single()

    await client
      .from('settings')
      .upsert({ ...(row as Record<string,unknown>), scan_timeout: 999 }, { onConflict: 'user_id' })

    const { data: updated } = await client
      .from('settings')
      .select('*')
      .eq('user_id', 'a0000000-0000-0000-0000-000000000001')
      .single()
    expect((updated as Record<string,unknown>).scan_timeout).toBe(999)
  })

  it('delete removes matching rows', async () => {
    await client.from('audit_logs').insert({ user_id: 'del_user', action: 'to_delete', details: {} })
    await client.from('audit_logs').delete().eq('action', 'to_delete')
    const { data } = await client.from('audit_logs').select('*').eq('action', 'to_delete')
    expect((data as unknown[]).length).toBe(0)
  })

  it('order sorts results correctly', async () => {
    const { data } = await client
      .from('vulnerability_checks')
      .select('*')
      .order('risk_score', { ascending: false })
    const scores = (data as Array<{ risk_score: number }>).map(r => r.risk_score)
    for (let i = 1; i < scores.length; i++) {
      expect(scores[i]).toBeLessThanOrEqual(scores[i - 1])
    }
  })

  it('limit restricts result count', async () => {
    const { data } = await client
      .from('vulnerability_checks')
      .select('*')
      .limit(3)
    expect((data as unknown[]).length).toBeLessThanOrEqual(3)
  })
})

describe('LocalDB shared store', () => {
  it('shares one store across separately loaded module copies (Next.js compiles each route separately)', async () => {
    let a: ReturnType<typeof createLocalClient> | undefined
    let b: ReturnType<typeof createLocalClient> | undefined
    jest.isolateModules(() => { a = require('@/lib/supabase/local-db').createLocalClient() })
    jest.isolateModules(() => { b = require('@/lib/supabase/local-db').createLocalClient() })
    await a!.from('scans').insert({ id: 'shared-scan-1', scan_name: 'shared' })
    const { data } = await b!.from('scans').select('*').eq('id', 'shared-scan-1').single()
    expect(data).toMatchObject({ scan_name: 'shared' })
  })
})
