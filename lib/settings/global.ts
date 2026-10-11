import type { createServerSupabase } from '@/lib/supabase/server'

export interface GlobalSettings {
  safe_scan_mode: boolean
  scan_timeout: number
  login_attempt_limit: number
}

export const DEFAULT_SETTINGS: GlobalSettings = {
  safe_scan_mode: true,
  scan_timeout: 300,
  login_attempt_limit: 5,
}

/**
 * Scanner settings are global and admin-managed: the effective values are the
 * most recently updated settings row that belongs to an admin. Rows owned by
 * technicians are ignored, so they can never change login lockout or Safe
 * Scan Mode for anyone.
 */
export async function getGlobalSettings(supabase: ReturnType<typeof createServerSupabase>): Promise<GlobalSettings> {
  const { data: admins } = await supabase.from('users').select('id').eq('role', 'admin')
  const adminIds = ((admins as { id: string }[] | null) ?? []).map(a => a.id)
  if (adminIds.length === 0) return DEFAULT_SETTINGS

  const { data } = await supabase
    .from('settings')
    .select('safe_scan_mode, scan_timeout, login_attempt_limit')
    .in('user_id', adminIds)
    .order('updated_at', { ascending: false })
    .limit(1)
  const row = (data as Partial<GlobalSettings>[] | null)?.[0]
  return {
    safe_scan_mode: row?.safe_scan_mode ?? DEFAULT_SETTINGS.safe_scan_mode,
    scan_timeout: row?.scan_timeout ?? DEFAULT_SETTINGS.scan_timeout,
    login_attempt_limit: row?.login_attempt_limit ?? DEFAULT_SETTINGS.login_attempt_limit,
  }
}
