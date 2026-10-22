import { createClient } from '@supabase/supabase-js'
import { createLocalClient } from './local-db'

const isLocalMode =
  !process.env.NEXT_PUBLIC_SUPABASE_URL ||
  process.env.NEXT_PUBLIC_SUPABASE_URL.includes('REPLACE_WITH') ||
  process.env.NEXT_PUBLIC_SUPABASE_URL === 'your_supabase_project_url'

export function createServerSupabase() {
  if (isLocalMode) {
    // The local fallback is seeded with publicly documented demo
    // credentials — never allow it to be silently used in production.
    // Checked here (on actual use), not at module load: `next build` sets
    // NODE_ENV=production while statically analyzing every route module,
    // and a module-level throw would fail the build itself rather than
    // just refusing to serve real production traffic.
    // SENTRIX_ALLOW_LOCAL_DB=1 is an explicit opt-in for POC/demo deployments.
    if (process.env.NODE_ENV === 'production' && process.env.SENTRIX_ALLOW_LOCAL_DB !== '1') {
      throw new Error(
        '[SentriX] Refusing to start in production without a real Supabase configuration. ' +
        'Set NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY, ' +
        'or set SENTRIX_ALLOW_LOCAL_DB=1 to use the in-memory demo database.'
      )
    }
    // eslint-disable-next-line no-console
    console.log('[SentriX] Running in LOCAL mode (no Supabase)')
    return createLocalClient() as any
  }
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
  const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!
  return createClient(supabaseUrl, supabaseServiceKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  })
}
