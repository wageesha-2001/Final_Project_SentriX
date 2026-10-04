import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

if (!supabaseUrl || supabaseUrl.includes('REPLACE_WITH') || supabaseUrl === 'your_supabase_project_url') {
  throw new Error('NEXT_PUBLIC_SUPABASE_URL must be set before using the Supabase browser client')
}
if (!supabaseAnonKey || supabaseAnonKey === 'your_supabase_anon_key') {
  throw new Error('NEXT_PUBLIC_SUPABASE_ANON_KEY must be set before using the Supabase browser client')
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey)
