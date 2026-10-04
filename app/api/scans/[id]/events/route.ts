import { NextRequest } from 'next/server'
import { getAuthUser } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getAuthUser(req)
  if (!user) return new Response('Unauthorized', { status: 401 })

  const encoder = new TextEncoder()
  let closed = false

  const stream = new ReadableStream({
    async start(controller) {
      const send = (data: object) => {
        if (closed) return
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`))
        } catch { closed = true }
      }

      const poll = async () => {
        if (closed) return
        const supabase = createServerSupabase()
        const { data: scan } = await supabase.from('scans').select('*').eq('id', params.id).single()
        if (!scan) { send({ error: 'not_found' }); controller.close(); return }
        if (user.role !== 'admin' && scan.user_id !== user.sub) {
          send({ error: 'forbidden' }); controller.close(); return
        }
        send({ scan })
        if (scan.status === 'completed' || scan.status === 'stopped' || scan.status === 'failed') {
          controller.close()
          return
        }
        setTimeout(poll, 1500)
      }

      req.signal.addEventListener('abort', () => { closed = true; try { controller.close() } catch { /* already closed */ } })
      await poll()
    }
  })

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  })
}
