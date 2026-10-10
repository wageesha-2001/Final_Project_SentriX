'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import Link from 'next/link'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Scan } from '@/types'
import { formatDate } from '@/lib/utils'
import { Shield, StopCircle, CheckCircle, Cpu, AlertTriangle } from 'lucide-react'
import toast from 'react-hot-toast'

export default function ScanProgressPage() {
  const { id } = useParams<{ id: string }>()
  const router = useRouter()
  const [scan, setScan] = useState<Scan | null>(null)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [showStop, setShowStop] = useState(false)
  const [stopping, setStopping] = useState(false)

  useEffect(() => {
    const source = new EventSource(`/api/scans/${id}/events`)
    source.onmessage = (e) => {
      try {
        const { scan: s } = JSON.parse(e.data)
        if (!s) return
        setFetchError(null)
        setScan(s)
        if (s.status === 'completed') {
          toast.success('Scan completed!')
          source.close()
          router.push(`/scans/${id}`)
        }
        if (s.status === 'stopped' || s.status === 'failed') {
          source.close()
        }
      } catch {}
    }
    source.onerror = () => setFetchError('Connection interrupted — reconnecting...')
    return () => source.close()
  }, [id, router])

  const handleStop = async () => {
    setStopping(true)
    const res = await fetch(`/api/scans/${id}/stop`, { method: 'POST' })
    if (res.ok) {
      toast.success('Scan stopped')
      router.push('/scans')
    } else {
      toast.error('Failed to stop scan')
    }
    setStopping(false)
    setShowStop(false)
  }

  const progress = scan?.progress ?? 0
  const statusMessages: Record<string, string> = {
    pending: 'Initializing scanner...',
    running: progress < 30 ? 'Discovering devices on network...' : progress < 70 ? 'Analyzing device security...' : progress < 90 ? 'Calculating risk scores...' : 'Finalizing results...',
    completed: 'Scan completed successfully',
    stopped: 'Scan was stopped',
    failed: 'Scan failed',
  }

  return (
    <DashboardLayout title="Scan Progress" subtitle="Real-time security audit status">
      <div className="max-w-2xl mx-auto space-y-6">
        {fetchError && (
          <div className="cyber-card p-4 border-cyber-red/30 bg-cyber-red/5 text-cyber-red text-sm">
            {fetchError}
          </div>
        )}
        {scan && (
          <>
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="cyber-card p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h2 className="text-lg font-bold text-white">{scan.scan_name}</h2>
                  <p className="text-xs text-cyber-muted font-mono mt-1">{scan.network_range}</p>
                  <p className="text-xs text-cyber-text-muted mt-0.5">Started: {formatDate(scan.started_at)}</p>
                </div>
                <RiskBadge level={scan.overall_risk} />
              </div>

              <div className="space-y-3">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-cyber-text-muted">{statusMessages[scan.status] || 'Processing...'}</span>
                  <span className="text-cyber-accent font-bold font-mono">{progress}%</span>
                </div>
                <div className="h-3 bg-cyber-surface rounded-full overflow-hidden border border-cyber-border">
                  <motion.div
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.5 }}
                    className="h-full scan-progress-bar rounded-full"
                  />
                </div>
              </div>

              {scan.status === 'running' && (
                <div className="mt-4 grid grid-cols-3 gap-3 text-center">
                  {[
                    { label: 'CCTV Devices Found', value: scan.total_devices, icon: Cpu, color: 'text-cyber-accent' },
                    { label: 'Vulnerable', value: scan.vulnerable_devices, icon: AlertTriangle, color: 'text-cyber-yellow' },
                    { label: 'Critical', value: scan.critical_devices, icon: Shield, color: 'text-cyber-red' },
                  ].map(item => (
                    <div key={item.label} className="bg-cyber-surface rounded-lg p-3">
                      <item.icon className={`w-4 h-4 mx-auto mb-1 ${item.color}`} />
                      <p className={`text-xl font-bold ${item.color}`}>{item.value}</p>
                      <p className="text-xs text-cyber-muted">{item.label}</p>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>

            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}
              className="cyber-card p-4">
              <div className="flex items-center gap-2 text-xs text-cyber-text-muted font-mono">
                <div className={`w-2 h-2 rounded-full ${scan.status === 'running' ? 'bg-cyber-accent animate-pulse' : 'bg-cyber-green'}`} />
                <span className="text-cyber-accent">[ SENTRIX SCANNER ]</span>
                <span>{statusMessages[scan.status]}</span>
              </div>
              <div className="mt-3 space-y-1 text-xs font-mono">
                <p className="text-cyber-green">[+] Scan ID: {scan.id}</p>
                <p className="text-cyber-green">[+] Target: {scan.network_range}</p>
                {scan.status === 'running' && (
                  <>
                    <p className="text-cyber-accent animate-pulse">[*] Progress: {progress}%</p>
                    <p className="text-cyber-text-muted">[~] CCTV devices identified: {scan.total_devices}</p>
                  </>
                )}
                {scan.status === 'completed' && (
                  <p className="text-cyber-green">[✓] Scan completed — {scan.total_devices} CCTV devices identified (non-CCTV hosts skipped)</p>
                )}
              </div>
            </motion.div>

            {scan.status === 'running' && (
              <button onClick={() => setShowStop(true)}
                className="w-full py-3 rounded-lg border border-cyber-red/30 text-cyber-red hover:bg-cyber-red/10 transition-colors text-sm font-semibold flex items-center justify-center gap-2">
                <StopCircle className="w-4 h-4" /> Stop Scan
              </button>
            )}

            {scan.status === 'completed' && (
              <Link href={`/scans/${scan.id}`}
                className="cyber-btn-primary w-full py-3 rounded-lg text-sm font-bold flex items-center justify-center gap-2">
                <CheckCircle className="w-4 h-4" /> View Results
              </Link>
            )}
          </>
        )}
      </div>

      <ConfirmDialog isOpen={showStop} title="Stop Scan" variant="warning"
        message="Are you sure you want to stop this scan? Devices already analysed are kept with the stopped scan, but stopped scans are not included in the dashboard, device inventory or reports."
        confirmLabel={stopping ? 'Stopping...' : 'Stop Scan'} cancelLabel="Continue Scanning"
        onConfirm={handleStop} onCancel={() => setShowStop(false)} />
    </DashboardLayout>
  )
}
