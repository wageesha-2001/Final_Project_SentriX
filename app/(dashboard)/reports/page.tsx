'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Scan } from '@/types'
import { formatDate } from '@/lib/utils'
import { FileText, ExternalLink } from 'lucide-react'
import toast from 'react-hot-toast'

export default function ReportsPage() {
  const router = useRouter()
  const [scans, setScans] = useState<Scan[]>([])
  const [reportDates, setReportDates] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([
      fetch('/api/scans').then(r => r.json()),
      fetch('/api/reports').then(r => r.json()),
    ]).then(([s, r]) => {
      setScans((s.data || []).filter((scan: Scan) => scan.status === 'completed'))
      const dates: Record<string, string> = {}
      for (const rep of r.data || []) dates[rep.scan_id] = rep.created_at
      setReportDates(dates)
    }).finally(() => setLoading(false))
  }, [])

  const handleGenerate = async (scanId: string) => {
    setGenerating(scanId)
    try {
      const res = await fetch(`/api/reports/${scanId}/generate`, { method: 'POST' })
      if (res.ok) { toast.success('Report generated!'); router.push(`/reports/${scanId}`) }
      else toast.error('Failed to generate report')
    } catch { toast.error('Error generating report') }
    finally { setGenerating(null) }
  }

  return (
    <DashboardLayout title="Reports" subtitle="Security audit reports">
      <div className="space-y-4">
        {loading ? <LoadingSpinner size="lg" text="Loading reports..." className="h-48" /> :
         scans.length === 0 ? (
           <EmptyState icon={FileText} title="No reports yet"
             description="Complete a scan, then generate its report here or from the scan results page."
             action={<Link href="/scans/new" className="cyber-btn-primary px-4 py-2 rounded-lg text-sm font-bold">New Scan</Link>} />
         ) : (
           <div className="space-y-3">
             {scans.map((scan, i) => {
               const generatedAt = reportDates[scan.id]
               return (
                 <motion.div key={scan.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                   className="cyber-card p-4 flex flex-wrap items-center justify-between gap-4 group hover:border-cyber-accent/30 transition-colors">
                   <div className="flex items-center gap-4 min-w-0">
                     <div className="w-10 h-10 shrink-0 rounded-lg bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
                       <FileText className="w-5 h-5 text-cyber-accent" />
                     </div>
                     <div className="min-w-0">
                       <p className="font-semibold text-white text-sm group-hover:text-cyber-accent transition-colors">{scan.scan_name}</p>
                       <p className="text-xs text-cyber-muted">{formatDate(scan.started_at)} • {scan.network_range} • {scan.total_devices} devices</p>
                       <p className={`text-xs mt-0.5 ${generatedAt ? 'text-cyber-green' : 'text-cyber-yellow'}`}>
                         {generatedAt ? `Report generated ${formatDate(generatedAt)}` : 'Report not generated yet'}
                       </p>
                     </div>
                   </div>
                   <div className="flex items-center gap-3">
                     <RiskBadge level={scan.overall_risk} size="sm" />
                     {generatedAt && (
                       <Link href={`/reports/${scan.id}`}
                         className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyber-border text-xs text-cyber-text-muted hover:text-white hover:border-cyber-muted transition-colors">
                         <ExternalLink className="w-3.5 h-3.5" /> View
                       </Link>
                     )}
                     <button onClick={() => handleGenerate(scan.id)} disabled={generating !== null}
                       className="cyber-btn-primary flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold">
                       {generating === scan.id
                         ? <span className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
                         : <FileText className="w-3.5 h-3.5" />}
                       {generating === scan.id ? 'Generating...' : generatedAt ? 'Regenerate' : 'Generate Report'}
                     </button>
                   </div>
                 </motion.div>
               )
             })}
           </div>
         )}
      </div>
    </DashboardLayout>
  )
}
