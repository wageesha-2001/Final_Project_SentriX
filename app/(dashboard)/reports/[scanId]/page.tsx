'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Report } from '@/types'
import { formatDate } from '@/lib/utils'
import { FileText, Download, ExternalLink, SearchX, Lock } from 'lucide-react'
import Link from 'next/link'
import toast from 'react-hot-toast'

export default function ReportPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  // Why there is no report: only a completed scan without one can generate it
  const [missing, setMissing] = useState<'scan_not_found' | 'forbidden' | 'not_completed' | 'not_generated'>('not_generated')

  useEffect(() => {
    fetch(`/api/reports/${scanId}`).then(async r => {
      const d = await r.json().catch(() => ({}))
      if (d.data) setReport(d.data)
      else if (r.status === 403) setMissing('forbidden')
      else if (d.reason === 'scan_not_found') setMissing('scan_not_found')
      else if (d.scan_status && d.scan_status !== 'completed') setMissing('not_completed')
    }).finally(() => setLoading(false))
  }, [scanId])

  const handleGenerate = async () => {
    setGenerating(true)
    try {
      const res = await fetch(`/api/reports/${scanId}/generate`, { method: 'POST' })
      const d = await res.json()
      if (res.ok && d.data) { setReport(d.data); toast.success('Report generated!') }
      else toast.error(d.error || 'Failed to generate report')
    } catch { toast.error('Error generating report') }
    finally { setGenerating(false) }
  }

  const handleDownload = () => {
    if (!report) return
    const blob = new Blob([report.report_html], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${report.report_title.replace(/[^a-z0-9]/gi, '_')}.html`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('Report downloaded')
  }

  const handleOpenNew = () => {
    if (!report) return
    const blob = new Blob([report.report_html], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    window.open(url, '_blank')
  }

  if (loading) return <DashboardLayout title="Report"><LoadingSpinner size="lg" className="h-64" /></DashboardLayout>
  if (!report && missing !== 'not_generated') {
    const info = {
      scan_not_found: { icon: SearchX, title: 'Scan not found', description: 'There is no scan with this id. It may have been deleted, or the link is wrong.' },
      forbidden: { icon: Lock, title: 'You do not have access to this report', description: 'Reports can only be viewed by the user who ran the scan or an admin.' },
      not_completed: { icon: FileText, title: 'Report not available yet', description: 'Reports can only be generated for completed scans.' },
    }[missing]
    return (
      <DashboardLayout title="Report">
        <EmptyState icon={info.icon} title={info.title} description={info.description}
          action={<Link href="/reports" className="cyber-btn-primary px-4 py-2 rounded-lg text-sm font-bold">Back to Reports</Link>} />
      </DashboardLayout>
    )
  }
  if (!report) return (
    <DashboardLayout title="Report">
      <EmptyState icon={FileText} title="Report not generated yet"
        description="Generate the security report for this scan to view and download it."
        action={
          <button onClick={handleGenerate} disabled={generating}
            className="cyber-btn-primary flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold">
            {generating ? <span className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> : <FileText className="w-4 h-4" />}
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        } />
    </DashboardLayout>
  )

  return (
    <DashboardLayout title="Security Report" subtitle={report.report_title}
      actions={
        <div className="flex gap-2">
          <button onClick={handleOpenNew}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyber-border text-cyber-text-muted hover:text-white text-xs font-medium transition-colors">
            <ExternalLink className="w-3.5 h-3.5" /> Open
          </button>
          <button onClick={handleDownload}
            className="cyber-btn-primary flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold">
            <Download className="w-3.5 h-3.5" /> Download HTML
          </button>
        </div>
      }>
      <div className="space-y-4">
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="cyber-card p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FileText className="w-5 h-5 text-cyber-accent" />
            <div>
              <p className="font-semibold text-white text-sm">{report.report_title}</p>
              <p className="text-xs text-cyber-muted">Generated: {formatDate(report.created_at)}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="cyber-card overflow-hidden">
          <div className="h-[70vh] overflow-hidden rounded-xl">
            <iframe srcDoc={report.report_html} className="w-full h-full border-0" title="Security Report" sandbox="allow-same-origin" />
          </div>
        </motion.div>
      </div>
    </DashboardLayout>
  )
}
