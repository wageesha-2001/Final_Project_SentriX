'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Report } from '@/types'
import { formatDate } from '@/lib/utils'
import { FileText, Download, ExternalLink } from 'lucide-react'
import toast from 'react-hot-toast'

export default function ReportPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`/api/reports/${scanId}`).then(r => r.json()).then(d => {
      if (d.data) setReport(d.data)
    }).finally(() => setLoading(false))
  }, [scanId])

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
  if (!report) return <DashboardLayout title="Report"><EmptyState icon={FileText} title="Report not found" description="Generate a report from the scan results page." /></DashboardLayout>

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
