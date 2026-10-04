'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Scan } from '@/types'
import { formatDate } from '@/lib/utils'
import { FileText, Download, ExternalLink } from 'lucide-react'

export default function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/scans').then(r => r.json()).then(d => {
      setScans((d.data || []).filter((s: Scan) => s.status === 'completed'))
    }).finally(() => setLoading(false))
  }, [])

  return (
    <DashboardLayout title="Reports" subtitle="Security audit reports">
      <div className="space-y-4">
        {loading ? <LoadingSpinner size="lg" text="Loading reports..." className="h-48" /> :
         scans.length === 0 ? (
           <EmptyState icon={FileText} title="No reports yet"
             description="Complete a scan and generate a report."
             action={<Link href="/scans/new" className="cyber-btn-primary px-4 py-2 rounded-lg text-sm font-bold">New Scan</Link>} />
         ) : (
           <div className="space-y-3">
             {scans.map((scan, i) => (
               <motion.div key={scan.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                 className="cyber-card p-4 flex items-center justify-between gap-4 group hover:border-cyber-accent/30 transition-colors">
                 <div className="flex items-center gap-4">
                   <div className="w-10 h-10 rounded-lg bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
                     <FileText className="w-5 h-5 text-cyber-accent" />
                   </div>
                   <div>
                     <p className="font-semibold text-white text-sm group-hover:text-cyber-accent transition-colors">{scan.scan_name}</p>
                     <p className="text-xs text-cyber-muted">{formatDate(scan.started_at)} • {scan.network_range} • {scan.total_devices} devices</p>
                   </div>
                 </div>
                 <div className="flex items-center gap-3">
                   <RiskBadge level={scan.overall_risk} size="sm" />
                   <Link href={`/reports/${scan.id}`}
                     className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyber-border text-xs text-cyber-text-muted hover:text-white hover:border-cyber-muted transition-colors">
                     <ExternalLink className="w-3.5 h-3.5" /> View
                   </Link>
                 </div>
               </motion.div>
             ))}
           </div>
         )}
      </div>
    </DashboardLayout>
  )
}
