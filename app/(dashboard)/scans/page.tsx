'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Scan } from '@/types'
import { formatDate, formatDuration } from '@/lib/utils'
import { History, Search, ExternalLink, Cpu, Clock, CheckCircle, XCircle, AlertCircle } from 'lucide-react'

export default function ScanHistoryPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  useEffect(() => {
    fetch('/api/scans').then(r => r.json()).then(d => setScans(d.data || [])).finally(() => setLoading(false))
  }, [])

  const filtered = scans.filter(s =>
    s.scan_name.toLowerCase().includes(search.toLowerCase()) ||
    s.network_range.includes(search)
  )

  const statusIcon = (status: string) => {
    const icons: Record<string, JSX.Element> = {
      completed: <CheckCircle className="w-4 h-4 text-cyber-green" />,
      running: <AlertCircle className="w-4 h-4 text-cyber-accent animate-pulse" />,
      stopped: <XCircle className="w-4 h-4 text-cyber-muted" />,
      failed: <XCircle className="w-4 h-4 text-cyber-red" />,
      pending: <Clock className="w-4 h-4 text-cyber-yellow" />,
    }
    return icons[status] || <Clock className="w-4 h-4 text-cyber-muted" />
  }

  return (
    <DashboardLayout title="Scan History" subtitle="All previous security audits"
      actions={
        <Link href="/scans/new" className="cyber-btn-primary px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-2">
          <Search className="w-3.5 h-3.5" /> New Scan
        </Link>
      }>
      <div className="space-y-4">
        <div className="flex gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search by name or network range..."
              className="cyber-input w-full pl-10 pr-4 py-2.5 rounded-lg text-sm" />
          </div>
        </div>

        {loading ? <LoadingSpinner size="lg" text="Loading scan history..." className="h-48" /> :
         filtered.length === 0 ? (
           <EmptyState icon={History} title="No scans found"
             description={search ? 'No scans match your search.' : 'Start your first network security audit.'}
             action={!search && <Link href="/scans/new" className="cyber-btn-primary px-4 py-2 rounded-lg text-sm font-bold">New Scan</Link>} />
         ) : (
           <div className="cyber-card overflow-hidden">
             <div className="overflow-x-auto">
               <table className="w-full">
                 <thead>
                   <tr className="border-b border-cyber-border bg-cyber-surface/50">
                     {['Status', 'Scan Name', 'Network', 'Devices', 'Risk', 'Started', 'Duration'].map(h => (
                       <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-cyber-text-muted uppercase tracking-wider">{h}</th>
                     ))}
                     <th className="px-4 py-3"></th>
                   </tr>
                 </thead>
                 <tbody>
                   {filtered.map((scan, i) => (
                     <motion.tr key={scan.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }}
                       className="border-b border-cyber-border/50 hover:bg-cyber-surface/30 transition-colors">
                       <td className="px-4 py-3">{statusIcon(scan.status)}</td>
                       <td className="px-4 py-3">
                         <p className="text-sm font-medium text-white">{scan.scan_name}</p>
                         <p className="text-xs text-cyber-muted capitalize">{scan.status}</p>
                       </td>
                       <td className="px-4 py-3"><span className="text-xs font-mono text-cyber-accent">{scan.network_range}</span></td>
                       <td className="px-4 py-3">
                         <div className="flex items-center gap-1.5">
                           <Cpu className="w-3.5 h-3.5 text-cyber-muted" />
                           <span className="text-sm text-white">{scan.total_devices}</span>
                         </div>
                       </td>
                       <td className="px-4 py-3"><RiskBadge level={scan.overall_risk} size="sm" /></td>
                       <td className="px-4 py-3 text-xs text-cyber-text-muted">{formatDate(scan.started_at)}</td>
                       <td className="px-4 py-3 text-xs text-cyber-muted font-mono">
                         {scan.completed_at ? formatDuration(scan.started_at, scan.completed_at) : '—'}
                       </td>
                       <td className="px-4 py-3">
                         <Link href={scan.status === 'running' ? `/scans/${scan.id}/progress` : `/scans/${scan.id}`}
                           className="p-1.5 rounded text-cyber-muted hover:text-cyber-accent transition-colors">
                           <ExternalLink className="w-4 h-4" />
                         </Link>
                       </td>
                     </motion.tr>
                   ))}
                 </tbody>
               </table>
             </div>
           </div>
         )}
      </div>
    </DashboardLayout>
  )
}
