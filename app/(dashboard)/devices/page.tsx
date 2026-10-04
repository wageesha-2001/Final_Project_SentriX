'use client'

import { Suspense, useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Device } from '@/types'
import { formatDate } from '@/lib/utils'
import { Cpu, Search, Filter, ExternalLink } from 'lucide-react'

function DevicesContent() {
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filterRisk, setFilterRisk] = useState('all')
  const searchParams = useSearchParams()
  const scanFilter = searchParams.get('scan')

  useEffect(() => {
    fetch('/api/devices')
      .then(r => r.json())
      .then(d => {
        const all: Device[] = d.data || []
        setDevices(scanFilter ? all.filter(dev => dev.scan_id === scanFilter) : all)
      })
      .catch(() => setDevices([]))
      .finally(() => setLoading(false))
  }, [scanFilter])

  const filtered = devices.filter(d => {
    const matchSearch = d.ip_address.includes(search) || d.vendor.toLowerCase().includes(search.toLowerCase()) || d.model.toLowerCase().includes(search.toLowerCase())
    const matchRisk = filterRisk === 'all' || d.risk_level === filterRisk
    return matchSearch && matchRisk
  })

  return (
    <DashboardLayout title="Devices" subtitle="All discovered CCTV devices">
      <div className="space-y-4">
        <div className="flex flex-wrap gap-3">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by IP, vendor, or model..."
              className="cyber-input w-full pl-10 pr-4 py-2.5 rounded-lg text-sm" />
          </div>
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <select value={filterRisk} onChange={e => setFilterRisk(e.target.value)}
              className="cyber-input pl-10 pr-8 py-2.5 rounded-lg text-sm appearance-none cursor-pointer">
              <option value="all">All Risk Levels</option>
              <option value="secure">Secure</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>

        {loading ? <LoadingSpinner size="lg" text="Loading devices..." className="h-48" /> :
         filtered.length === 0 ? (
           <EmptyState icon={Cpu} title="No devices found"
             description={search ? 'No devices match your search.' : 'Run a scan to discover devices on your network.'} />
         ) : (
           <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
             {filtered.map((device, i) => (
               <motion.div key={device.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                 className="cyber-card p-4 hover:border-cyber-accent/30 transition-colors group">
                 <div className="flex items-start justify-between mb-3">
                   <div className="flex items-center gap-3">
                     <div className="w-10 h-10 rounded-lg bg-cyber-surface border border-cyber-border flex items-center justify-center group-hover:border-cyber-accent/40 transition-colors">
                       <Cpu className="w-5 h-5 text-cyber-accent" />
                     </div>
                     <div>
                       <p className="font-semibold text-white text-sm">{device.vendor}</p>
                       <p className="text-xs text-cyber-muted">{device.model}</p>
                     </div>
                   </div>
                   <RiskBadge level={device.risk_level} showScore={device.risk_score} size="sm" />
                 </div>
                 <div className="space-y-1.5 text-xs mb-3">
                   <div className="flex justify-between"><span className="text-cyber-muted">IP:</span><span className="text-white font-mono">{device.ip_address}</span></div>
                   <div className="flex justify-between"><span className="text-cyber-muted">Type:</span><span className="text-white capitalize">{device.device_type}</span></div>
                   <div className="flex justify-between"><span className="text-cyber-muted">Ports:</span><span className="text-white font-mono">{device.open_ports.map(p => p.port).join(', ')}</span></div>
                   <div className="flex justify-between"><span className="text-cyber-muted">Scanned:</span><span className="text-white">{formatDate(device.created_at)}</span></div>
                 </div>
                 <Link href={`/devices/${device.id}`}
                   className="flex items-center justify-center gap-2 w-full py-2 rounded-lg border border-cyber-border text-xs text-cyber-text-muted hover:text-cyber-accent hover:border-cyber-accent/30 transition-colors">
                   <ExternalLink className="w-3.5 h-3.5" /> View Details
                 </Link>
               </motion.div>
             ))}
           </div>
         )}
      </div>
    </DashboardLayout>
  )
}

export default function DevicesPage() {
  return (
    <Suspense fallback={<DashboardLayout title="Devices"><LoadingSpinner size="lg" className="h-64" /></DashboardLayout>}>
      <DevicesContent />
    </Suspense>
  )
}
