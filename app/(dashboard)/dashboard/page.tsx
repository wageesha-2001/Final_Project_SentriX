'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import Link from 'next/link'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { StatCard } from '@/components/ui/StatCard'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { SimulatedDataBanner, SimulatedTag } from '@/components/ui/SimulatedDataBanner'
import { formatDate, formatDuration } from '@/lib/utils'
import { Cpu, Shield, AlertTriangle, Zap, Search, ArrowRight, Activity } from 'lucide-react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { Scan } from '@/types'

interface DashboardData {
  total_devices: number
  camera_devices: number
  nvr_devices: number
  potential_devices: number
  secure_devices: number
  vulnerable_devices: number
  critical_devices: number
  total_scans: number
  latest_scan: Scan | null
  recent_scans: Scan[]
  risk_distribution: { name: string; value: number; color: string }[]
  has_simulated_data: boolean
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/dashboard')
      .then(r => r.json())
      .then(d => setData(d.data))
      .finally(() => setLoading(false))
  }, [])

  const statusColors: Record<string, string> = {
    completed: 'text-cyber-green', running: 'text-cyber-accent', pending: 'text-cyber-yellow',
    stopped: 'text-cyber-muted', failed: 'text-cyber-red',
  }

  return (
    <DashboardLayout title="Dashboard" subtitle="Security Overview">
      {loading ? (
        <div className="flex items-center justify-center h-64">
          <LoadingSpinner size="lg" text="Loading dashboard..." />
        </div>
      ) : data ? (
        <div className="space-y-6">
          {data.has_simulated_data && <SimulatedDataBanner context="dashboard" />}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
            <StatCard title="CCTV Devices" value={data.total_devices} icon={Cpu} color="accent"
              subtitle={`${data.camera_devices} cameras • ${data.nvr_devices} NVR/DVR`} delay={0} />
            <StatCard title="Secure" value={data.secure_devices} icon={Shield} color="green" subtitle="No findings or matches" delay={0.1} />
            <StatCard title="Potential Issues" value={data.potential_devices} icon={Search} color="purple" subtitle="Potential matches to review" delay={0.15} />
            <StatCard title="Vulnerable" value={data.vulnerable_devices} icon={AlertTriangle} color="yellow" subtitle="Confirmed findings" delay={0.2} />
            <StatCard title="Critical Risk" value={data.critical_devices} icon={Zap} color="red" subtitle="Immediate action required" delay={0.3} />
          </div>
          <p className="text-xs text-cyber-muted -mt-3">
            Each device is counted once, using its most recent completed scan.
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
              className="cyber-card p-6 lg:col-span-1">
              <h2 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider mb-4">Risk Distribution</h2>
              {data.risk_distribution.some(d => d.value > 0) ? (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={data.risk_distribution.filter(d => d.value > 0)} cx="50%" cy="50%"
                      innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value">
                      {data.risk_distribution.filter(d => d.value > 0).map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1e2d3d', borderRadius: '8px', color: '#e2e8f0' }} />
                    <Legend iconType="circle" iconSize={8} formatter={(v) => <span style={{ color: '#718096', fontSize: 12 }}>{v}</span>} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-48 text-cyber-muted">
                  <p className="text-sm">No scan data yet</p>
                </div>
              )}
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}
              className="cyber-card p-6 lg:col-span-2">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider">Recent Scans</h2>
                <Link href="/scans" className="text-xs text-cyber-accent hover:underline flex items-center gap-1">
                  View All <ArrowRight className="w-3 h-3" />
                </Link>
              </div>
              {data.recent_scans.length > 0 ? (
                <div className="space-y-3">
                  {data.recent_scans.map(scan => (
                    <Link key={scan.id} href={scan.status === 'running' || scan.status === 'pending' ? `/scans/${scan.id}/progress` : `/scans/${scan.id}`}
                      className="flex items-center justify-between p-3 bg-cyber-surface rounded-lg hover:bg-cyber-border/30 transition-colors group">
                      <div className="flex items-center gap-3">
                        <div className={`w-2 h-2 rounded-full ${scan.status === 'running' ? 'bg-cyber-accent animate-pulse' : scan.status === 'completed' ? 'bg-cyber-green' : 'bg-cyber-muted'}`} />
                        <div>
                          <p className="text-sm font-medium text-white group-hover:text-cyber-accent transition-colors">{scan.scan_name}</p>
                          <p className="text-xs text-cyber-muted font-mono">{scan.network_range} • {formatDate(scan.started_at)}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {scan.scan_mode === 'simulated' && <SimulatedTag />}
                        {scan.status === 'completed' && <RiskBadge level={scan.overall_risk} size="sm" />}
                        <span className={`text-xs font-medium ${statusColors[scan.status] || 'text-cyber-muted'}`}>
                          {scan.status.toUpperCase()}
                        </span>
                      </div>
                    </Link>
                  ))}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-40 gap-3">
                  <Activity className="w-10 h-10 text-cyber-muted" />
                  <p className="text-cyber-muted text-sm">No scans yet</p>
                  <Link href="/scans/new"
                    className="cyber-btn-primary px-4 py-2 rounded-lg text-xs font-bold">
                    Start First Scan
                  </Link>
                </div>
              )}
            </motion.div>
          </div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}
            className="cyber-card p-6 bg-gradient-to-r from-cyber-accent/5 to-cyber-green/5 border-cyber-accent/20">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-cyber-accent uppercase tracking-wider">Quick Actions</h2>
                <p className="text-cyber-text-muted text-sm mt-1">Start auditing your CCTV network now</p>
              </div>
              <Link href="/scans/new"
                className="cyber-btn-primary px-6 py-2.5 rounded-lg text-sm font-bold flex items-center gap-2">
                <Search className="w-4 h-4" /> New Scan
              </Link>
            </div>
          </motion.div>
        </div>
      ) : (
        <div className="text-center text-cyber-muted py-20">Failed to load dashboard data.</div>
      )}
    </DashboardLayout>
  )
}
