'use client'

import { useEffect, useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Shield, Activity, Filter, RefreshCw } from 'lucide-react'
import { formatDate } from '@/lib/utils'
import { cn } from '@/lib/utils'
import toast from 'react-hot-toast'

interface AuditLog {
  id: string
  user_id: string
  action: string
  details: Record<string, unknown>
  created_at: string
}

const ACTION_LABELS: Record<string, string> = {
  login_success: 'Login Success',
  login_failed: 'Login Failed',
  scan_created: 'Scan Created',
  scan_started: 'Scan Started',
  scan_stopped: 'Scan Stopped',
  report_generated: 'Report Generated',
  vulnerability_check_toggled: 'Check Toggled',
  enable_all: 'Checks Enabled (All)',
  disable_all: 'Checks Disabled (All)',
  user_created: 'User Created',
  user_deleted: 'User Deleted',
}

function getActionColor(action: string): string {
  if (action === 'login_failed') return 'text-cyber-red'
  if (action === 'scan_started' || action === 'scan_completed') return 'text-cyber-green'
  return 'text-cyber-accent'
}

function getDetailsSummary(action: string, details: Record<string, unknown>): string {
  if (!details || Object.keys(details).length === 0) return '—'
  if (action === 'scan_created' || action === 'scan_started') {
    const name = details.scan_name as string | undefined
    const range = details.network_range as string | undefined
    if (name) return `${name}${range ? ` (${range})` : ''}`
  }
  if (action === 'login_failed' || action === 'login_success') {
    const email = details.email as string | undefined
    if (email) return email
  }
  if (action === 'user_created' || action === 'user_deleted') {
    const email = details.email as string | undefined
    const role = details.role as string | undefined
    if (email) return `${email}${role ? ` [${role}]` : ''}`
  }
  if (action === 'vulnerability_check_toggled') {
    const name = details.name as string | undefined
    const enabled = details.enabled
    if (name) return `${name} — ${enabled ? 'enabled' : 'disabled'}`
  }
  const first = Object.entries(details)[0]
  if (first) return `${first[0]}: ${String(first[1])}`
  return '—'
}

const ALL_ACTIONS = Object.keys(ACTION_LABELS)

export default function AuditLogsPage() {
  const [loading, setLoading] = useState(true)
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [isAdmin, setIsAdmin] = useState(false)
  const [actionFilter, setActionFilter] = useState('')
  const [refreshing, setRefreshing] = useState(false)

  const fetchLogs = useCallback(async (showRefreshState = false) => {
    if (showRefreshState) setRefreshing(true)
    try {
      const url = actionFilter
        ? `/api/audit-logs?limit=100&action=${encodeURIComponent(actionFilter)}`
        : '/api/audit-logs?limit=100'
      const res = await fetch(url)
      if (res.ok) {
        const d = await res.json()
        setLogs(d.data || [])
      } else if (res.status === 403) {
        setIsAdmin(false)
      }
    } catch {
      toast.error('Failed to load audit logs')
    } finally {
      if (showRefreshState) setRefreshing(false)
    }
  }, [actionFilter])

  useEffect(() => {
    fetch('/api/auth/me')
      .then(r => r.json())
      .then(me => {
        if (me.data?.role === 'admin') setIsAdmin(true)
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (isAdmin) fetchLogs()
  }, [isAdmin, fetchLogs])

  if (loading) {
    return (
      <DashboardLayout title="Audit Logs">
        <LoadingSpinner size="lg" className="h-64" />
      </DashboardLayout>
    )
  }

  if (!isAdmin) {
    return (
      <DashboardLayout title="Audit Logs" subtitle="Security event history">
        <div className="flex flex-col items-center justify-center h-64 gap-4">
          <div className="p-4 rounded-xl bg-cyber-red/10 border border-cyber-red/30">
            <Shield className="w-10 h-10 text-cyber-red" />
          </div>
          <div className="text-center">
            <p className="text-white font-bold text-lg">Access Denied</p>
            <p className="text-cyber-text-muted text-sm mt-1">Admin privileges required to view audit logs.</p>
          </div>
        </div>
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout title="Audit Logs" subtitle="Security event history for all users">
      <div className="space-y-6 max-w-5xl">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="cyber-card overflow-hidden"
        >
          {/* Header */}
          <div className="p-6 border-b border-cyber-border">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyber-accent/10 border border-cyber-accent/20">
                  <Activity className="w-5 h-5 text-cyber-accent" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white">Event Log</h2>
                  <p className="text-xs text-cyber-text-muted mt-0.5">{logs.length} events</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {/* Action filter */}
                <div className="relative">
                  <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
                  <select
                    value={actionFilter}
                    onChange={e => setActionFilter(e.target.value)}
                    className="cyber-input pl-9 pr-8 py-2 rounded-lg text-xs appearance-none cursor-pointer"
                  >
                    <option value="">All Actions</option>
                    {ALL_ACTIONS.map(a => (
                      <option key={a} value={a}>{ACTION_LABELS[a]}</option>
                    ))}
                  </select>
                </div>
                {/* Refresh */}
                <button
                  onClick={() => fetchLogs(true)}
                  disabled={refreshing}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyber-surface border border-cyber-border text-cyber-text-muted hover:text-white text-xs font-medium transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={cn('w-3.5 h-3.5', refreshing && 'animate-spin')} />
                  Refresh
                </button>
              </div>
            </div>
          </div>

          {/* Table */}
          {logs.length === 0 ? (
            <div className="p-10">
              <EmptyState
                icon={Activity}
                title="No audit events yet"
                description="Security events will appear here as users interact with the system."
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-cyber-border bg-cyber-surface/40">
                    <th className="text-left px-4 py-3 text-cyber-text-muted font-semibold uppercase tracking-wider">Timestamp</th>
                    <th className="text-left px-4 py-3 text-cyber-text-muted font-semibold uppercase tracking-wider">Action</th>
                    <th className="text-left px-4 py-3 text-cyber-text-muted font-semibold uppercase tracking-wider">Details</th>
                    <th className="text-left px-4 py-3 text-cyber-text-muted font-semibold uppercase tracking-wider">User ID</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/30">
                  {logs.map((log, idx) => (
                    <motion.tr
                      key={log.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.02 }}
                      className="hover:bg-cyber-surface/30 transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-cyber-muted whitespace-nowrap">
                        {formatDate(log.created_at)}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className={cn('font-semibold', getActionColor(log.action))}>
                          {ACTION_LABELS[log.action] ?? log.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-cyber-text-muted max-w-xs truncate">
                        {getDetailsSummary(log.action, log.details)}
                      </td>
                      <td className="px-4 py-3 font-mono text-cyber-muted truncate max-w-[140px]">
                        {log.user_id}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </motion.div>
      </div>
    </DashboardLayout>
  )
}
