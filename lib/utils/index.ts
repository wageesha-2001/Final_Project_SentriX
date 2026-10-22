import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { RiskLevel, VulnerabilitySeverity } from '@/types'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function getRiskColor(risk: RiskLevel | VulnerabilitySeverity): string {
  const colors: Record<string, string> = {
    secure: 'text-cyber-green',
    low: 'text-blue-400',
    medium: 'text-cyber-yellow',
    high: 'text-orange-400',
    critical: 'text-cyber-red',
  }
  return colors[risk] || 'text-cyber-muted'
}

export function getRiskBgColor(risk: RiskLevel | VulnerabilitySeverity): string {
  const colors: Record<string, string> = {
    secure: 'bg-cyber-green/10 border-cyber-green/30',
    low: 'bg-blue-400/10 border-blue-400/30',
    medium: 'bg-cyber-yellow/10 border-cyber-yellow/30',
    high: 'bg-orange-400/10 border-orange-400/30',
    critical: 'bg-cyber-red/10 border-cyber-red/30',
  }
  return colors[risk] || 'bg-gray-400/10 border-gray-400/30'
}

export function formatDate(dateStr: string | null | undefined): string {
  const date = dateStr ? new Date(dateStr) : null
  if (!date || isNaN(date.getTime())) return '—'
  return date.toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export function formatDuration(start: string | null | undefined, end?: string | null): string {
  const startTime = start ? new Date(start).getTime() : NaN
  if (isNaN(startTime)) return '—'
  const endTime = end ? new Date(end).getTime() : Date.now()
  const diff = Math.floor((endTime - startTime) / 1000)
  if (diff < 60) return `${diff}s`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`
  return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`
}

export function getNetworkSize(cidr: string): number {
  const parts = cidr.split('/')
  if (parts.length < 2) return 1
  const prefix = parseInt(parts[1])
  return Math.pow(2, 32 - prefix)
}
