import { cn } from '@/lib/utils'
import { RiskLevel, VulnerabilitySeverity } from '@/types'

interface RiskBadgeProps {
  level: RiskLevel | VulnerabilitySeverity
  showScore?: number
  size?: 'sm' | 'md' | 'lg'
}

const configs: Record<string, { label: string; classes: string }> = {
  secure: { label: 'SECURE', classes: 'bg-cyber-green/10 text-cyber-green border-cyber-green/30' },
  low: { label: 'LOW', classes: 'bg-blue-400/10 text-blue-400 border-blue-400/30' },
  medium: { label: 'MEDIUM', classes: 'bg-cyber-yellow/10 text-cyber-yellow border-cyber-yellow/30' },
  high: { label: 'HIGH', classes: 'bg-orange-400/10 text-orange-400 border-orange-400/30' },
  critical: { label: 'CRITICAL', classes: 'bg-cyber-red/10 text-cyber-red border-cyber-red/30' },
}

const sizeClasses = {
  sm: 'text-[10px] px-2 py-0.5',
  md: 'text-xs px-3 py-1',
  lg: 'text-sm px-4 py-1.5',
}

export function RiskBadge({ level, showScore, size = 'md' }: RiskBadgeProps) {
  const config = configs[level] || configs.secure
  return (
    <span className={cn('inline-flex items-center gap-1 border rounded font-bold tracking-wider', config.classes, sizeClasses[size])}>
      {config.label}
      {showScore !== undefined && <span className="opacity-70">({showScore})</span>}
    </span>
  )
}
