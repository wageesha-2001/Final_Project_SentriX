import { FlaskConical } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SimulatedDataBannerProps {
  /** What the simulated data is shown as, e.g. "scan", "report", "dashboard". */
  context?: string
  className?: string
}

/** Compact label for scan lists. */
export function SimulatedTag({ className }: { className?: string }) {
  return (
    <span title="Simulation mode: built-in demo devices, not a real network audit"
      className={cn('px-1.5 py-0.5 rounded border border-cyber-yellow/40 bg-cyber-yellow/10 text-[10px] font-bold uppercase tracking-wider text-cyber-yellow', className)}>
      Simulated
    </span>
  )
}

/** Warns that results come from built-in demo devices, not a real network audit. */
export function SimulatedDataBanner({ context = 'scan', className }: SimulatedDataBannerProps) {
  const message = context === 'dashboard'
    ? 'Some scans shown here ran in simulation mode. Their devices and findings are built-in demo data, not real network results.'
    : `This ${context} ran in simulation mode. Devices and findings are built-in demo data, not results from a real network audit.`
  return (
    <div role="alert" className={cn('flex items-start gap-3 p-4 rounded-lg border border-cyber-yellow/40 bg-cyber-yellow/10', className)}>
      <FlaskConical className="w-5 h-5 text-cyber-yellow mt-0.5 flex-shrink-0" />
      <div>
        <p className="text-sm font-bold text-cyber-yellow uppercase tracking-wider">Simulated data</p>
        <p className="text-xs text-cyber-text-muted mt-1">{message}</p>
      </div>
    </div>
  )
}
