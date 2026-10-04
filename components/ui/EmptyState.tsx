import { LucideIcon } from 'lucide-react'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description?: string
  action?: React.ReactNode
}

export function EmptyState({ icon: Icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 rounded-2xl bg-cyber-surface border border-cyber-border flex items-center justify-center mb-4">
        <Icon className="w-8 h-8 text-cyber-muted" />
      </div>
      <h3 className="text-white font-semibold mb-2">{title}</h3>
      {description && <p className="text-cyber-text-muted text-sm max-w-xs">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
