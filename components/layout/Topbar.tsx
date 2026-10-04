'use client'

import { Bell, Shield, User } from 'lucide-react'

interface TopbarProps {
  title: string
  subtitle?: string
  userName?: string
  userRole?: string
  actions?: React.ReactNode
}

export function Topbar({ title, subtitle, userName, userRole, actions }: TopbarProps) {
  return (
    <header className="h-16 bg-cyber-surface/80 backdrop-blur-sm border-b border-cyber-border sticky top-0 z-10 flex items-center px-6 gap-4">
      <div className="flex-1">
        <h1 className="text-lg font-bold text-white">{title}</h1>
        {subtitle && <p className="text-xs text-cyber-text-muted">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        {actions}
        <div className="flex items-center gap-2 bg-cyber-card border border-cyber-border rounded-lg px-3 py-1.5">
          <div className="w-6 h-6 rounded-full bg-cyber-accent/20 border border-cyber-accent/30 flex items-center justify-center">
            <User className="w-3.5 h-3.5 text-cyber-accent" />
          </div>
          {userName && (
            <div className="hidden sm:block">
              <p className="text-xs font-medium text-white">{userName}</p>
              <p className="text-[10px] text-cyber-accent uppercase">{userRole}</p>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
