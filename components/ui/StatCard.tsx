'use client'

import { motion } from 'framer-motion'
import { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface StatCardProps {
  title: string
  value: number | string
  icon: LucideIcon
  color: 'accent' | 'green' | 'red' | 'yellow' | 'purple'
  subtitle?: string
  delay?: number
}

const colorMap = {
  accent: { text: 'text-cyber-accent', bg: 'bg-cyber-accent/10', border: 'border-cyber-accent/20', glow: 'glow-accent' },
  green: { text: 'text-cyber-green', bg: 'bg-cyber-green/10', border: 'border-cyber-green/20', glow: 'glow-green' },
  red: { text: 'text-cyber-red', bg: 'bg-cyber-red/10', border: 'border-cyber-red/20', glow: 'glow-red' },
  yellow: { text: 'text-cyber-yellow', bg: 'bg-cyber-yellow/10', border: 'border-cyber-yellow/20', glow: '' },
  purple: { text: 'text-cyber-purple', bg: 'bg-cyber-purple/10', border: 'border-cyber-purple/20', glow: '' },
}

export function StatCard({ title, value, icon: Icon, color, subtitle, delay = 0 }: StatCardProps) {
  const colors = colorMap[color]
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay }}
      className={cn('cyber-card p-6', colors.border, 'border')}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold text-cyber-text-muted uppercase tracking-wider">{title}</p>
          <p className={cn('text-3xl font-black mt-2', colors.text)}>{value}</p>
          {subtitle && <p className="text-xs text-cyber-text-muted mt-1">{subtitle}</p>}
        </div>
        <div className={cn('p-3 rounded-xl border', colors.bg, colors.border)}>
          <Icon className={cn('w-6 h-6', colors.text)} />
        </div>
      </div>
    </motion.div>
  )
}
