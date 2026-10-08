'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import {
  LayoutDashboard, Search, History, Cpu, FileText,
  Settings, Shield, LogOut, ChevronLeft, ChevronRight, Info,
  Users, ClipboardList, Database
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState } from 'react'
import toast from 'react-hot-toast'

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/scans/new', label: 'New Scan', icon: Search },
  { href: '/scans', label: 'Scan History', icon: History },
  { href: '/devices', label: 'Devices', icon: Cpu },
  { href: '/reports', label: 'Reports', icon: FileText },
  { href: '/community-vulns', label: 'Vulnerability DB', icon: Database },
  { href: '/settings', label: 'Settings', icon: Settings },
  { href: '/about', label: 'About / Ethics', icon: Info },
]

const adminNavItems = [
  { href: '/users', label: 'Users', icon: Users },
  { href: '/audit-logs', label: 'Audit Logs', icon: ClipboardList },
]

interface SidebarProps {
  userName?: string
  userRole?: string
}

export function Sidebar({ userName = 'User', userRole = 'technician' }: SidebarProps) {
  const pathname = usePathname()
  const router = useRouter()
  const [collapsed, setCollapsed] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)

  const allNavItems = [...navItems, ...(userRole === 'admin' ? adminNavItems : [])]

  const handleLogout = async () => {
    setLoggingOut(true)
    await fetch('/api/auth/logout', { method: 'POST' })
    toast.success('Logged out successfully')
    router.push('/login')
  }

  return (
    <motion.aside
      animate={{ width: collapsed ? 72 : 240 }}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
      className="flex flex-col h-screen bg-cyber-surface border-r border-cyber-border sticky top-0 overflow-hidden z-20"
    >
      <div className="flex items-center justify-between p-4 border-b border-cyber-border min-h-[64px]">
        {!collapsed && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyber-accent flex-shrink-0" />
            <span className="text-lg font-black tracking-widest text-white">SENTRIX</span>
          </motion.div>
        )}
        {collapsed && <Shield className="w-6 h-6 text-cyber-accent mx-auto" />}
        <button onClick={() => setCollapsed(!collapsed)}
          className="p-1 rounded text-cyber-muted hover:text-cyber-text ml-auto">
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
        {allNavItems.map((item) => {
          const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href))
          return (
            <Link key={item.href} href={item.href}
              className={cn('sidebar-item flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium',
                isActive ? 'active text-cyber-accent bg-cyber-accent/10' : 'text-cyber-text-muted hover:text-white'
              )}>
              <item.icon className={cn('w-5 h-5 flex-shrink-0', isActive && 'text-cyber-accent')} />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </Link>
          )
        })}
      </nav>

      <div className="p-3 border-t border-cyber-border">
        {!collapsed && (
          <div className="bg-cyber-card rounded-lg p-3 mb-3">
            <p className="text-xs font-semibold text-white truncate">{userName}</p>
            <p className="text-[10px] text-cyber-accent uppercase tracking-wider mt-0.5">{userRole}</p>
          </div>
        )}
        <button onClick={handleLogout} disabled={loggingOut}
          className={cn('flex items-center gap-3 px-3 py-2.5 rounded-lg w-full text-sm font-medium text-cyber-red/80 hover:text-cyber-red hover:bg-cyber-red/10 transition-colors',
            collapsed && 'justify-center'
          )}>
          <LogOut className="w-5 h-5 flex-shrink-0" />
          {!collapsed && <span>Logout</span>}
        </button>
      </div>
    </motion.aside>
  )
}
