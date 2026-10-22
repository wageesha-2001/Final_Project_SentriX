'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Users, UserPlus, Trash2, Shield, Eye, EyeOff } from 'lucide-react'
import { formatDate } from '@/lib/utils'
import { cn } from '@/lib/utils'
import { User } from '@/types'
import toast from 'react-hot-toast'

interface NewUserForm {
  name: string
  email: string
  password: string
  role: 'admin' | 'technician'
}

export default function UsersPage() {
  const [loading, setLoading] = useState(true)
  const [users, setUsers] = useState<User[]>([])
  const [isAdmin, setIsAdmin] = useState(false)
  const [deleteUserId, setDeleteUserId] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [newUser, setNewUser] = useState<NewUserForm>({
    name: '', email: '', password: '', role: 'technician',
  })

  useEffect(() => {
    Promise.all([
      fetch('/api/auth/me').then(r => r.json()),
      fetch('/api/users').then(r => r.json()),
    ]).then(([me, usersData]) => {
      if (me.data?.role === 'admin') {
        setIsAdmin(true)
        setUsers(usersData.data || [])
      }
    }).finally(() => setLoading(false))
  }, [])

  const handleAddUser = async () => {
    if (!newUser.name || !newUser.email || !newUser.password) {
      toast.error('All fields are required')
      return
    }
    setSubmitting(true)
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newUser),
      })
      const d = await res.json()
      if (res.ok) {
        setUsers(prev => [...prev, d.data])
        setNewUser({ name: '', email: '', password: '', role: 'technician' })
        toast.success('User created successfully')
      } else {
        toast.error(d.error || 'Failed to create user')
      }
    } catch {
      toast.error('Network error')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDeleteUser = async () => {
    if (!deleteUserId) return
    setDeleting(true)
    try {
      const res = await fetch(`/api/users/${deleteUserId}`, { method: 'DELETE' })
      if (res.ok) {
        setUsers(prev => prev.filter(u => u.id !== deleteUserId))
        toast.success('User deleted')
      } else {
        const d = await res.json()
        toast.error(d.error || 'Failed to delete user')
      }
    } catch {
      toast.error('Network error')
    } finally {
      setDeleting(false)
      setDeleteUserId(null)
    }
  }

  if (loading) {
    return (
      <DashboardLayout title="User Management">
        <LoadingSpinner size="lg" className="h-64" />
      </DashboardLayout>
    )
  }

  if (!isAdmin) {
    return (
      <DashboardLayout title="User Management" subtitle="Manage system users">
        <div className="flex flex-col items-center justify-center h-64 gap-4">
          <div className="p-4 rounded-xl bg-cyber-red/10 border border-cyber-red/30">
            <Shield className="w-10 h-10 text-cyber-red" />
          </div>
          <div className="text-center">
            <p className="text-white font-bold text-lg">Access Denied</p>
            <p className="text-cyber-text-muted text-sm mt-1">Admin privileges required to manage users.</p>
          </div>
        </div>
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout title="User Management" subtitle="Manage system access and roles">
      <div className="space-y-6 max-w-4xl">

        {/* Users table */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="cyber-card overflow-hidden"
        >
          <div className="p-6 border-b border-cyber-border flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyber-accent/10 border border-cyber-accent/20">
              <Users className="w-5 h-5 text-cyber-accent" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">System Users</h2>
              <p className="text-xs text-cyber-text-muted mt-0.5">{users.length} user{users.length !== 1 ? 's' : ''}</p>
            </div>
          </div>

          {users.length === 0 ? (
            <div className="p-10">
              <EmptyState
                icon={Users}
                title="No users found"
                description="Add the first user using the form below."
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-cyber-border bg-cyber-surface/40">
                    <th className="text-left px-4 py-3 text-cyber-text-muted font-semibold uppercase tracking-wider">Name</th>
                    <th className="text-left px-4 py-3 text-cyber-text-muted font-semibold uppercase tracking-wider">Email</th>
                    <th className="text-left px-4 py-3 text-cyber-text-muted font-semibold uppercase tracking-wider">Role</th>
                    <th className="text-left px-4 py-3 text-cyber-text-muted font-semibold uppercase tracking-wider">Created</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/30">
                  {users.map((u, idx) => (
                    <motion.tr
                      key={u.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.04 }}
                      className="hover:bg-cyber-surface/30 transition-colors"
                    >
                      <td className="px-4 py-3 text-white font-medium">{u.name}</td>
                      <td className="px-4 py-3 font-mono text-cyber-text-muted">{u.email}</td>
                      <td className="px-4 py-3">
                        <span className={cn(
                          'inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider',
                          u.role === 'admin'
                            ? 'text-cyber-red bg-cyber-red/10 border-cyber-red/30'
                            : 'text-cyber-accent bg-cyber-accent/10 border-cyber-accent/30'
                        )}>
                          {u.role === 'admin' && <Shield className="w-3 h-3" />}
                          {u.role}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-cyber-muted whitespace-nowrap">
                        {formatDate(u.created_at)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setDeleteUserId(u.id)}
                          className="text-cyber-red/50 hover:text-cyber-red transition-colors p-1"
                          title="Delete user"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </motion.div>

        {/* Add user form */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="cyber-card p-6"
        >
          <h2 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider mb-4 flex items-center gap-2">
            <UserPlus className="w-4 h-4 text-cyber-accent" /> Add New User
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                Full Name
              </label>
              <input
                value={newUser.name}
                onChange={e => setNewUser({ ...newUser, name: e.target.value })}
                placeholder="Jane Smith"
                className="cyber-input w-full px-3 py-2 rounded-lg text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                Email Address
              </label>
              <input
                type="email"
                value={newUser.email}
                onChange={e => setNewUser({ ...newUser, email: e.target.value })}
                placeholder="jane@example.com"
                className="cyber-input w-full px-3 py-2 rounded-lg text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={newUser.password}
                  onChange={e => setNewUser({ ...newUser, password: e.target.value })}
                  placeholder="10+ chars: Aa, 0-9, symbol"
                  className="cyber-input w-full px-3 py-2 pr-10 rounded-lg text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-cyber-muted hover:text-cyber-text"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                Role
              </label>
              <select
                value={newUser.role}
                onChange={e => setNewUser({ ...newUser, role: e.target.value as 'admin' | 'technician' })}
                className="cyber-input w-full px-3 py-2 rounded-lg text-sm"
              >
                <option value="technician">Technician</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </div>
          <div className="mt-4 flex justify-end">
            <button
              type="button"
              onClick={handleAddUser}
              disabled={submitting}
              className="cyber-btn-primary px-5 py-2.5 rounded-lg text-sm font-bold flex items-center gap-2 disabled:opacity-60"
            >
              {submitting
                ? <><span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />Creating...</>
                : <><UserPlus className="w-4 h-4" />Create User</>}
            </button>
          </div>
        </motion.div>
      </div>

      <ConfirmDialog
        isOpen={!!deleteUserId}
        title="Delete User"
        variant="danger"
        message="Are you sure you want to delete this user? This action cannot be undone."
        confirmLabel={deleting ? 'Deleting...' : 'Delete User'}
        onConfirm={handleDeleteUser}
        onCancel={() => setDeleteUserId(null)}
      />
    </DashboardLayout>
  )
}
