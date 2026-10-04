'use client'

import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import toast from 'react-hot-toast'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { createScanSchema, CreateScanInput } from '@/lib/validators/schemas'
import { Shield, Network, AlertTriangle, CheckCircle, Info } from 'lucide-react'

const EXAMPLE_RANGES = ['192.168.1.0/24', '10.0.0.0/24', '172.16.0.0/24', '192.168.0.0/24']

export default function NewScanPage() {
  const router = useRouter()
  const [isCreating, setIsCreating] = useState(false)

  const { register, handleSubmit, setValue, formState: { errors }, watch } = useForm<CreateScanInput>({
    resolver: zodResolver(createScanSchema),
    defaultValues: { authorized: undefined as unknown as true },
  })

  const onSubmit = async (data: CreateScanInput) => {
    setIsCreating(true)
    try {
      const createRes = await fetch('/api/scans', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
      })
      const createData = await createRes.json()
      if (!createRes.ok) { toast.error(createData.error || 'Failed to create scan'); return }
      const scanId = createData.data.id
      const startRes = await fetch(`/api/scans/${scanId}/start`, { method: 'POST' })
      if (!startRes.ok) { toast.error('Failed to start scan'); return }
      toast.success('Scan started successfully!')
      router.push(`/scans/${scanId}/progress`)
    } catch {
      toast.error('An error occurred. Please try again.')
    } finally {
      setIsCreating(false)
    }
  }

  return (
    <DashboardLayout title="New Scan" subtitle="Configure and start a network security audit">
      <div className="max-w-2xl mx-auto space-y-6">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="cyber-card p-5 border-amber-500/20 bg-amber-500/5">
          <div className="flex gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-bold text-amber-300">Ethical Usage Reminder</h3>
              <p className="text-xs text-amber-200/70 mt-1">
                SentriX must only be used on networks you own or have explicit written authorization to test.
                Unauthorized network scanning may be illegal and unethical. This tool is for defensive security purposes only.
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="cyber-card p-6">
          <h2 className="text-base font-bold text-white mb-5 flex items-center gap-2">
            <Network className="w-5 h-5 text-cyber-accent" /> Scan Configuration
          </h2>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
            <div>
              <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                Scan Name
              </label>
              <input {...register('scan_name')} placeholder="e.g., Office CCTV Network Audit Q4 2024"
                className="cyber-input w-full px-4 py-3 rounded-lg text-sm" />
              {errors.scan_name && <p className="text-cyber-red text-xs mt-1">{errors.scan_name.message}</p>}
            </div>

            <div>
              <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                Network Range (CIDR)
              </label>
              <input {...register('network_range')} placeholder="192.168.1.0/24"
                className="cyber-input w-full px-4 py-3 rounded-lg text-sm font-mono" />
              {errors.network_range && <p className="text-cyber-red text-xs mt-1">{errors.network_range.message}</p>}
              <div className="flex flex-wrap gap-2 mt-2">
                {EXAMPLE_RANGES.map(r => (
                  <button key={r} type="button" onClick={() => setValue('network_range', r)}
                    className="text-xs px-2 py-1 bg-cyber-surface border border-cyber-border rounded text-cyber-accent hover:bg-cyber-accent/10 font-mono transition-colors">
                    {r}
                  </button>
                ))}
              </div>
            </div>

            <div className="p-4 bg-cyber-surface rounded-lg border border-cyber-border space-y-3">
              <div className="flex items-start gap-3">
                <Info className="w-4 h-4 text-cyber-accent mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-xs font-semibold text-white">Scan Information</p>
                  <ul className="text-xs text-cyber-text-muted mt-1 space-y-1">
                    <li>• Discovers active CCTV devices on the specified network range</li>
                    <li>• Checks for common security misconfigurations</li>
                    <li>• Calculates risk scores and generates a security report</li>
                    <li>• Uses mock scanner for safe development testing</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="p-4 border border-cyber-accent/20 rounded-lg bg-cyber-accent/5">
              <label className="flex items-start gap-3 cursor-pointer">
                <input type="checkbox" {...register('authorized')}
                  className="mt-1 w-4 h-4 accent-cyber-accent" />
                <div>
                  <p className="text-sm font-semibold text-white">Authorization Confirmation</p>
                  <p className="text-xs text-cyber-text-muted mt-1">
                    I confirm that I am the owner of, or have explicit written authorization to perform security testing on,
                    the network range specified above. I understand this tool is for authorized and ethical security auditing only.
                  </p>
                </div>
              </label>
              {errors.authorized && <p className="text-cyber-red text-xs mt-2">{errors.authorized.message}</p>}
            </div>

            <button type="submit" disabled={isCreating}
              className="cyber-btn-primary w-full py-3 rounded-lg text-sm font-bold flex items-center justify-center gap-2">
              {isCreating ? (
                <>
                  <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  INITIALIZING SCAN...
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" /> START SECURITY SCAN
                </>
              )}
            </button>
          </form>
        </motion.div>
      </div>
    </DashboardLayout>
  )
}
