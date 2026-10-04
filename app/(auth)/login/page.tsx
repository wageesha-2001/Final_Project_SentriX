'use client'

import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import toast from 'react-hot-toast'
import { Shield, Lock, Mail, Eye, EyeOff, AlertTriangle } from 'lucide-react'
import { loginSchema, LoginInput } from '@/lib/validators/schemas'

export default function LoginPage() {
  const router = useRouter()
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  const { register, handleSubmit, formState: { errors } } = useForm<LoginInput>({
    resolver: zodResolver(loginSchema),
  })

  const onSubmit = async (data: LoginInput) => {
    setIsLoading(true)
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      const result = await res.json()
      if (!res.ok) {
        toast.error(result.error || 'Login failed')
        return
      }
      toast.success('Welcome to SentriX')
      router.push('/dashboard')
    } catch {
      toast.error('Connection error. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-cyber-bg cyber-grid flex items-center justify-center p-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-96 h-96 bg-cyber-accent/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-64 h-64 bg-cyber-green/5 rounded-full blur-3xl" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="w-full max-w-md relative z-10"
      >
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-cyber-accent/10 border border-cyber-accent/30 rounded-2xl mb-4 glow-accent">
            <Shield className="w-8 h-8 text-cyber-accent" />
          </div>
          <h1 className="text-3xl font-black tracking-widest text-white">SENTRIX</h1>
          <p className="text-cyber-text-muted text-sm mt-1">Security Auditing Framework</p>
        </div>

        <div className="cyber-card p-8">
          <div className="flex items-center gap-2 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 mb-6">
            <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
            <p className="text-xs text-amber-300">
              <strong>Authorized Access Only.</strong> Unauthorized use is prohibited and may be subject to legal action.
            </p>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
            <div>
              <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
                <input
                  {...register('email')}
                  type="email"
                  placeholder="admin@sentrix.local"
                  className="cyber-input w-full pl-10 pr-4 py-3 rounded-lg text-sm"
                />
              </div>
              {errors.email && <p className="text-cyber-red text-xs mt-1">{errors.email.message}</p>}
            </div>

            <div>
              <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
                <input
                  {...register('password')}
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••"
                  className="cyber-input w-full pl-10 pr-12 py-3 rounded-lg text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-cyber-muted hover:text-cyber-text"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {errors.password && <p className="text-cyber-red text-xs mt-1">{errors.password.message}</p>}
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="cyber-btn-primary w-full py-3 rounded-lg text-sm tracking-wider font-bold"
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  AUTHENTICATING...
                </span>
              ) : 'SECURE LOGIN'}
            </button>
          </form>

          <div className="mt-6 pt-4 border-t border-cyber-border">
            <p className="text-xs text-cyber-text-muted text-center">Demo credentials:</p>
            <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
              <div className="bg-cyber-surface rounded p-2">
                <p className="text-cyber-accent font-mono">admin@sentrix.local</p>
                <p className="text-cyber-muted font-mono">Admin@SentriX2024</p>
              </div>
              <div className="bg-cyber-surface rounded p-2">
                <p className="text-cyber-accent font-mono">tech@sentrix.local</p>
                <p className="text-cyber-muted font-mono">Tech@SentriX2024</p>
              </div>
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-cyber-text-muted mt-6">
          SentriX — For authorized security testing only
        </p>
      </motion.div>
    </div>
  )
}
