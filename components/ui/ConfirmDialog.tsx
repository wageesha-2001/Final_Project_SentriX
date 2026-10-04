'use client'

import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, X } from 'lucide-react'

interface ConfirmDialogProps {
  isOpen: boolean
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  onConfirm: () => void
  onCancel: () => void
  variant?: 'danger' | 'warning' | 'info'
}

export function ConfirmDialog({
  isOpen, title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel',
  onConfirm, onCancel, variant = 'warning',
}: ConfirmDialogProps) {
  const variantColors = {
    danger: 'text-cyber-red border-cyber-red/30 bg-cyber-red/10',
    warning: 'text-cyber-yellow border-cyber-yellow/30 bg-cyber-yellow/10',
    info: 'text-cyber-accent border-cyber-accent/30 bg-cyber-accent/10',
  }
  const btnColors = {
    danger: 'bg-cyber-red text-white hover:bg-red-600',
    warning: 'bg-cyber-yellow text-black hover:bg-yellow-400',
    info: 'bg-cyber-accent text-black hover:bg-cyan-400',
  }

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onCancel}
          />
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="relative cyber-card p-6 w-full max-w-md z-10"
          >
            <button onClick={onCancel} className="absolute top-4 right-4 text-cyber-muted hover:text-cyber-text">
              <X className="w-4 h-4" />
            </button>
            <div className={`inline-flex p-3 rounded-xl border mb-4 ${variantColors[variant]}`}>
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-white mb-2">{title}</h3>
            <p className="text-cyber-text-muted text-sm mb-6">{message}</p>
            <div className="flex gap-3">
              <button onClick={onCancel}
                className="flex-1 py-2.5 px-4 rounded-lg border border-cyber-border text-cyber-text-muted hover:text-white hover:border-cyber-muted text-sm font-medium transition-colors">
                {cancelLabel}
              </button>
              <button onClick={onConfirm}
                className={`flex-1 py-2.5 px-4 rounded-lg text-sm font-bold transition-colors ${btnColors[variant]}`}>
                {confirmLabel}
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}
