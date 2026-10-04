'use client'

import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { Shield, AlertTriangle, CheckCircle, XCircle, Scale, BookOpen, Lock } from 'lucide-react'

export default function AboutPage() {
  const allowed = [
    'Scanning networks you own or have explicit written authorization to test',
    'Internal corporate CCTV network security audits',
    'University or educational cybersecurity research with proper oversight',
    'Authorized penetration testing engagements with signed scope documents',
    'Security auditing for compliance purposes (ISO 27001, NIST, etc.)',
  ]
  const prohibited = [
    'Scanning networks without explicit written authorization',
    'Scanning public internet IP ranges or unknown networks',
    'Using this tool for malicious or unauthorized surveillance',
    'Attempting to exploit discovered vulnerabilities',
    'Distributing or sharing scan results without authorization',
    'Using this tool for any illegal purpose in your jurisdiction',
  ]

  return (
    <DashboardLayout title="About & Ethical Usage" subtitle="Understanding responsible security auditing">
      <div className="max-w-3xl space-y-6">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="cyber-card p-6 border-cyber-accent/20 bg-gradient-to-br from-cyber-accent/5 to-transparent">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center flex-shrink-0">
              <Shield className="w-6 h-6 text-cyber-accent" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">What is SentriX?</h2>
              <p className="text-cyber-text-muted text-sm mt-2 leading-relaxed">
                SentriX is an <strong className="text-white">Intelligent Automated Security Auditing Framework</strong> designed
                specifically for identifying and analyzing security vulnerabilities in IP CCTV networks. It helps security professionals
                and network administrators proactively identify misconfigurations, weak credentials, and outdated firmware before
                malicious actors can exploit them.
              </p>
              <p className="text-cyber-text-muted text-sm mt-3 leading-relaxed">
                Built as a university final-year cybersecurity project, SentriX demonstrates responsible disclosure principles,
                ethical security research methodologies, and modern full-stack development practices.
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="cyber-card p-6 border-amber-500/20 bg-amber-500/5">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <h2 className="text-base font-bold text-amber-300">Ethical Usage Policy</h2>
          </div>
          <p className="text-amber-200/70 text-sm leading-relaxed">
            This tool is provided <strong className="text-amber-300">strictly for authorized and ethical security testing only</strong>.
            Misuse of this software may violate computer fraud and abuse laws in your jurisdiction, including but not limited to
            the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), and equivalent legislation in other countries.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="cyber-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <CheckCircle className="w-5 h-5 text-cyber-green" />
              <h3 className="font-bold text-cyber-green">Permitted Use Cases</h3>
            </div>
            <ul className="space-y-2">
              {allowed.map((item, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-cyber-text-muted">
                  <CheckCircle className="w-3.5 h-3.5 text-cyber-green mt-0.5 flex-shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="cyber-card p-5">
            <div className="flex items-center gap-2 mb-4">
              <XCircle className="w-5 h-5 text-cyber-red" />
              <h3 className="font-bold text-cyber-red">Prohibited Actions</h3>
            </div>
            <ul className="space-y-2">
              {prohibited.map((item, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-cyber-text-muted">
                  <XCircle className="w-3.5 h-3.5 text-cyber-red mt-0.5 flex-shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </motion.div>
        </div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="cyber-card p-6">
          <div className="flex items-center gap-2 mb-4">
            <Lock className="w-5 h-5 text-cyber-accent" />
            <h3 className="font-bold text-white">Security Features Built Into SentriX</h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              ['Mandatory Authorization Checkbox', 'Users must confirm authorization before every scan'],
              ['Safe Scan Mode', 'Disables credential testing by default for safer operation'],
              ['No Exploit Code', 'Contains zero exploitation or brute-force attack code'],
              ['Audit Logging', 'Every action is logged for accountability and review'],
              ['Role-Based Access', 'Admin and technician roles limit feature access'],
              ['JWT Authentication', 'Secure session management with httpOnly cookies'],
            ].map(([title, desc]) => (
              <div key={title} className="flex items-start gap-3 p-3 bg-cyber-surface rounded-lg">
                <CheckCircle className="w-4 h-4 text-cyber-green mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-sm font-medium text-white">{title}</p>
                  <p className="text-xs text-cyber-text-muted">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }} className="cyber-card p-6">
          <div className="flex items-center gap-2 mb-3">
            <BookOpen className="w-5 h-5 text-cyber-purple" />
            <h3 className="font-bold text-white">Technology Stack</h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
            {[
              ['Frontend', 'Next.js 14 + TypeScript'],
              ['Styling', 'Tailwind CSS + Framer Motion'],
              ['Database', 'PostgreSQL via Supabase'],
              ['Auth', 'Custom JWT (jose library)'],
              ['Forms', 'React Hook Form + Zod'],
              ['Deployment', 'Vercel / Debian + PM2'],
            ].map(([label, value]) => (
              <div key={label} className="bg-cyber-surface rounded p-2.5">
                <p className="text-cyber-muted">{label}</p>
                <p className="text-white font-medium mt-0.5">{value}</p>
              </div>
            ))}
          </div>
        </motion.div>

        <div className="text-center text-xs text-cyber-muted pb-4">
          <p>SentriX v1.0 — Final Year Cybersecurity Project</p>
          <p className="mt-1">Built for educational and authorized security testing purposes only.</p>
        </div>
      </div>
    </DashboardLayout>
  )
}
