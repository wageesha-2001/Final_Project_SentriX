import type { Metadata } from 'next'
import { Toaster } from 'react-hot-toast'
import './globals.css'

export const metadata: Metadata = {
  title: 'SentriX - Security Auditing Framework',
  description: 'Intelligent Automated Security Auditing Framework for Large-Scale IP CCTV Networks',
  icons: { icon: '/favicon.ico' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {children}
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#111827',
              color: '#e2e8f0',
              border: '1px solid #1e2d3d',
              fontFamily: 'Inter, sans-serif',
            },
            success: { iconTheme: { primary: '#00ff9d', secondary: '#0a0e1a' } },
            error: { iconTheme: { primary: '#ff3b5c', secondary: '#0a0e1a' } },
          }}
        />
      </body>
    </html>
  )
}
