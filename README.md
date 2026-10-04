# SentriX — Intelligent Security Auditing Framework

SentriX is a full-stack cybersecurity dashboard for automated IP CCTV network security auditing. Built with Next.js 14, TypeScript, Tailwind CSS, and Supabase.

> **For authorized and ethical security testing only.** Never use this tool on networks you do not own or do not have explicit written permission to test.

---

## Features

- **Automated Network Scanning** — Discovers IP CCTV cameras, NVRs, and DVRs on a given subnet
- **Vulnerability Detection** — Checks for default credentials, open RTSP streams, HTTP-only interfaces, Telnet services, outdated firmware, and more
- **Risk Scoring** — Calculates per-device risk scores (0–100) and overall network risk level
- **Professional Reports** — Generates detailed HTML security reports with executive summary and remediation guidance
- **Role-Based Access** — Admin and Technician roles with JWT authentication
- **Scan History** — Saves all audit results for tracking remediation progress
- **Ethical Safety Controls** — Authorization confirmation, safe scan mode, audit logging

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Next.js 14 (App Router) |
| Language | TypeScript |
| Styling | Tailwind CSS + Framer Motion |
| Database | PostgreSQL via Supabase |
| Authentication | Custom JWT (jose) |
| Forms | React Hook Form + Zod |
| Charts | Recharts |
| Notifications | react-hot-toast |

---

## Getting Started

### Prerequisites

- Node.js 18+
- A Supabase project (free tier works)
- npm or yarn

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd sentrix
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Set Up Supabase

1. Create a new project at [supabase.com](https://supabase.com)
2. Go to **SQL Editor** and run `database/schema.sql`
3. Then run `database/seed.sql` to populate initial data

### 4. Configure Environment Variables

```bash
cp .env.example .env.local
```

Edit `.env.local` and fill in:

```env
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
JWT_SECRET=your-minimum-32-character-secret-key-here
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

**Where to find Supabase keys:**
- Dashboard → Settings → API → Project URL and anon/public key
- Service role key: Dashboard → Settings → API → service_role (secret)

### 5. Update Seed User Passwords

The seed file contains bcrypt hashes. Generate real hashes for your passwords:

```bash
node -e "const bcrypt = require('bcryptjs'); bcrypt.hash('YourPassword123', 12).then(h => console.log(h))"
```

Update `database/seed.sql` with your generated hashes before running it.

### 6. Run the Development Server

```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000)

### 7. Log In

Use the demo credentials shown on the login page:
- **Admin:** `admin@sentrix.local` / `Admin@SentriX2024`
- **Technician:** `tech@sentrix.local` / `Tech@SentriX2024`

---

## Usage Guide

### Running Your First Scan

1. Log in to the dashboard
2. Click **New Scan** in the sidebar
3. Enter a scan name (e.g., "Office CCTV Audit")
4. Enter the network range in CIDR format (e.g., `192.168.1.0/24`)
5. Check the authorization confirmation box
6. Click **Start Security Scan**
7. Monitor progress on the Scan Progress page
8. When complete, view results and generate a report

### Generating Reports

1. Open any completed scan
2. Click **Generate Report**
3. View the HTML report inline or download it

### Settings

- **Safe Scan Mode** — Disables credential testing for safer operation
- **Vulnerability Checks** — Enable/disable individual security checks
- **Default Credentials** — Manage the vendor credential database (admin only)

---

## Project Structure

```
sentrix/
├── app/
│   ├── (auth)/login/          # Login page
│   ├── (dashboard)/           # Protected dashboard pages
│   │   ├── dashboard/         # Overview dashboard
│   │   ├── scans/             # Scan management
│   │   ├── devices/           # Device details
│   │   ├── reports/           # Security reports
│   │   ├── settings/          # App settings
│   │   └── about/             # Ethical usage info
│   └── api/                   # REST API routes
├── components/
│   ├── layout/                # Sidebar, Topbar, DashboardLayout
│   └── ui/                    # Reusable UI components
├── lib/
│   ├── auth/                  # JWT helpers and middleware
│   ├── supabase/              # Database clients
│   ├── scanner/               # Mock scanner + report generator
│   ├── risk/                  # Risk scoring calculator
│   ├── validators/            # Zod schemas
│   └── utils/                 # Helper functions
├── types/                     # TypeScript type definitions
├── database/
│   ├── schema.sql             # PostgreSQL schema
│   └── seed.sql               # Initial data
└── middleware.ts              # Next.js edge middleware (auth guard)
```

---

## Database Schema

| Table | Purpose |
|---|---|
| `users` | User accounts with roles |
| `scans` | Scan records and results summary |
| `devices` | Discovered CCTV devices |
| `vulnerabilities` | Per-device vulnerabilities |
| `reports` | Generated HTML reports |
| `settings` | Per-user scanner settings |
| `default_credentials` | Vendor default credential database |
| `audit_logs` | All system actions for compliance |

---

## Security Architecture

- **JWT in httpOnly cookies** — Tokens are inaccessible to JavaScript
- **bcrypt password hashing** — Industry-standard password security
- **Zod input validation** — All API inputs validated server-side
- **Row-level ownership** — Users can only access their own scan data
- **Service role isolation** — Supabase service key never exposed to client
- **Audit logging** — Login, logout, scan start/stop, and report generation all logged

---

## Deployment

### Vercel (Recommended)

1. Push to GitHub
2. Connect to Vercel
3. Add environment variables in Vercel dashboard
4. Deploy

### Debian + PM2 + Nginx

```bash
# Build
npm run build

# Start with PM2
pm2 start npm --name sentrix -- start
pm2 save
pm2 startup

# Nginx config (example)
# server {
#   listen 80;
#   server_name your-domain.com;
#   location / { proxy_pass http://localhost:3000; }
# }
```

---

## Vulnerability Checks

| Check | Severity | Risk Score |
|---|---|---|
| Default Credentials | Critical | +35 |
| Exposed RTSP Stream | High | +25 |
| Open Telnet Service | High | +25 |
| Outdated Firmware | High | +20 |
| Weak Authentication | High | +20 |
| HTTP-Only Interface | Medium | +15 |
| Insecure Web Interface | Medium | +15 |
| Missing Security Headers | Medium | +10 |

Risk scores are capped at 100. Risk levels: Secure (0), Low (1–20), Medium (21–45), High (46–70), Critical (71–100).

---

## Ethical Notice

SentriX is built for **defensive security purposes only**. It contains:
- No exploit code or payloads
- No brute-force attack logic
- No unauthorized internet scanning capability
- Mandatory authorization confirmation before each scan
- Safe scan mode enabled by default

**Always obtain written authorization before scanning any network.**

---

## License

MIT License — For educational and authorized security testing use only.

---

*SentriX — Final Year Cybersecurity Project*
