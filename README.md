# SentriX — Intelligent Security Auditing Framework

SentriX is a full-stack cybersecurity dashboard for automated IP CCTV network security auditing. Built with Next.js 14, TypeScript, Tailwind CSS, and Supabase.

> **For authorized and ethical security testing only.** Never use this tool on networks you do not own or do not have explicit written permission to test.

---

## Features

- **Automated Network Scanning** — Discovers IP CCTV cameras, NVRs, and DVRs on a given subnet
- **Vulnerability Detection** — Checks for default credentials, open RTSP streams, HTTP-only interfaces, Telnet services, outdated firmware, and more
- **Community Vulnerability Database** — Maps detected devices to a locally maintained / GitHub-hosted knowledge base of CCTV weaknesses (see below)
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

# Community Vulnerability Database (optional — defaults shown)
COMMUNITY_VULN_DB_ENABLED=true
COMMUNITY_VULN_DB_LOCAL_PATH=data/vulnerabilities.txt
COMMUNITY_VULN_DB_REMOTE_URL=
COMMUNITY_VULN_DB_SYNC_MODE=local
```

Existing Supabase installs: also run `database/migrate_community_vulnerabilities.sql` in the SQL Editor.

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
│   ├── vuln-db/               # Community vulnerability DB: validator, sync, matcher
│   ├── validators/            # Zod schemas
│   └── utils/                 # Helper functions
├── data/                      # vulnerabilities.txt + format guide
├── types/                     # TypeScript type definitions
├── database/
│   ├── schema.sql             # PostgreSQL schema
│   ├── seed.sql               # Initial data
│   └── migrate_community_vulnerabilities.sql  # Add the community DB to an existing install
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
| `device_vulnerability_matches` | Per-scan community vulnerability matches (list itself is in `data/vulnerabilities.txt`) |

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

## Community Vulnerability Database

SentriX keeps a **community-maintained list of CCTV / IP camera weaknesses in one plain text file**:
`data/vulnerabilities.txt`. There is **no database for this data** — SentriX reads the file directly, so anyone can update
it with a text editor. The file can also be hosted in a public GitHub repo so the community can improve it through pull requests.

| File | Purpose |
|---|---|
| `data/vulnerabilities.txt` | The vulnerability list (134 sample records, easy-to-edit `Label: value` blocks) |
| `data/vulnerability-schema.md` | Every label, allowed values, validation rules, how to contribute |

A record looks like this (blocks are separated by `---`):

```text
ID: SXV-2026-0001
Title: HTTP-Only Interface on DS-2CD2 series cameras
Vendor: Hikvision
Models: DS-2CD2043G0-I, DS-2CD2143G0-I
Firmware: V5.5.*
Device Type: camera
Category: HTTP-Only Interface
Severity: Medium
CVSS: 5.3
Risk Score: 14
Ports: 80
Protocols: HTTP
Keywords: hikvision, http only
Source: SIMULATED
Published: 2025-09-01
Updated: 2025-09-08
Description: The web management interface is served over unencrypted HTTP ...
Recommendation: Enable HTTPS for the management interface.
Steps:
- Enable HTTPS in the device network settings.
- Disable or redirect the plain HTTP listener.
Note: SIMULATED record created for academic demonstration.
---
```

> The shipped records are **demonstration data** (`SIMULATED` / `COMMUNITY_REPORTED`), not confirmed vulnerabilities.
> No CVE IDs are invented and the file contains no exploit code.

### Update the vulnerability data

1. Edit `data/vulnerabilities.txt` — copy a block, change the values, save.
2. Sign in as **admin**, open **Vulnerability DB**, click **Reload local file** (the file is also re-read automatically when a scan starts after it changed).
3. Mistakes are listed with the record number and reason; all valid records still load.

### Configure and sync from GitHub

```env
COMMUNITY_VULN_DB_ENABLED=true
COMMUNITY_VULN_DB_LOCAL_PATH=data/vulnerabilities.txt
COMMUNITY_VULN_DB_REMOTE_URL=https://raw.githubusercontent.com/<username>/sentrix-vuln-db/main/vulnerabilities.txt
COMMUNITY_VULN_DB_SYNC_MODE=both      # local | remote | both
```

Put the same text file in your public repo, restart SentriX, and click **Sync from GitHub**.

- `local` uses only the local file; `remote` uses the GitHub file (falling back to local); `both` merges them, and when the same ID is in both, the one with the newer `Updated` date wins.
- Only `https://raw.githubusercontent.com/...` URLs are accepted (10 s timeout, 5 MB limit, redirects refused).
- If GitHub is unreachable: *"Remote vulnerability database is unavailable. Local data will be used."*
- Reloads and syncs are recorded in **Audit Logs** and shown in the page's history.

### How matching confidence works

During a scan, each discovered device is compared with the records using vendor, model, firmware, device type, open ports,
protocols and keywords. SentriX is deliberately conservative:

| Confidence | Condition | Risk applied |
|---|---|---|
| **High** | Vendor + exact model (or model wildcard + firmware) | 100 % of the record's `Risk Score` |
| **Medium** | Vendor + model wildcard, firmware, port or protocol | 75 % |
| **Low** — shown as **Potential Match** | Generic record, vendor-only, or broad keyword match | 50 % |

For each device only the strongest match per category is kept, and at most 3 Potential Matches are shown.

### How risk scoring uses matches

`device risk = min(100, scanner findings + Σ matched Risk Score × confidence factor)` and `trust score = 100 − risk`.
Risk Score bands: Critical 30–40, High 20–29, Medium 10–19, Low 1–9, Informational 0.
The feature is switched on/off by **Community Vulnerability Mapping** under *Settings → Enabled Vulnerability Checks*
(admin only). Matches appear on the scan results page, the device details page and in reports. Technicians can view matches
but cannot reload, sync, or change settings.

What is saved in the app database: only the **per-scan match results** (`device_vulnerability_matches`, including a copy of the
matched record so old scans and reports stay readable after the file changes). The vulnerability list itself is never copied into a table.

> A device that triggers both a built-in check and a community record for the same weakness is scored by both.
> Treat the score as a prioritisation aid, not an exact measurement.

### Contribute new vulnerability records

1. Fork the public vulnerability repo and add block(s) to `vulnerabilities.txt` following `data/vulnerability-schema.md`.
2. Use an honest `Source`; use `VENDOR_ADVISORY` / `CVE` only with a real reference / real CVE ID.
3. Run `npm test` — it validates the file and reports any bad record.
4. Open a pull request. After it is merged, an admin clicks **Sync from GitHub**.

Records must describe weaknesses and fixes only — **no exploit code, payloads, passwords, or attack instructions**.

### Ethical usage

The list exists for **defensive identification and reporting**. Matches are indicators, not proof: verify them against
official vendor advisories before remediation, and only audit networks you own or are explicitly authorised to test.

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
