# SentriX — Intelligent Security Auditing Framework

SentriX is a full-stack cybersecurity dashboard for automated IP CCTV network security auditing. It discovers the cameras, NVRs and DVRs on a network you are authorized to test, checks them for common weaknesses, matches them against a community vulnerability database, scores the risk and produces a report. Built with Next.js 14, TypeScript, Tailwind CSS and Supabase.

> **For authorized and ethical security testing only.** Never use this tool on networks you do not own or do not have explicit written permission to test.

---

## Features

- **Real network discovery** — Live, non-intrusive probing of the entered range (TCP connect, RTSP `OPTIONS`, unauthenticated HTTP). No logins, no brute force, no exploits. A simulation mode with demo devices is still available.
- **Evidence-based CCTV identification** — A weighted classifier separates IP cameras, NVRs and DVRs from other hosts (printers, PCs, routers) and keeps only CCTV devices. Vendor, model and device type are read from what the device itself exposes, e.g. Hikvision `App-webs` and its login page.
- **Reliable sweeps** — Ports that don't answer are re-checked with a longer timeout, so one dropped packet doesn't lose a device or a port.
- **Vulnerability detection** — A device is flagged **VULNERABLE** only when its **exact model + firmware** matches a record in `data/vulnerabilities.txt`, or an authorised default-credential check confirms a login. Open ports, HTTP-only, RTSP, Telnet, missing headers, etc. are kept as **informational observations** that do not add risk (see "Vulnerability Detection Model" below).
- **Authorised default-credential check** — Optional, lab-gated, **one** attempt per device, vendor-matched, never stores passwords.
- **Separated per-device statuses** — Known-Vulnerability, Authentication and Overall status are tracked independently, so a device is never "vulnerable" just because a port is open.
- **Community vulnerability database** — Maps devices to a plain-text, community-maintained knowledge base of CCTV weaknesses that can be synced from GitHub (see below).
- **Risk scoring** — Per-device risk (0–100) from confirmed findings only, plus a trust score (100 − risk) and an overall network rating.
- **Device inventory** — Each device is listed once, using its most recent completed scan. The dashboard, Devices page, scan results and reports all agree.
- **Professional reports** — HTML reports with an executive summary that separates confirmed from potential critical issues, key findings and remediation steps.
- **Role-based access** — Admin and Technician roles with JWT authentication, server-side logout and account lockout.
- **Audit logging** — Logins, logouts, scans, reports, user changes, settings changes and database syncs are all recorded.
- **Works on phones** — Below tablet width the sidebar becomes a slide-out menu.
- **Ethical safety controls** — Authorization confirmation before every scan, safe scan mode, range limits (/16 or smaller, no loopback/multicast/0.0.0.0).

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Next.js 14 (App Router) |
| Language | TypeScript |
| Styling | Tailwind CSS + Framer Motion |
| Database | PostgreSQL via Supabase, or a built-in in-memory local mode for development |
| Authentication | Custom JWT (jose) + bcryptjs |
| Forms | React Hook Form + Zod |
| Charts | Recharts |
| Notifications | react-hot-toast |
| Testing | Jest (281 tests) + ESLint |

---

## Getting Started

### Prerequisites

- Node.js 18+ (Node 20+ recommended)
- npm
- A Supabase project (free tier works) — **optional for local development**
- Network access to the CCTV range you want to audit (for real scans)

### 1. Clone and install

```bash
git clone <your-repo-url>
cd sentrix
npm install
```

### 2. Choose a database

**Option A — Local mode (quickest, development only).** Leave `NEXT_PUBLIC_SUPABASE_URL` unset (or set it to `your_supabase_project_url`). SentriX then uses an in-memory database seeded with demo users, checks and credentials. Everything is wiped when the server restarts. Local mode refuses to run with `NODE_ENV=production`.

**Option B — Supabase.**

1. Create a project at [supabase.com](https://supabase.com).
2. In the **SQL Editor**, run `database/schema.sql`, then `database/seed.sql`.
3. **Upgrading an existing install?** Run the migrations you haven't run yet:

| Migration | Adds |
|---|---|
| `database/migrate_community_vulnerabilities.sql` | Community vulnerability matches table |
| `database/migrate_default_credentials.sql` | Full vendor default-credential list |
| `database/migrate_revoked_tokens.sql` | `revoked_tokens` table, needed for server-side logout |
| `database/migrate_scan_mode.sql` | `scan_mode` column (real vs simulated) |
| `database/migrate_device_status.sql` | Per-device `known_vulnerability_status`, `authentication_status`, `overall_security_status`, `trust_score`, and the `informational` flag on `vulnerabilities` |

### 3. Configure environment variables

```bash
cp .env.example .env.local
```

Edit `.env.local`:

```env
# Supabase (omit for local mode)
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# Required: at least 32 random characters. Changing it signs everyone out.
JWT_SECRET=your-minimum-32-character-secret-key-here
NEXT_PUBLIC_APP_URL=http://localhost:3000

# Scanner (npm run dev / npm start already set SENTRIX_REAL_SCAN=1)
SENTRIX_REAL_SCAN=1          # 1 = probe the real network, unset = simulation
SENTRIX_SCAN_DEBUG=1         # print a per-host evidence + per-device decision table
# SENTRIX_ALLOW_CRED_CHECK — deprecated/optional. The credential check now runs
# on real scans whenever Safe Scan Mode is off and the check is enabled.

# Allow the in-memory demo DB in production (POC/demo only). Without it, a
# production build refuses to start unless real Supabase keys are set.
SENTRIX_ALLOW_LOCAL_DB=0

# Show the demo accounts on the login page (off by default; never enable in production)
NEXT_PUBLIC_SHOW_DEMO_CREDENTIALS=0

# Community Vulnerability Database (optional — defaults shown)
COMMUNITY_VULN_DB_ENABLED=true
COMMUNITY_VULN_DB_LOCAL_PATH=data/vulnerabilities.txt
COMMUNITY_VULN_DB_REMOTE_URL=
COMMUNITY_VULN_DB_SYNC_MODE=local
```

**Where to find Supabase keys:** Dashboard → Settings → API (Project URL, anon key, and the secret `service_role` key).

### 4. Set seed user passwords (Supabase)

The seed file contains bcrypt hashes. Generate hashes for your own passwords:

```bash
node -e "const bcrypt = require('bcryptjs'); bcrypt.hash('Your#Strong2026Pass', 12).then(h => console.log(h))"
```

Put them in `database/seed.sql` before running it.

### 5. Run

| Command | What it does |
|---|---|
| `npm run dev` | Development server with **real network scanning** and the debug evidence table |
| `npm run dev:sim` | Development server in **simulation mode** (demo devices, no network traffic) |
| `npm run build` | Production build |
| `npm start` | Production server with real network scanning |
| `npm test` | Jest test suite |
| `npm run lint` | ESLint |

Visit [http://localhost:3000](http://localhost:3000).

### 6. Log in

The demo accounts are **not shown on the login page** unless `NEXT_PUBLIC_SHOW_DEMO_CREDENTIALS=1`:

- **Admin:** `admin@sentrix.local` / `Admin@SentriX2024`
- **Technician:** `tech@sentrix.local` / `Tech@SentriX2024`

Change or remove these accounts before exposing SentriX to anyone else.

---

## Usage Guide

### Running a scan

1. Click **New Scan** in the sidebar. The page shows whether the scanner is in live or simulation mode.
2. Enter a scan name (at least 3 characters, not just spaces).
3. Enter the network range in CIDR format, e.g. `192.168.70.0/24` or a single device `192.168.70.56/32`.
   - Allowed prefixes are /16 to /32. `0.x`, `127.x`, multicast/reserved (224+) and leading zeros (`192.168.070.1`) are rejected.
   - Host bits are cleared, so `192.168.70.60/16` is saved as `192.168.0.0/16`, the range that will really be scanned.
4. Tick the authorization confirmation and click **Start Security Scan**.
5. Watch the live progress page. You can stop a running scan; its progress then stays where it stopped and it is shown as **STOPPED**.
6. When it completes, open the results and generate a report.

A real /24 scan takes about a minute; a single device takes a few seconds.

### Reports

Open a completed scan and click **Generate Report**, then view it inline, open it in a new tab or download the HTML. Reports can only be generated for completed scans. Opening a report link for a scan that doesn't exist, or isn't yours, says so instead of offering to generate one.

### Settings

- **Safe Scan Mode** — Disables credential-testing checks (on by default).
- **Scan timeout / Login attempt limit** — Whole numbers only. Empty or invalid values show a message instead of silently not saving. Every change is written to the audit log.
- **Enabled Vulnerability Checks** — Enable or disable individual checks, or a whole severity group (admin only).
- **Default Credentials** — Manage the vendor default-credential list (admin only).

### Users (admin)

New accounts need a password of 10–72 bytes with upper- and lower-case letters, a number and a symbol. Names are limited to 100 characters. Deleting a user signs them out immediately.

---

## Scanning Modes

### Real network discovery (`SENTRIX_REAL_SCAN=1`)

For every address in the range, SentriX:

1. **Sweeps** ports 23, 80, 443, 554, 8000, 8080 and 37777 with a TCP connect (600 ms, 32 hosts in parallel).
2. **Confirms**: closed ports on a live host are re-checked up to twice at 1.5 s, and a silent address gets one longer check of 80 and 554 before it is written off.
3. **Fingerprints** the open services, without logging in:
   - RTSP `OPTIONS` on 554 (any RTSP reply, including 401, confirms an RTSP service)
   - Unauthenticated HTTP `GET /` and known vendor paths (e.g. Hikvision `/ISAPI`, Dahua `/cgi-bin/magicBox.cgi`, Axis, ONVIF) — a 200/401/403 only shows the path exists
   - Server headers and public login pages (Hikvision's login page reveals the model and web version)
   - The MAC address from the ARP table when the device is on the same subnet
4. **Classifies** each host and keeps only CCTV devices (see below).

What it never does: guess passwords in bulk, run exploits, or scan outside the range you entered. The **only** credentialed traffic is the optional, lab-gated default-credential check — **one** vendor-matched attempt per device, off unless you explicitly enable it (`SENTRIX_ALLOW_CRED_CHECK=1` + Safe Scan Mode off); see [Vulnerability Detection Model](#vulnerability-detection-model).

Limitations: on a routed subnet MAC addresses are not visible, and the exact firmware version needs an authenticated API, so firmware may show the web-interface version or `Unknown`.

### Simulation (`npm run dev:sim`)

Uses fixed demo devices (NVRs at .10–.12, cameras at .64–.69 and non-CCTV hosts) inside the entered range. No packets are sent. Useful for demos without a CCTV network.

### How CCTV devices are identified

Each host gets an evidence score (0–100):

| Evidence | Points |
|---|---|
| RTSP service confirmed | +35 |
| ONVIF service | +35 |
| Known CCTV vendor (from headers, pages or MAC) | +40 |
| Vendor SDK/API path present | +25 |
| MAC address belongs to a CCTV vendor | +25 |
| SDK port 8000 / 37777 open | +20 each |
| Several CCTV ports open | +15 |
| Only 554 open | +15 |
| Web port, when another strong signal exists | +5 |

A score of 35 or more counts as CCTV. 75+ with a device signal is reported as an IP camera / NVR / DVR with High confidence, 60+ as a CCTV device (Medium), and 35–59 as a possible CCTV device (Low). A web server on its own scores nothing, and an open port 8000 alone is not treated as a vendor SDK.

---

## Vulnerability Detection Model

**Identifying a device as CCTV is separate from judging it vulnerable.** Classification (above) only decides *whether to audit* a device. Vulnerability status is decided in three independent steps and combined into one overall status.

### A device is VULNERABLE only when…

1. **Known-vulnerability match** — its **exact model** is listed in `data/vulnerabilities.txt` **and** its firmware is consistent with that record's `Firmware`:
   - `Firmware: *` → matches any version (confirmed).
   - Device firmware known and inside the record's range → confirmed.
   - Device firmware known but outside the range → **no match**.
   - Device firmware **Unknown** + a specific range → **UNVERIFIED** (potential, not confirmed, 0 risk).
   - Records with `Models: *` or a pattern like `DS-2CD2*` **never match** — a vendor/port/protocol signal alone is not evidence of a known vulnerability.
2. **Confirmed default credentials** — the authorised credential check logged in with a default password.

Everything else (open ports, HTTP-only, RTSP present, Telnet, missing headers, being a known brand) is recorded as an **informational observation**: shown on the device, but it adds **0 risk** and never makes the device vulnerable. *No record matched* does not prove a device is safe — only that no known vulnerability was found locally.

Matching engine: `lib/vuln-db/matcher.ts`.

### Separated per-device statuses

| Status | Values |
|---|---|
| `known_vulnerability_status` | `MATCHED` · `NO_MATCH` · `UNVERIFIED` |
| `authentication_status` | `CONFIRMED_DEFAULT_CREDENTIALS` · `CONFIRMED_WEAK_PASSWORD` · `AUTHENTICATION_REJECTED` · `NOT_TESTED` · `AUTHENTICATION_ERROR` |
| `overall_security_status` | `VULNERABLE` · `HEALTHY` · `NOT_VERIFIED` |

**Overall** is derived as: **VULNERABLE** if a confirmed file match or a confirmed credential weakness (default **or** weak password); **NOT_VERIFIED** if nothing confirmed but a needed check could not complete (unknown firmware on a matched model, auth error, or an auth test required by policy that did not run); otherwise **HEALTHY**. Classification code: `lib/risk/calculator.ts`.

### Authorised credential check (active)

`lib/scanner/credential-check.ts` makes **real** login attempts. It runs automatically on **real scans** when **Safe Scan Mode is off** and the *Default Credentials Check* is enabled (always off in simulation; the old `SENTRIX_ALLOW_CRED_CHECK` flag is no longer required).

Per device it tests, in order, and stops at the first success:

1. **All factory-default credentials** stored for the device's **exact vendor** (highest-risk first) → `CONFIRMED_DEFAULT_CREDENTIALS` (**Critical**).
2. A **built-in list of common weak passwords** (`12345678`, `password`, `admin`, `qwerty`, …) against the admin usernames → `CONFIRMED_WEAK_PASSWORD` (**Low**).

Safety:
- Reliable success signal: a protected endpoint that returns **401 unauthenticated and 2xx only when a credential is accepted** (a 200 login page is not success). Supports HTTP Basic and Digest.
- **Stops immediately on any lockout/throttling signal** (HTTP 429/403/503).
- **Never logs, stores, returns or displays a password** — only the vendor, username and whether it was a default or weak password.
- ⚠️ Trying many passwords can lock out real accounts — keep **Safe Scan Mode on** for production networks; this is an authorised-lab feature.

### Risk & trust

`device risk = min(100, Σ confirmed match Risk Score + credential finding)`, where a confirmed **default credential** adds 75 (Critical band) and a confirmed **weak password** adds 8 (Low band); informational items add 0; `trust = 100 − risk`. Device risk levels: Secure 0, Low 1–20, Medium 21–45, High 46–70, Critical 71–100. The overall scan rating is the highest device rating.

---

## Project Structure

```
sentrix/
├── app/
│   ├── (auth)/login/            # Login page
│   ├── (dashboard)/             # Protected pages
│   │   ├── dashboard/           # Overview
│   │   ├── scans/               # New scan, history, live progress, results
│   │   ├── devices/             # Device inventory and details
│   │   ├── reports/             # Security reports
│   │   ├── community-vulns/     # Community vulnerability database
│   │   ├── settings/            # Scanner settings, checks, default credentials
│   │   ├── users/               # User management (admin)
│   │   ├── audit-logs/          # Audit trail (admin)
│   │   └── about/               # Ethical usage info
│   └── api/                     # REST API routes (incl. /api/scanner for the active scan mode)
├── components/
│   ├── layout/                  # Sidebar (desktop rail + phone drawer), Topbar, DashboardLayout
│   └── ui/                      # Reusable UI components
├── lib/
│   ├── auth/                    # JWT, request auth (DB-checked, revocation-aware)
│   ├── supabase/                # Supabase client + in-memory local mode
│   ├── scanner/
│   │   ├── network-discovery.ts # Real, non-intrusive probing
│   │   ├── cctv-discovery.ts    # Weighted CCTV classifier + simulated hosts
│   │   ├── mock-scanner.ts      # Scan pipeline (real or simulated discovery → analysis)
│   │   └── report-generator.ts  # HTML report
│   ├── devices/                 # Device inventory (latest completed scan per device)
│   ├── risk/                    # Risk scoring
│   ├── vuln-db/                 # Community DB: parser, validator, sync, matcher
│   ├── validators/              # Zod schemas (scans, users, settings, login)
│   └── utils/                   # Helpers, rate limiter
├── data/                        # vulnerabilities.txt + format guide
├── types/                       # TypeScript types
├── database/                    # schema.sql, seed.sql, migrations
├── __tests__/                   # Jest tests
├── ecosystem.config.js          # PM2 config (real scanning on)
└── middleware.ts                # Edge auth guard
```

---

## Database Schema

| Table | Purpose |
|---|---|
| `users` | User accounts with roles |
| `scans` | Scan records and results summary |
| `devices` | Discovered CCTV devices, incl. `known_vulnerability_status`, `authentication_status`, `overall_security_status`, `trust_score` |
| `vulnerabilities` | Per-device findings; the `informational` flag marks observations that do not affect risk/status |
| `reports` | Generated HTML reports |
| `settings` | Per-user scanner settings |
| `default_credentials` | Vendor default-credential list |
| `audit_logs` | All system actions for compliance |
| `vulnerability_checks` | Built-in checks and whether they are enabled |
| `device_vulnerability_matches` | Per-scan community vulnerability matches (the list itself is in `data/vulnerabilities.txt`) |
| `revoked_tokens` | Login tokens ended by logout, kept until they expire |

---

## Security Architecture

- **JWT in httpOnly, SameSite=strict cookies** — Tokens are not readable by JavaScript.
- **Accounts checked on every request** — A deleted user is signed out immediately, and the role always comes from the database, never from the token.
- **Server-side logout** — Each token has a unique ID. Logout revokes it, so a copied token stops working; the user's other sessions are unaffected.
- **Account lockout** — After the configured number of failed logins (default 5), the account is locked for 15 minutes, including for the correct password.
- **Password safety** — bcrypt (cost 12), a strong-password policy, and no silent truncation past bcrypt's 72-byte limit. The login button is disabled until the page has loaded, so credentials can never be sent in a URL.
- **Input validation** — Zod schemas on every API input. Malformed requests get 400, missing records 404, other users' records 403.
- **Ownership checks** — Technicians only see their own scans, devices and reports.
- **Service role isolation** — The Supabase service key never reaches the browser.
- **HTTP security headers** — CSP, X-Frame-Options, HSTS and more (`next.config.js`).
- **Audit logging** — Logins, failed logins, logouts, scans, reports, user creation and deletion, settings changes and database syncs.

---

## Deployment

### Vercel

1. Push to GitHub and import the repo in Vercel.
2. Add the environment variables (a real Supabase project is required in production).
3. Deploy. Note: real network discovery needs the server to reach your CCTV network, which a hosted platform usually cannot. Self-host for real scans.

### Debian + PM2 + Nginx

```bash
npm run build
pm2 start ecosystem.config.js --env production   # sets NODE_ENV=production and SENTRIX_REAL_SCAN=1
pm2 save
pm2 startup

# Nginx (example)
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
| `data/vulnerabilities.txt` | The vulnerability list (172 sample records, easy-to-edit `Label: value` blocks) |
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
COMMUNITY_VULN_DB_GITHUB_TOKEN=       # only for a private repo (fine-grained PAT, Contents: read-only)
```

Put the same text file in your repo, restart SentriX, and click **Sync from GitHub**.

- `local` uses only the local file; `remote` uses the GitHub file (falling back to local); `both` merges them, and when the same ID is in both, the one with the newer `Updated` date wins.
- Only `https://raw.githubusercontent.com/...` URLs are fetched (10 s timeout, 5 MB limit, redirects refused). A copied GitHub page link (`https://github.com/<user>/<repo>/blob/<branch>/<path>`) is converted to the raw link automatically.
- A private repo returns HTTP 404 without a token — set `COMMUNITY_VULN_DB_GITHUB_TOKEN`, or make the repo public.
- If GitHub is unreachable: *"Remote vulnerability database is unavailable. Local data will be used."*
- Reloads and syncs are recorded in **Audit Logs** and shown in the page's history.

### How matching works

During a scan, each discovered device is compared with the records by **exact model + firmware** (the authoritative rule is in [Vulnerability Detection Model](#vulnerability-detection-model) above):

| Result | Condition | Risk applied |
|---|---|---|
| **Confirmed (High)** | Exact model listed **and** firmware matches (`*` = any version) | 100 % of the record's `Risk Score` |
| **Unverified (Low)** — shown as **Potential Match** | Exact model listed, record names a specific firmware range, device firmware is Unknown | 0 % (not counted; flagged for review) |
| **No match** | Model not listed, model a wildcard/pattern, firmware out of range, or wrong vendor/device type | — |

Rules that keep matches honest:

- Records with `Models: *` or a pattern (e.g. `DS-2CD2*`) never match — list each affected model by its full name.
- Only the strongest match per category is kept (confirmed over unverified).
- **Internet Exposure** records only match a device found at a **public** IP address. Devices on private ranges (10.x, 172.16–31.x, 192.168.x, CGNAT, loopback, link-local) show no evidence of internet exposure.
- A record's `Vendor: Generic…`/`Unknown…`/`*` applies to any vendor (the exact model still pins the device); a named vendor must agree with a known device vendor.

### How risk scoring uses matches

`device risk = min(100, Σ confirmed match Risk Score + confirmed default-credential finding)` and `trust score = 100 − risk`. Only **confirmed** findings count; unverified matches and informational observations add 0.

Risk Score bands: Critical 30–40, High 20–29, Medium 10–19, Low 1–9, Informational 0.
The feature is switched on/off by **Community Vulnerability Mapping** under *Settings → Enabled Vulnerability Checks*
(admin only). Matches appear on the scan results page, the device details page and in reports. Technicians can view matches
but cannot reload, sync, or change settings.

What is saved in the app database: only the **per-scan match results** (`device_vulnerability_matches`, including a copy of the
matched record so old scans and reports stay readable after the file changes). The vulnerability list itself is never copied into a table.

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

## Vulnerability Checks & observations

Admins can enable/disable individual checks under *Settings → Enabled Vulnerability Checks*. Under the current model these behave as follows:

| Item | How it affects a device |
|---|---|
| **Community Vulnerability Mapping** | Drives **confirmed** findings from `data/vulnerabilities.txt` (exact model + firmware). Makes a device **VULNERABLE**. |
| **Default Credentials Check** | When active (real scan + Safe Scan Mode off), tries the vendor's default credentials then common weak passwords (stops on lockout). A default login → **VULNERABLE (Critical)**; a weak password → **VULNERABLE (Low)**. |
| Open ports, HTTP-only, RTSP exposed, Telnet, missing security headers, insecure web, session cookies, ONVIF anonymous | **Informational observations.** Detected from evidence, shown on the device and in reports, but they add **0 risk** and never make a device vulnerable. |

Observation checks are evidence-derived (e.g. HTTP-only when port 80 is open without HTTPS; RTSP exposed when 554 is open; open risky ports when 4+ ports answer). Disabling a check hides its observation. In **simulation mode** the same observations are attached to the built-in demo devices.

Risk comes only from confirmed findings, capped at 100. Risk levels: Secure (0), Low (1–20), Medium (21–45), High (46–70), Critical (71–100). The overall scan rating is the highest device rating.

---

## Testing

```bash
npm test         # 281 Jest tests (18 suites)
npm run lint     # ESLint
npx tsc --noEmit # type check
```

The suites cover the scanner and classifier, the risk calculator and status classification, the community database (parser, validator, exact model + firmware matcher, the shipped file), the authorised credential check (`__tests__/credential-check.test.ts`, injected probe — no traffic), the twelve detection cases (`__tests__/scan-classification.test.ts`), API routes against the in-memory database, authentication and session handling, and regression tests from the October 2026 QA passes. Network tests use injected probes and send no traffic.

---

## Changelog

### October 2026 — Detection-accuracy rework

- **Exact model + firmware matching.** A device is VULNERABLE only when its exact model is listed in `data/vulnerabilities.txt` and firmware is consistent. `Models: *` and patterns (`DS-2CD2*`) no longer match, fixing healthy devices being flagged from ports/vendor alone.
- **Separated statuses** persisted per device: `known_vulnerability_status`, `authentication_status`, `overall_security_status` (VULNERABLE / HEALTHY / NOT_VERIFIED), plus `trust_score`.
- **Heuristics are now informational** (open ports, HTTP-only, RTSP, …): shown but 0 risk.
- **Authorised credential audit** (`lib/scanner/credential-check.ts`): on real scans with Safe Scan Mode off, tries vendor default credentials then a built-in weak-password list (Basic/Digest), stops on lockout, never stores passwords. Default login → VULNERABLE (Critical); weak password → VULNERABLE (Low), via `CONFIRMED_WEAK_PASSWORD`.
- **New migration** `database/migrate_device_status.sql`; dashboard adds Healthy / Not-Verified / Known-vuln / Confirmed-credential counts.
- **Tests**: added `scan-classification.test.ts` (12 cases) and `credential-check.test.ts`; suite now 281 tests.

### October 2026 — Real scanning and QA hardening

**Scanning**
- Real, non-intrusive network discovery (`SENTRIX_REAL_SCAN=1`), now the default for `npm run dev` and `npm start`. `npm run dev:sim` keeps simulation.
- Port sweeps confirm dropped ports with longer retries; RTSP and HTTP probes retry once. A /24 now finds every device consistently.
- Evidence-weighted CCTV classifier; a bare open port 8000 no longer makes an unrelated host look like CCTV.
- Stopped scans keep the progress they reached.

**Security**
- Every request checks that the account still exists and takes the role from the database.
- Server-side logout via revoked token IDs (`revoked_tokens` table).
- Login lockout that survives server recompiles.
- Strong password policy, no silent bcrypt truncation, name/email length limits.
- Demo credentials hidden from the login page unless `NEXT_PUBLIC_SHOW_DEMO_CREDENTIALS=1`.
- Login submit disabled until the page has loaded; signed-in users are redirected away from `/login`.
- Stricter scan-range validation and normalization; whole-number settings; audit-log `limit` clamped to 1–200.
- Correct 400/403/404 responses (malformed login, deleting missing users or credentials, live progress for missing or forbidden scans).
- Settings changes are audit-logged.

**Scoring and reports**
- A weakness found by both a built-in check and a community record is scored once.
- Internet Exposure records require a public IP; unidentified vendors no longer get stronger matches.
- Report summary distinguishes confirmed critical issues from potential ones and never contradicts the overall rating.

**Interface**
- Phone layout with a slide-out menu; collapsed sidebar remembered across pages.
- Only one sidebar item highlighted at a time.
- Clear "not found" / "no access" pages for scan progress and reports; stopped scans show **STOPPED** instead of a risk badge.
- Settings fields show validation messages; the nested-button hydration error is fixed.
- New Scan states whether the scanner is live or simulated.

---

## Ethical Notice

SentriX is built for **defensive security purposes only**. It contains:
- No exploit code or payloads
- The credential check tries vendor default credentials and a built-in weak-password list on **real scans with Safe Scan Mode off**; it **stops on lockout** and **never stores passwords**. Keep Safe Scan Mode on for production networks
- No unauthorized internet scanning capability (ranges are limited to /16 or smaller)
- Mandatory authorization confirmation before each scan
- Safe scan mode enabled by default (also required-off to run the credential check)

**Always obtain written authorization before scanning any network.**

---

## License

MIT License — For educational and authorized security testing use only.

---

*SentriX — Final Year Cybersecurity Project*
