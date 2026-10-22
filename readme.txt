==============================================================================
 SentriX
 Intelligent Automated Security Auditing System for IP CCTV Networks
 Full technical README  (plain-language, for anyone)
==============================================================================

 FOR AUTHORISED AND ETHICAL SECURITY TESTING ONLY.
 Only scan networks you own or have explicit written permission to test.
 SentriX probes devices and (when enabled) tries ONE authorised default-password
 check; doing that on networks you do not control may be illegal.

------------------------------------------------------------------------------
 TABLE OF CONTENTS
------------------------------------------------------------------------------
 1.  What SentriX is
 2.  What it does (features)
 3.  Technology used
 4.  How it works end to end (the scan pipeline)
 5.  How a device is identified as CCTV
 6.  How a device is judged vulnerable (the important rule)
 7.  The vulnerability database file (data/vulnerabilities.txt)
 8.  The default-credentials database and the live credential check
 9.  Risk score, trust score and device status
 10. Requirements
 11. Install and run (step by step)
 12. Logging in (demo accounts)
 13. Environment variables (all of them)
 14. Run modes: real scan vs simulation, local DB vs Supabase
 15. Using the app screen by screen
 16. How to UPDATE things (vuln DB, credentials, users, settings, checks)
 17. Database setup and migrations (Supabase)
 18. Production deployment (PM2)
 19. Testing, type-check, lint, build
 20. Project structure (where everything lives)
 21. API endpoints (reference)
 22. Security & safety controls
 23. Troubleshooting (common problems)
 24. Glossary


==============================================================================
 1. WHAT SENTRIX IS
==============================================================================
SentriX scans a network, finds the CCTV equipment on it (IP cameras, NVRs,
DVRs), checks each device against a vulnerability database and an optional
default-password test, scores the risk, and produces a shareable report. It is
a web application with a dashboard, user accounts and roles.

A "POC mode" lets it run with ZERO external setup (no database server needed):
it uses a built-in in-memory database and can scan either a real network or a
set of built-in demo devices.


==============================================================================
 2. WHAT IT DOES (FEATURES)
==============================================================================
 * Real network discovery - non-intrusive probing (TCP connect, one RTSP
   OPTIONS, unauthenticated HTTP GETs). No brute force, no exploits.
 * CCTV identification - a weighted classifier separates cameras/NVRs/DVRs
   from printers, PCs, routers, etc. (see section 5).
 * Vulnerability matching - each device is compared to records in a plain-text
   database (data/vulnerabilities.txt) by EXACT model + firmware (see section 6).
 * Authorised credential check - on real scans (Safe Scan Mode off): tries
   vendor default credentials AND common weak passwords, stops on lockout,
   never stores passwords (see section 8). Default creds -> Critical;
   weak password -> Low.
 * Risk & trust scoring - per device (0-100) and overall network rating.
 * Separated statuses - Known-Vulnerability / Authentication / Overall status
   so a device is never "vulnerable" just because a port is open.
 * Device inventory - each physical device listed once (latest scan).
 * Reports - printable HTML report per scan.
 * Roles - Admin and Technician, JWT login, server-side logout, lockout.
 * Audit log - logins, scans, reports, user/settings/DB changes.
 * Safety controls - authorisation confirmation, safe scan mode, range limits.


==============================================================================
 3. TECHNOLOGY USED
==============================================================================
 Framework ....... Next.js 14 (App Router) + React 18 + TypeScript
 Styling ......... Tailwind CSS, Framer Motion, lucide-react icons, Recharts
 Auth ............ JWT (jose), bcryptjs password hashing
 Validation ...... Zod + react-hook-form
 Database ........ Supabase (PostgreSQL)  OR  built-in in-memory DB (POC mode)
 Tests ........... Jest + ts-jest
 Node ............ Node.js 18+ (developed on Node 22)


==============================================================================
 4. HOW IT WORKS END TO END (THE SCAN PIPELINE)
==============================================================================
When a scan runs, each device goes through these steps (in this order):

 Step 1  Network discovery      - find live hosts in the range (port sweep).
 Step 2  CCTV identification    - decide camera / NVR / DVR / not-CCTV.
 Step 3  Vulnerability match    - compare to data/vulnerabilities.txt.
 Step 4  Credential check       - optional authorised default-password test.
 Step 5  Risk + status          - score risk, set the three statuses.
 Step 6  Save to database       - store only findings confirmed in THIS scan.
 Step 7  Dashboard & reports    - pages read the saved results.

Discovery (Steps 1-2) is kept SEPARATE from vulnerability detection (Steps 3-4):
finding a device does NOT make it vulnerable.

Main code: lib/scanner/mock-scanner.ts (runMockScan orchestrates all 7 steps).


==============================================================================
 5. HOW A DEVICE IS IDENTIFIED AS CCTV
==============================================================================
SentriX collects harmless clues, gives each a point value, adds them up, and if
the total reaches the threshold it treats the host as CCTV and audits it;
otherwise it is ignored (not stored, not scanned, not counted).

Clues and points (lib/scanner/cctv-discovery.ts -> classifyHost):
   Live video stream (RTSP confirmed on 554) .............. +35
   ONVIF service present .................................. +35
   Known camera brand (Hikvision, Dahua, Axis, Hanwha...) . +40
   Vendor API (Hikvision ISAPI / Dahua-SDK / Axis VAPIX) . +25
   Camera-brand MAC address (OUI) ........................ +25
   SDK port 8000 (Hikvision) / 37777 (Dahua) open ........ +20 each
   Port 554 open but RTSP not confirmed .................. +15
   Two or more CCTV ports open together .................. +15
   Web page (80/443) ONLY if a strong clue already exists  +5
   Web page on its own ................................... +0  (ignored)

Decision (threshold = 35):
   score >= 35  -> CCTV device (audited)
   score <  35  -> not CCTV (skipped)
Confidence: >=75 High, 60-74 Medium, 35-59 Low.
Type: model names like "DS-76xxNI"/"NVR" -> NVR; "DVR" -> DVR; else IP Camera.

Why a plain web page scores 0 alone: printers, routers and PCs also serve web
pages, so a web page only counts when a real camera clue is already present.

Evidence gathering: lib/scanner/network-discovery.ts (port sweep, RTSP/HTTP
probes, Server header, vendor endpoints, MAC OUI, model/firmware parsing).


==============================================================================
 6. HOW A DEVICE IS JUDGED VULNERABLE  (THE IMPORTANT RULE)
==============================================================================
A device is marked VULNERABLE only if ONE of these is true:

 (A) KNOWN VULNERABILITY MATCH
     Its EXACT model is listed in data/vulnerabilities.txt AND its firmware is
     consistent with that record's firmware:
       - Firmware "*"            -> matches every firmware (confirmed).
       - Device firmware known and inside the record's range -> confirmed.
       - Device firmware known but outside the range -> NO match.
       - Device firmware UNKNOWN + record names a specific range
                                 -> UNVERIFIED (potential, not confirmed, 0 risk).
     Records with "Models: *" or a pattern like "DS-2CD2*" NEVER match. A
     vendor/port/protocol signal alone is NOT a vulnerability.

 (B) CONFIRMED DEFAULT CREDENTIALS
     The authorised credential check logged in with a default password
     (see section 8).

Anything else (open ports, HTTP-only, RTSP present, being a Hikvision, etc.) is
recorded as an INFORMATIONAL observation only: shown on the device, but it does
NOT add risk and does NOT make the device vulnerable.

Reminder: "No record matched" does NOT prove a device is safe - it only means
no KNOWN vulnerability was found in the local database.

Matching code: lib/vuln-db/matcher.ts (matchDevice).


==============================================================================
 7. THE VULNERABILITY DATABASE FILE  (data/vulnerabilities.txt)
==============================================================================
This plain-text file is the authoritative list of known CCTV vulnerabilities.
You edit it with any text editor. Lines starting with "#" are comments.

One record looks like this (fields are "Label: value", record ends with "---"):

   ID: SXV-2026-0001
   Title: Outdated Firmware on DS-2CD2042WD-I (V5.7 branch)
   Vendor: Hikvision
   Models: DS-2CD2042WD-I
   Firmware: V5.7.*
   Device Type: camera
   Category: Outdated Firmware
   Severity: High
   CVSS: 7.5
   Risk Score: 25
   Ports: 80, 8000
   Protocols: HTTP, ISAPI
   Keywords: hikvision, camera, outdated firmware
   Source: COMMUNITY_REPORTED
   Published: 2026-10-12
   Updated: 2026-10-12
   Description: ...one line...
   Recommendation: ...one line...
   Steps:
   - step one
   - step two
   Note: ...one line...
   ---

Field rules:
 * Models: list EXACT model names, comma separated. Do NOT use "*" or patterns
   if you want precise matching - each listed model must be the full name.
 * Firmware: "*" = any version; or a version/wildcard like "V5.7.*".
   (The device string "V5.7.3 build 210721" matches "V5.7.*".)
 * Device Type: camera | nvr | dvr | any
 * Severity + Risk Score must agree:
       Critical 30-40, High 20-29, Medium 10-19, Low 1-9, Informational 0
 * Source: SIMULATED | COMMUNITY_REPORTED | VENDOR_ADVISORY | CVE
   (use CVE only with a real CVE id as the ID, e.g. CVE-2021-12345)
 * Dates: YYYY-MM-DD.

HOW TO ADD A RECORD:
 1. Copy an existing record (ID line down to the "---").
 2. Paste at the end of the file and change the values. Use a new unique ID.
 3. Save the file.
 4. In the app: Community Vulnerabilities page -> "Reload local file"
    (or just run the next scan - the file is re-read automatically on change).

Parsing/validation code: lib/vuln-db/parser.ts, lib/vuln-db/validator.ts
Full schema: data/vulnerability-schema.md


==============================================================================
 8. DEFAULT-CREDENTIALS DATABASE AND THE LIVE CREDENTIAL CHECK
==============================================================================
There is a separate list of known factory default usernames/passwords per
vendor (the "default_credentials" table / list). It is ADMIN ONLY.

The authorised credential check (lib/scanner/credential-check.ts) makes REAL
login attempts. It runs automatically on REAL scans when BOTH:
   * Safe Scan Mode is OFF (Settings), and
   * the "Default Credentials Check" is enabled (Vulnerability Checks).
It is always OFF in simulation mode. (The optional SENTRIX_ALLOW_CRED_CHECK
env flag from earlier builds is no longer required.)

What it tests, per device:
   1. Every FACTORY DEFAULT credential stored for the device's exact vendor
      (highest-risk first). No other vendor's credentials are tried.
   2. Then a built-in list of common WEAK passwords (12345678, password,
      admin, qwerty, 00000000, ...) against the admin usernames.
   The first credential that works wins and testing stops.

Safety:
   * Reliable success signal: a protected page that returns 401 when
     unauthenticated and 2xx only when a credential is accepted. A 200 login
     page is NOT treated as success.
   * STOPS IMMEDIATELY on any lockout/throttling signal (HTTP 429/403/503).
   * NEVER logs, stores, returns or displays a password - only the vendor and
     username (and whether it was a default or weak password).
   WARNING: trying many passwords can lock out real accounts. This is an
   authorised-lab feature; keep Safe Scan Mode ON for production networks.

Possible results (authentication_status):
   CONFIRMED_DEFAULT_CREDENTIALS - a factory default worked -> Critical finding
                                   -> device VULNERABLE (Critical).
   CONFIRMED_WEAK_PASSWORD       - a weak/common password worked -> Low finding
                                   -> device VULNERABLE (Low).
   AUTHENTICATION_REJECTED       - all attempts refused -> no credential finding.
   NOT_TESTED                    - no web interface / check not active.
   AUTHENTICATION_ERROR          - timeout, lockout or service error.


==============================================================================
 9. RISK SCORE, TRUST SCORE AND DEVICE STATUS
==============================================================================
Risk score (0-100) comes ONLY from confirmed findings:
   confirmed vulnerabilities.txt matches + a confirmed credential finding.
Informational observations add 0. The total is capped at 100.
Trust score = 100 - risk score.

Risk level from score: 0 secure, 1-20 low, 21-45 medium, 46-70 high, 71-100 crit.

Each device has THREE separate statuses:
   known_vulnerability_status : MATCHED | NO_MATCH | UNVERIFIED
   authentication_status      : CONFIRMED_DEFAULT_CREDENTIALS |
                                CONFIRMED_WEAK_PASSWORD |
                                AUTHENTICATION_REJECTED | NOT_TESTED |
                                AUTHENTICATION_ERROR
   overall_security_status    : VULNERABLE | HEALTHY | NOT_VERIFIED

Overall rules:
   VULNERABLE   - a confirmed file match OR confirmed default/weak credentials.
                  (Default credentials -> Critical risk; weak password -> Low.)
   NOT_VERIFIED - no confirmed finding, but a needed check could not complete
                  (unknown firmware on a matched model, auth error, or an
                  auth test required by policy that could not run).
   HEALTHY      - no confirmed finding and all needed checks completed.
Code: lib/risk/calculator.ts


==============================================================================
 10. REQUIREMENTS
==============================================================================
 * Node.js 18 or newer (22 recommended) and npm.
 * A Linux/macOS/WSL shell is easiest (real scanning needs raw socket access
   and, for MAC addresses, same-LAN access).
 * Optional: a Supabase project (only for production with a real database).
 * Optional: PM2 (for production process management).


==============================================================================
 11. INSTALL AND RUN  (STEP BY STEP)
==============================================================================
 1. Install dependencies:
        npm install

 2. Start in development (REAL scanning + debug logging are ON in this script):
        npm run dev
    Open http://localhost:3000

 3. Or start in SIMULATION mode (built-in demo devices, no real traffic):
        npm run dev:sim

 4. Build and run a production build locally:
        npm run build
        npm run start            (real scanning on; port 3000)

No .env file is required for POC mode - it falls back to the in-memory database
automatically. See section 13 for all configuration.


==============================================================================
 12. LOGGING IN  (DEMO ACCOUNTS)
==============================================================================
In POC / local-DB mode two accounts are seeded:

   Admin        email: admin@sentrix.local    password: Admin@SentriX2024
   Technician   email: tech@sentrix.local     password: Tech@SentriX2024

Change these before any real deployment. (On Supabase, users come from the
users table seeded by database/seed.sql - update those hashes.)

Roles:
   Admin      - everything: users, settings, credentials DB, vuln checks,
                vulnerability DB sync, all scans and reports.
   Technician - run scans, view their own scans/devices/reports; read-only
                scanner settings; cannot see the credentials DB or manage users.


==============================================================================
 13. ENVIRONMENT VARIABLES (ALL OF THEM)
==============================================================================
Scanning behaviour:
   SENTRIX_REAL_SCAN=1        Use REAL network probing. Unset/0 = simulation
                              (built-in demo devices).
   SENTRIX_SCAN_DEBUG=1       Print per-device discovery + classification lines
                              to the server log.
   SENTRIX_ALLOW_CRED_CHECK   Deprecated / optional. The credential check now
                              runs on real scans whenever Safe Scan Mode is OFF
                              and the check is enabled; this flag is not required.

Database selection:
   NEXT_PUBLIC_SUPABASE_URL        Supabase project URL. If missing/placeholder,
                                   SentriX uses the in-memory local DB.
   NEXT_PUBLIC_SUPABASE_ANON_KEY   Supabase anon key.
   SUPABASE_SERVICE_ROLE_KEY       Supabase service-role key (server side).
   SENTRIX_ALLOW_LOCAL_DB=1        Explicitly allow the in-memory DB in
                                   production (POC/demo). Without it, production
                                   refuses to start without Supabase.

Auth:
   JWT_SECRET                 Secret used to sign login tokens. SET THIS to a
                              long random value in any real deployment.

Vulnerability database:
   COMMUNITY_VULN_DB_ENABLED      "false" disables vuln matching. Default on.
   COMMUNITY_VULN_DB_LOCAL_PATH   Path to the text DB. Default
                                  data/vulnerabilities.txt
   COMMUNITY_VULN_DB_SYNC_MODE    local | remote | both. Default local.
   COMMUNITY_VULN_DB_REMOTE_URL   Raw URL (e.g. GitHub) for remote sync.

UI:
   NEXT_PUBLIC_SHOW_DEMO_CREDENTIALS   Show the demo accounts on the login page.
   NODE_ENV                            standard Node environment.


==============================================================================
 14. RUN MODES
==============================================================================
REAL vs SIMULATION (controlled by SENTRIX_REAL_SCAN):
   Real        - probes the actual network you entered. Finds real devices.
   Simulation  - returns a fixed set of built-in demo devices. Good for demos
                 and tests. Results are clearly flagged as "SIMULATED DATA" in
                 the UI and in the report, so they are never mistaken for real.

LOCAL DB vs SUPABASE (auto-detected in lib/supabase/server.ts):
   Local (in-memory)  - used when no real Supabase URL is configured. Data
                        resets when the server restarts. Great for POC/demo.
   Supabase           - used when NEXT_PUBLIC_SUPABASE_URL +
                        SUPABASE_SERVICE_ROLE_KEY are set. Persistent.

Both axes are independent: you can run a REAL scan against the LOCAL DB.


==============================================================================
 15. USING THE APP  (SCREEN BY SCREEN)
==============================================================================
 Dashboard       - totals (devices, vulnerable, healthy, not-verified,
                   known-vuln, confirmed credentials, critical), risk chart,
                   recent scans.
 Scans           - list of scans; "New Scan" to start one.
 New Scan        - enter a name and network range (e.g. 192.168.1.0/24), tick
                   the authorisation box, start. A /16 is the largest allowed;
                   loopback/multicast/0.0.0.0 are rejected.
 Scan progress   - live progress and device count while it runs.
 Scan results    - devices found, their statuses, findings, discovery summary.
 Devices         - every physical device once (latest scan), with firmware,
                   overall status, trust score, known-vuln and info counts.
 Device details  - full breakdown: identity, ports, protocols, risk/trust,
                   known-vulnerability status, authentication assessment,
                   confirmed findings, informational observations, DB matches.
 Reports         - generate / view / download the HTML report for a scan.
 Community Vulns  - view the loaded vulnerability records; reload local file;
                   sync from the remote URL (admin).
 Vulnerability Checks (admin) - enable/disable individual checks.
 Default Credentials (admin)  - manage the vendor default-password list.
 Users (admin)   - create/delete users and set roles.
 Settings        - Safe Scan Mode, scan timeout, login attempt limit
                   (scanner settings are global; admin edits, technician reads).
 Audit Logs      - chronological record of important actions.
 About           - app information.


==============================================================================
 16. HOW TO UPDATE THINGS
==============================================================================
 UPDATE THE VULNERABILITY DATABASE:
   Edit data/vulnerabilities.txt (section 7), save, then click
   "Reload local file" on the Community Vulnerabilities page. Or configure a
   remote URL and use "Sync".

 UPDATE DEFAULT CREDENTIALS:
   Admin -> Default Credentials page -> add/delete entries. (Or edit
   database/seed.sql / migrate_default_credentials.sql for Supabase and re-run.)

 ADD / REMOVE USERS:
   Admin -> Users page. (Supabase: insert into the users table with a bcrypt
   password_hash; see database/seed.sql for the format.)

 ENABLE / DISABLE CHECKS:
   Admin -> Vulnerability Checks page. Disabled checks are skipped by scans.

 CHANGE SCAN SETTINGS:
   Admin -> Settings: Safe Scan Mode (off = allow the credential check),
   scan timeout, login attempt limit. These are global for all users.

 CHANGE DEMO LOGINS:
   Replace the bcrypt hashes in lib/supabase/local-db.ts (local) or
   database/seed.sql (Supabase).


==============================================================================
 17. DATABASE SETUP AND MIGRATIONS (SUPABASE)
==============================================================================
POC/local mode needs no setup. For a real Supabase database, run these SQL
files in the Supabase SQL editor, in order:

   database/schema.sql                         (base tables + RLS)
   database/seed.sql                           (demo users + default creds)
   database/migrate_default_credentials.sql    (full vendor credential set)
   database/migrate_community_vulnerabilities.sql (per-scan match table)
   database/migrate_scan_mode.sql              (scan_mode column)
   database/migrate_device_status.sql          (known/auth/overall status +
                                                trust_score + informational flag)
   database/migrate_revoked_tokens.sql         (server-side logout support)

If you upgrade an existing database, make sure migrate_device_status.sql has
been applied, or the new per-device statuses fall back to derived values.


==============================================================================
 18. PRODUCTION DEPLOYMENT (PM2)
==============================================================================
An ecosystem.config.js is included for PM2:

   npm install
   npm run build
   pm2 start ecosystem.config.js        (or: pm2 start ecosystem.config.js --env production)

It runs "next start" on PORT 3000 with SENTRIX_REAL_SCAN=1 and
SENTRIX_ALLOW_LOCAL_DB=1, fork mode, auto-restart, logs in ./logs.

For a REAL production database, set the Supabase env vars and JWT_SECRET (and
remove SENTRIX_ALLOW_LOCAL_DB unless you intentionally want the demo DB).


==============================================================================
 19. TESTING, TYPE-CHECK, LINT, BUILD
==============================================================================
   npm test                 Run the Jest test suite (unit + route + flow tests).
   npx tsc --noEmit         Type-check the whole project.
   npm run lint             ESLint (next lint).
   npm run build            Production build (also type-checks route modules).

Tests live in __tests__/ and cover discovery, matching, the 12 classification
cases, the credential check, risk scoring, reports and API routes.


==============================================================================
 20. PROJECT STRUCTURE (WHERE EVERYTHING LIVES)
==============================================================================
   app/
     (auth)/login            Login page.
     (dashboard)/...         All signed-in pages (section 15).
     api/...                 Server endpoints (section 21).
     layout.tsx, page.tsx    Root layout and landing redirect.
   lib/
     scanner/
       network-discovery.ts  Real probing + fingerprinting + credential probe.
       cctv-discovery.ts     CCTV classification (scoring + threshold).
       credential-check.ts   Authorised default-credential verification.
       mock-scanner.ts       The 7-step scan pipeline (real + simulation).
       report-generator.ts   HTML report builder.
     vuln-db/
       parser.ts, validator.ts  Read + validate data/vulnerabilities.txt.
       store.ts, queries.ts     Load records, per-scan matches.
       matcher.ts               Exact model + firmware matching engine.
       constants.ts, config.ts  Severities, categories, env config.
     risk/calculator.ts       Risk/trust scores + status classification.
     devices/inventory.ts     One row per physical device (latest scan).
     auth/                    JWT + middleware + password hashing.
     supabase/
       server.ts              Chooses Supabase vs local DB.
       local-db.ts            In-memory DB (seeded users, creds, checks).
     validators/schemas.ts    Zod input schemas.
     utils/                   Helpers (rate limiter, formatting).
   data/
     vulnerabilities.txt      The vulnerability database (you edit this).
     vulnerability-schema.md  Full record-format reference.
   database/                  schema.sql + migrations + seed.sql.
   types/index.ts             All shared TypeScript types.
   __tests__/                 Test suite.
   components/                React UI components.
   middleware.ts              Route protection (auth).
   ecosystem.config.js        PM2 production config.
   next.config.js, tailwind.config.ts, tsconfig.json, jest.config.js


==============================================================================
 21. API ENDPOINTS (REFERENCE)
==============================================================================
 Auth:
   POST /api/auth/login         Log in (sets JWT cookie).
   POST /api/auth/logout        Log out (revokes token).
   GET  /api/auth/me            Current user.
 Scans:
   GET/POST /api/scans          List / create scans.
   GET/DELETE /api/scans/{id}   Get / delete a scan.
   POST /api/scans/{id}/start   Start a scan.
   POST /api/scans/{id}/stop    Stop a running scan.
   GET  /api/scans/{id}/events  Live progress (streaming).
   GET  /api/scans/{id}/results Devices + findings + matches + discovery.
 Devices:
   GET /api/devices             Device inventory (?scan=ID to filter).
   GET /api/devices/{id}        One device with findings + matches.
 Reports:
   GET /api/reports             List reports.
   POST /api/reports/{scanId}/generate   Build the HTML report.
   GET  /api/reports/{scanId}            Fetch a report.
 Dashboard:
   GET /api/dashboard           Aggregated counts + chart data.
 Vulnerability DB:
   GET  /api/community-vulns         List loaded records.
   GET  /api/community-vulns/status  Source, counts, last load.
   POST /api/community-vulns/sync    Reload local / sync remote (admin).
 Checks / credentials / users / settings / audit (admin where noted):
   GET/PUT   /api/vulnerability-checks[/{id}] , /bulk
   GET/POST  /api/default-credentials  ,  DELETE /{id}      (admin)
   GET/POST  /api/users  ,  GET/DELETE /api/users/{id}      (admin)
   GET/PUT   /api/settings                                  (admin edits)
   GET       /api/audit-logs
   GET       /api/scanner                                   (scanner status)


==============================================================================
 22. SECURITY & SAFETY CONTROLS
==============================================================================
 * Authorisation confirmation required before every scan.
 * Range limits: /16 or smaller; loopback, multicast and 0.0.0.0 rejected.
 * Safe Scan Mode (on by default) blocks the active credential check.
 * Credential check is triple-gated (section 8) and never stores passwords.
 * Non-intrusive probing only: no brute force, no exploits.
 * JWT auth, bcrypt password hashing, server-side logout (token revocation),
   login attempt limit / account lockout.
 * Role-based access; the credentials DB is admin-only.
 * Row Level Security enabled on all Supabase tables (fail-closed).
 * Production refuses the in-memory demo DB unless SENTRIX_ALLOW_LOCAL_DB=1.


==============================================================================
 23. TROUBLESHOOTING
==============================================================================
 "Running in LOCAL mode (no Supabase)" in logs:
     Expected in POC mode. Set Supabase env vars for a real database.

 Production won't start / refuses local DB:
     Set Supabase env vars, or set SENTRIX_ALLOW_LOCAL_DB=1 for a demo deploy.

 Real scan finds 0 devices:
     The range may be empty, firewalled, or on a different network segment.
     Inside WSL, the WSL subnet usually cannot reach your office LAN - run on a
     host that sits on the camera network, or enable WSL mirrored networking.
     MAC addresses and multicast only work on the SAME LAN segment.

 Device shows model/firmware "Unknown":
     The device did not expose them without a login. It will be NOT_VERIFIED
     rather than guessed - this is intentional.

 A device I expected is not vulnerable:
     Its exact model + firmware must be in data/vulnerabilities.txt. Patterns
     like "DS-2CD2*" and "Models: *" never match. Add the exact model, reload.

 Credential check never runs:
     Needs a REAL scan + Safe Scan Mode OFF + the Default Credentials Check
     enabled + an open web interface on the device. In simulation mode it never
     runs. Keep Safe Scan Mode ON for production networks to avoid lockouts.

 Vulnerability DB edits not showing:
     Click "Reload local file", or run a new scan (the file is re-read on
     change). Check the Community Vulnerabilities status for parse errors.


==============================================================================
 24. GLOSSARY
==============================================================================
 CCTV         Closed-circuit television: IP cameras, NVRs, DVRs.
 NVR / DVR    Network / Digital Video Recorder (stores camera footage).
 RTSP         Real-Time Streaming Protocol (live video), TCP port 554.
 ONVIF        Open standard for IP camera control/discovery.
 ISAPI/SDK    Vendor control interfaces (Hikvision ISAPI, Dahua/Hikvision SDK).
 MAC / OUI    Hardware address; its first half (OUI) reveals the manufacturer.
 Firmware     The software running on the device; versions can be vulnerable.
 CVSS         Standard 0-10 severity score for a vulnerability.
 JWT          Signed token proving who is logged in.
 RLS          Row Level Security (database access rules in PostgreSQL).
 POC mode     Proof-of-concept mode: in-memory DB, no external setup needed.

==============================================================================
 For authorised security testing only. (c) SentriX project.
==============================================================================
