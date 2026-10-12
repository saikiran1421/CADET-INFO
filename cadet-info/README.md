# CADET INFO — NCC Cadet Information Management System

Secure web app for NCC cadets (profile, camps, experiences, certificates) and ANOs (unit dashboard, Excel-style view, exports, audit log).

**Stack:** Node.js ≥ 22.13 · built-in `node:http` + `node:sqlite` (SQLite, relational schema in `schema.sql`) · vanilla JS front-end · **zero npm dependencies** (nothing to install, nothing to patch). Private certificate files on disk (`DATA_DIR/certs`, random names, never served statically).

## Run locally
```bash
node seed.js          # demo units/accounts; prints random passwords ONCE (demo only)
node server.js        # http://localhost:3000
npm test              # security test matrix (17 scenarios)
```
Cadet portal: `/#/login/cadet` · ANO / Super Admin portal: `/#/login/ano`

## Production setup (first launch)
1. Set env vars (see `.env.example`): `NODE_ENV=production`, `DATA_DIR` (persistent disk), `SUPERADMIN_EMAIL`, `SUPERADMIN_PASSWORD` (≥12 random chars), `TRUST_PROXY=1`, optional `REGISTRATION_CODE`.
2. Start the app → the Super Admin is created automatically. **Remove `SUPERADMIN_PASSWORD` afterwards.**
3. Log in at the ANO portal as Super Admin → **Units** (create your NCC unit/battalion/institution) → **ANO Accounts** (create each ANO and assign a unit; give them the initial password privately).
4. Cadets register themselves at `/#/register`, choose their unit, then fill in their profile. Share the `REGISTRATION_CODE` in class so outsiders cannot register.

## Deploy
* **Docker:** `docker build -t cadet-info . && docker run -p 3000:3000 -v cadetdata:/data --env-file .env cadet-info`
* **Render / Railway / Fly.io:** create a web service from this folder (Docker or Node 22), **attach a persistent disk mounted at `/data`**, set env vars above. These platforms provide HTTPS — required, because the session cookie is `Secure` in production.
* Run **one instance only** (SQLite file + local disk). Schedule backups of `/data` (database + `certs/`).

## Roles & access (enforced server-side in `server.js`)
| Role | Can access |
|---|---|
| CADET | Only own profile/camps/certificates. No endpoint accepts a cadet ID from the client for cadet actions. |
| ANO | Cadets whose `unit_id` equals the ANO's unit: list, detail, certificates, stats, export. Other units → 404. |
| SUPER_ADMIN | All units; manages units, ANO accounts, activation, audit logs. |

Certificates: `GET /api/certificates/:id/file` checks owner / same-unit ANO / super admin on every request; filenames on disk are random; files are validated by size (≤ 5 MB), extension **and** magic bytes (PDF/JPG/PNG).

## Production security checklist
- [ ] HTTPS only (host-provided); `NODE_ENV=production`
- [ ] Strong unique Super Admin / ANO passwords; remove `SUPERADMIN_PASSWORD` env after first start
- [ ] `/data` on a persistent, private disk; automated backups (encrypt them)
- [ ] `REGISTRATION_CODE` set; `TRUST_PROXY=1` only behind a trusted proxy
- [ ] Demo seed accounts never created in production
- [ ] Review audit logs regularly; deactivate departed ANOs/cadets
- [ ] Keep Node.js updated (`node:sqlite` is marked experimental by Node)
- [ ] Tell cadets what is stored (privacy notice at `/#/privacy`); follow your institution's data-protection rules (e.g. India DPDP Act)

## Known limits
No email/password-reset flow (Super Admin can create new ANO accounts; cadet password reset is not yet built). Camp "days" = To − From, as specified (a 1–10 Jan camp = 9). Single-node SQLite suits one college/unit group; migrate `schema.sql` to PostgreSQL for multi-instance scale.
