# ftd (Form To-Do) Specification

This document captures the project requirements and design goals gathered during the Development session. It can be used to recreate the `ftd` FastCGI form collector and admin dashboard.

## Core goals
- Provide a FastCGI listener for HTML form submissions and admin traffic forwarded by a front-end web server (e.g., nginx or OpenBSD httpd), defaulting to a Unix socket but allowing an optional TCP port via `-tcp <port>`. Default FastCGI paths are `/form` for submissions and `/form/admin` for admin; both are configurable via `FORM_PATH` and `ADMIN_PREFIX`.
- Persist each submission to PostgreSQL with:
  - Request metadata: timestamp, client IP, user agent, referrer.
  - JSONB payload containing **all form fields** (dynamic schema) plus upload metadata when present (`_upload_original_filename` and `_upload_stored_filename`).
- Offer an admin dashboard (also served via FastCGI) with authentication, pagination, and status workflow:
  - Status values: `new`, `in_progress`, `complete`, `archived`.
  - Main dashboard hides `archived` entries; a dedicated Archived view lists them with pagination.
  - The Active dashboard provides a bulk "Archive completed" control to sweep all rows currently marked `complete` into `archived`.
  - Each submission includes a reviewer comment field that can be edited alongside status updates and renders in a muted/read-only style when archived.
  - Admin login is password protected; password hashes are stored in the database (bcrypt).
  - The schema seeds a default admin (`admin` / `change-me`); the dashboard shows a red warning while the default hash is in use and exposes a CSRF-protected password change form so operators can rotate credentials without dropping their current session.
  - Sessions are signed and refreshed on activity (to avoid logging out open tabs); if `SESSION_SECRET` is unset, an ephemeral random key is generated per process (sessions invalidate on restart). Cookies default to `Secure`, `HttpOnly`, and `SameSite=Strict` unless `SESSION_COOKIE_INSECURE` is set for local HTTP testing.
  - Admin POSTs (login and status updates) require CSRF tokens validated against secure cookies.
- Include a sample HTML submitter form and a backend admin HTML experience that formats JSON payloads into readable field/value pairs plus prettified JSON.

## Security and robustness
- Assume form inputs are hostile: use prepared statements/parameterized queries for all SQL operations and validate status values before mutating rows; clamp comment length to avoid oversized updates.
- Validate pagination/status query parameters; reject invalid statuses.
- Render user content through Go html/template to ensure escaping; JSON is prettified for readability.
- Capture and log errors without leaking sensitive detail to clients.
- Send defensive admin response headers (CSP with self-only sources, frame denial, no sniffing, strict referrer/permissions policies, cache disabling) to reduce injection and clickjacking exposure.
- Front-end web server should terminate TLS and forward `X-Forwarded-For` so real client IPs are recorded.
- Throttle hostile traffic: block any IP that submits more than 4 forms within a one-minute window for 24 hours, and pause all submissions for 5 minutes when a sudden burst of 30+ distinct IPs appears in that same window. Return appropriate HTTP status codes (429 for IP blocks, 503 for global pauses) with `Retry-After` where applicable.
- Cap FastCGI submission size to 64KB (plus any configured upload allowance) and reject requests with more than 200 fields to mitigate data flooding; uploads are rejected entirely unless explicitly enabled.
- Allow at most one uploaded file per submission when enabled; enforce the configured byte cap, write it inside the chroot with a unique name `ftd.TIMESTAMP,<8-hex>`, and record the stored name and any client-supplied original name in the JSON payload under `_upload_stored_filename` and `_upload_original_filename`. Persist the stored path (or `Failed Upload (<status code>)`) in `file_path` for dashboard display.

## Privilege hardening
- If the process starts as `root`, open the PostgreSQL socket and FastCGI socket first, then chroot to the `_ftd` user’s home and drop privileges to that UID/GID.
- On OpenBSD, apply pledge(2): initial broad promise, tighten after DB connection and listener setup, then run with a reduced pledge set.
- Keep a single persistent DB connection so it survives the chrooted environment.

## Database schema
- Initialize the PostgreSQL schema (from `schema.sql`) before the first run; the service does not apply migrations at runtime an
d will exit on startup if required tables are missing.
- Tables:
  - `submissions`: `id` (PK), `submitted_at` (default `NOW()`), `ip_address`, `user_agent`, `referer`, `status` (check constraint on allowed values), `file_path` (optional stored upload path or failure label), `comment` (optional reviewer notes), `form_data` (JSONB with field data and upload metadata when a file is present).
  - `admin_users`: `username` (PK), `password_hash`, `created_at`.
  - `submission_blocks`: `scope` (`ip` or `global`), `identifier`, `blocked_until` to track per-IP and global throttling windows.
- Indexes: at least on `submissions.status` and `submissions.submitted_at DESC` to speed filtering and pagination.

## Admin UX expectations
- Dashboard presents two tabs (Active, Archived) with modern styling.
- Cards show submission metadata, extracted field list, reviewer comment textarea (muted/read-only when archived), prettified JSON, and status dropdown for updates.
- Active tab includes a bulk action to archive all `complete` submissions.
- Filtering on Active view by status (`new`, `in_progress`, `complete`).
- Logout endpoint clears the session.

## Deployment notes
- Environment variables:
  - `DATABASE_URL` (required)
  - `FASTCGI_SOCKET` (default `/var/www/run/ftd.sock`)
  - `FORM_PATH` (default `/form`)
  - `ADMIN_PREFIX` (default `/form/admin`)
  - `SESSION_SECRET` (optional; auto-generated if omitted)
  - `SESSION_COOKIE_INSECURE` (optional; disable `Secure` cookies for local HTTP testing only)
  - `MAX_UPLOAD_MB` (default `0`; set to allow one uploaded file per submission up to the given megabytes)
- An OpenBSD `rc.d` helper (`rc.d/ftd`) is provided; it sources `/etc/ftd.env` for environment variables, backgrounds under `rcctl`, and runs the daemon in the foreground so rc.subr can supervise it.
- Place the FastCGI socket where the web server can reach it and restrict permissions accordingly. Create it before chroot/drop-privilege when starting as `root`. If running with `-tcp`, configure your front-end to FastCGI proxy to the chosen port instead of the Unix socket.
- Example front-ends: nginx or OpenBSD httpd using `fastcgi_pass unix:/var/www/run/ftd.sock;` for both `/form` and `/form/admin/`.
- Initialize the PostgreSQL schema (from `schema.sql`) before the first run; the service does not apply migrations at runtime.

## Testing expectations
- `go build ./...` should succeed (requires access to `github.com/lib/pq` and `golang.org/x/crypto`).
- Admin/UI HTML and CSS should render without external assets beyond system fonts.

