# ftd Form To-Do

Yet another form handler. FastCGI Form Collector which turns submissions into to-do items for manual completion. Form fields are arbitrary and stored as submitted in JSON format. This project provides a minimal FastCGI listener for HTML form submissions, backed by PostgreSQL storage and an authenticated admin dashboard served over FastCGI.

## Features
- **FastCGI listener** on a Unix domain socket for dynamic form submissions and the admin dashboard (served via the same socket),
  with an optional TCP FastCGI listener via `-tcp <port>`.
- **PostgreSQL persistence** with JSONB storage for arbitrary form fields and request metadata (IP, user agent, referrer, timestamp).
- **Admin dashboard** with login (bcrypt passwords stored in the database), pagination, status management (`new`, `in_progress`, `complete`, `archived`), CSRF protection, hardened cookies, and nicely formatted JSON payloads.
- **Built-in throttling** that blocks abusive IPs (over 4 submissions per minute) for 24 hours and temporarily pauses all submissions for 5 minutes when a burst of distinct IPs appears.
- **Request caps** to protect the FastCGI endpoint from floods (64KB body and 200-field limit, with an adjustable upload budget on top).
- **Optional file capture** that, when enabled, stores an uploaded file inside the `_ftd` chroot with a unique timestamped name and records both the stored path and the original filename alongside the submission JSON. File uploads are disabled by default.
- **Sample submitter forms**: `sample_form.html` (no file upload) and `sample_form_upload.html` (includes a single file field) that post to the FastCGI endpoint.

## Configuration
Set the following environment variables before running the server:

| Variable | Description | Default |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL connection string (e.g., `postgres://user:pass@localhost:5432/forms`). | **Required** |
| `FASTCGI_SOCKET` | Unix socket path for the FastCGI listener. | `/var/www/run/ftd.sock` |
| `FORM_PATH` | FastCGI path for submissions. | `/form` |
| `ADMIN_PREFIX` | FastCGI path prefix for the admin dashboard (login, dashboard, static). | `/form/admin` |
| `SESSION_SECRET` | Secret used to sign admin session cookies; if omitted, an ephemeral random key is generated (sessions reset on restart). | Generated per process when unset |
| `SESSION_COOKIE_INSECURE` | If set, disables the default `Secure` cookie flag for admin/csrf cookies (useful for plain HTTP dev). | Not set (Secure cookies enabled) |
| `MAX_UPLOAD_MB` | Maximum allowed file upload size in megabytes; `0` disables uploads. | `0` |

## Database schema
Initialize the schema before the first run (ftd does not apply migrations at runtime and will exit if required tables are missi
ng):

```sh
psql "$DATABASE_URL" -f schema.sql
```

The schema creates `submissions` (with metadata, optional stored file path, reviewer comment, and JSONB payload), `admin_users` (bcrypt password hashes), and `submission_blocks` (temporary throttling windows). Indexes are added for status filtering and date ordering to keep pagination fast.
The schema also seeds a default admin account (`admin` / `change-me`); the dashboard will display a red reminder until you change it via the password form.
If you prefer to rotate the password directly from `psql` instead of using the dashboard, run these single-line commands at the `psql>` prompt to enable `pgcrypto` and set a new bcrypt hash for the admin account:

```
CREATE EXTENSION IF NOT EXISTS pgcrypto;
UPDATE admin_users SET password_hash = crypt('your-new-password', gen_salt('bf')) WHERE username = 'admin';
```

## Running locally
1. Export the required environment variables (see above).
2. Start the service:
   ```sh
   go run .
   ```
3. Point your FastCGI-capable web server at the configured socket (default `/var/www/run/ftd.sock`) for both form and admin paths. The service defaults to `/form` for submissions and `/form/admin` for the dashboard, configurable via `FORM_PATH` and `ADMIN_PREFIX` env vars.
   Alternatively, start the service with `-tcp 9000` (or another port) and configure your front-end to FastCGI proxy to `127.0.0.1:9000`.
4. Serve `sample_form.html` via your web server (or open from disk) and point its `action` at `/form` (or your `FORM_PATH`) on your FastCGI front-end. Access the admin dashboard through the same front-end at `/form/admin/` (or your `ADMIN_PREFIX`). To redirect submitters to a thank-you page after a successful submission, include a hidden field named `redirect` with an absolute or relative HTTP(S) URL; the handler issues a 303 See Other to that target once the form is stored.

> Note: Building requires downloading `github.com/lib/pq` and `golang.org/x/crypto`. Ensure outbound module downloads are permitted by your environment.

## File uploads
- Uploads are **disabled by default**. Set `MAX_UPLOAD_MB` to a positive integer to allow a single file upload per submission, capped to that size and counted against the FastCGI body budget.
- Uploaded files are stored under `uploads/` inside the `_ftd` chroot (created on demand) using names like `ftd.20240101T000000Z,89abcd12`. The stored path lives in the `file_path` column, and both the stored name and any client-supplied original name are injected into the `form_data` JSON as `_upload_stored_filename` and `_upload_original_filename`. When a write fails, the row keeps `Failed Upload (<status code>)` in `file_path` and in `_upload_stored_filename` so reviewers can see the error.
- The lightweight sample `sample_form.html` remains text-only; use `sample_form_upload.html` for an upload-capable example (with `enctype="multipart/form-data"`).

## Status workflow
Rows start as `new`. The admin UI lets you move them to `in_progress`, `complete`, or `archived`. Completed submissions remain available but collapse into the lower section; archived items stay out of the main dashboard and live in the dedicated Archived view with its own pagination. A bulk "Archive completed" control is available on the Active dashboard to sweep all completed rows into the archived view at once. Each submission also supports an internal reviewer comment field; it can be edited alongside status updates and is rendered in a muted, read-only state when the submission is archived.

## Rate limiting
- Each client IP may submit at most **4 forms per rolling minute**. Exceeding that threshold blocks the IP for 24 hours and returns HTTP 429 with a `Retry-After` hint.
- If a sudden burst of **30 or more distinct IPs** arrives within a minute, the service pauses all submissions for 5 minutes to mitigate abuse and returns HTTP 503 with `Retry-After`.
- Block information is stored in the `submission_blocks` table; expired blocks are cleaned when new requests arrive.

## Files
- `main.go` – FastCGI listener, admin routes, and handlers.
- `schema.sql` – PostgreSQL schema and indexes.
- `templates/` – Admin HTML templates.
- `static/` – Admin CSS assets.
- `sample_form.html` – Example HTML form posting to the FastCGI endpoint.
- `rc.d/ftd` – OpenBSD `rc.d` helper that loads `/etc/ftd.env` and backgrounds the daemon under `rcctl`.

## Security considerations
- Set a strong `SESSION_SECRET` before first run; if you omit it, the server will generate a random per-process key and all sessions will be invalidated on restart. The initial admin account (`admin`) ships in the schema with password `change-me`—the dashboard surfaces a warning until you change it via the built-in password form.
- Admin sessions are signed (with refresh-on-activity to avoid logging out active tabs) and constrained with `Secure`, `HttpOnly`, and `SameSite=Strict` flags by default. Set `SESSION_COOKIE_INSECURE=1` only for non-TLS local testing.
- CSRF tokens are required on admin POSTs (login and status updates) and validated against secure cookies.
- Admin responses set conservative security headers (CSP, frame-ancestors deny, referrer/permissions policies, cache disabling, MIME sniff protection) to reduce injection and clickjacking risk.
- Submission bodies are capped (64KB) and oversized/overlong forms are rejected to slow data flooding.
- Terminate TLS at your front-end web server (nginx/httpd) and forward `X-Forwarded-For` so the app can capture real client IPs.
- Restrict filesystem permissions on the FastCGI socket (`FASTCGI_SOCKET`) so only the web server can connect. The socket is created before chroot/drop-privilege when starting as `root`.
- If the process starts as `root`, it will chroot to the `_ftd` user's home and drop privileges to that account after opening the PostgreSQL socket and FastCGI listener. Create the `_ftd` user and ensure its home directory exists before launching.
- On OpenBSD, pledge(2) is used: startup allows file/socket setup and DNS, then pledges are tightened after connecting to PostgreSQL and preparing listener sockets (with promises adjusted depending on whether a Unix socket or TCP FastCGI port is used).

## Deployment recipes

### OpenBSD httpd (FastCGI over Unix socket)
1. Install dependencies and create the service account:
   ```sh
   pkg_add go postgresql-client
   useradd -m _ftd
   ```
2. Initialize the database schema and admin user (replace credentials as needed):
   ```sh
   createdb ftd
   psql ftd -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"
   psql ftd < schema.sql
   env \
    DATABASE_URL="postgres://<user>:<pass>@<host>:<port>/<db>" \
    go build -o /usr/local/bin/ftd
   ```
   Other environment variables use the defaults noted in the Configuration table; override them if you need a custom socket path or URL prefixes.
3. Create the run directory and permissions for httpd:
   ```sh
   install -d -m 750 -o _ftd -g www /var/www/run
   ```
4. Configure `/etc/httpd.conf`:
   ```
   server "example.com" {
       listen on * port 80

       location "/form" {
           fastcgi socket "/var/www/run/ftd.sock"
       }

       location "/form/admin/*" {
           fastcgi socket "/var/www/run/ftd.sock"
       }
   }
   ```
5. Templates and admin static assets are embedded in the binary and served from the `_ftd` chroot (the `_ftd` user home). You do **not** need to copy the `templates/` or `static/` directories to the filesystem; only place the sample HTML forms in your web root if you want to expose them directly.
6. Install the provided `rc.d` helper and supply environment via `/etc/ftd.env`:
   ```sh
   install -m 755 rc.d/ftd /etc/rc.d/ftd
   cat <<'EOF' > /etc/ftd.env
DATABASE_URL="postgres://<user>:<pass>@<host>:<port>/<db>"
# Optional overrides: FASTCGI_SOCKET, FORM_PATH, ADMIN_PREFIX, SESSION_SECRET, MAX_UPLOAD_MB, etc.
EOF
   ```
7. Enable and start the services (the daemon opens sockets before chrooting/dropping to `_ftd`):
    ```sh
    rcctl enable httpd
    rcctl start httpd
    rcctl enable ftd
    rcctl start ftd
    ```
8. Log into the dashboard at `/form/admin/` with `admin` / `change-me`, then update the password using the on-page form (a warning remains until you do).

### Linux + nginx (FastCGI over Unix socket)
1. Install dependencies and create the service account:
   ```sh
   sudo apt-get update && sudo apt-get install -y golang postgresql-client nginx
   sudo useradd -m -s /usr/sbin/nologin _ftd
   ```
2. Initialize the database schema and admin user:
   ```sh
   createdb ftd
   psql ftd -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"
   psql ftd < schema.sql
   env \
    DATABASE_URL="postgres://<user>:<pass>@<host>:<port>/<db>" \
    go build -o /usr/local/bin/ftd
   ```
   All other environment variables keep their documented defaults unless you override them (e.g., socket path or URL prefixes).
3. Prepare the FastCGI socket path for nginx:
   ```sh
   sudo install -d -m 750 -o _ftd -g www-data /var/www/run
   ```
4. Configure nginx (e.g., `/etc/nginx/sites-available/ftd.conf`):
   ```
   server {
       listen 80;
       server_name example.com;

       location /form {
           include fastcgi_params;
           fastcgi_pass unix:/var/www/run/ftd.sock;
       }

       location /form/admin/ {
           include fastcgi_params;
           fastcgi_pass unix:/var/www/run/ftd.sock;
       }
   }
   ```
   Enable the site and reload nginx:
   ```sh
   sudo ln -s /etc/nginx/sites-available/ftd.conf /etc/nginx/sites-enabled/ftd.conf
   sudo nginx -t
   sudo systemctl reload nginx
   ```
5. Templates and admin static assets are embedded in the binary and served from the `_ftd` chroot (the `_ftd` user home). There is no need to copy `templates/` or `static/` onto the host filesystem; only publish the sample HTML forms if you wish to serve them directly.
6. Run the FastCGI service (with socket creation before chroot/drop-privilege):
   ```sh
   sudo -u _ftd /usr/local/bin/ftd
   ```
7. Sign in at `/form/admin/` as `admin` / `change-me` and rotate the password via the dashboard form; the UI warns while the default remains.

