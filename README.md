# ftd

FastCGI form collector and mini-CRM. HTML forms post to it, submissions become
to-do items in an admin dashboard, and submitters become customer records you
can organize into lists and send tracked mailings to. Single Go binary,
PostgreSQL storage, hardened for OpenBSD (chroot, privilege drop, pledge).

## Features

- Accepts arbitrary form fields (stored as JSONB) plus request metadata; optional single file upload.
- Admin dashboard: submission queue with statuses (`new` → `in_progress` → `complete` → `archived`), reviewer comments, multi-user accounts, CSRF/secure-cookie/security-header hardening.
- CRM: submissions auto-create/update customers keyed on email; searchable directory, manual creation, CSV import/export, per-customer activity timeline.
- Mailings: lists + segment tools, HTML campaigns over an SMTP relay, test-send, per-recipient delivery status, open tracking, click tracking, unsubscribe handling, bounce suppression.
- Rate limiting: 4 submissions/minute per IP (24h block), global 5-minute pause on bursts of 30+ distinct IPs.

## Quick start (any platform)

```sh
go mod tidy                     # first build only: fetch deps, write go.sum
go build -o /usr/local/bin/ftd
createdb ftd
psql ftd < schema.sql           # idempotent; re-run it after upgrades
DATABASE_URL="postgres://user:pass@localhost/ftd?sslmode=disable" ftd -tcp 9000
```

Point a FastCGI-capable web server at TCP 9000 (or at the Unix socket, see
below), then log in at `/form/admin/` as `admin` / `change-me` and change the
password. Sample forms: `sample_form.html`, `sample_form_upload.html`.

**Database permissions:** the role in `DATABASE_URL` needs the tables *and*
sequences. Easiest is to run `schema.sql` as that role so it owns everything.
Otherwise, as the owner:

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ftd;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ftd;
```

## OpenBSD setup (httpd)

```sh
# 1. Packages and service account
pkg_add go postgresql-server postgresql-client
useradd -m _ftd

# 2. Database
su - _postgresql -c "createdb ftd"
psql ftd < schema.sql

# 3. Build
go mod tidy
go build -o /usr/local/bin/ftd

# 4. Socket directory for httpd
install -d -m 750 -o _ftd -g www /var/www/run
```

`/etc/httpd.conf`:

```
server "example.com" {
    listen on * port 80

    location "/form"         { fastcgi socket "/var/www/run/ftd.sock" }
    location "/form/t/*"     { fastcgi socket "/var/www/run/ftd.sock" }
    location "/form/admin/*" { fastcgi socket "/var/www/run/ftd.sock" }
}
```

Service environment and startup:

```sh
install -m 755 rc.d/ftd /etc/rc.d/ftd
cat > /etc/ftd.env <<'EOF'
DATABASE_URL="postgres://ftd:pass@localhost/ftd?sslmode=disable"
SESSION_SECRET="put-a-long-random-string-here"
EOF

rcctl enable httpd ftd
rcctl start httpd ftd
```

Log in at `http://example.com/form/admin/` (`admin` / `change-me`) and change
the password. Templates and CSS are embedded in the binary — nothing to copy
into the chroot.

## Linux setup (nginx + systemd)

```sh
# 1. Packages and service account
sudo apt-get install -y golang postgresql nginx
sudo useradd -m -s /usr/sbin/nologin _ftd

# 2. Database
sudo -u postgres createdb -O ftd ftd     # after: sudo -u postgres createuser ftd
psql -U ftd ftd < schema.sql

# 3. Build
go mod tidy
go build -o /usr/local/bin/ftd

# 4. Socket directory for nginx
sudo install -d -m 750 -o _ftd -g www-data /var/www/run
```

`/etc/nginx/sites-available/ftd.conf` (then symlink into `sites-enabled` and reload):

```
server {
    listen 80;
    server_name example.com;

    location /form {
        include fastcgi_params;
        fastcgi_pass unix:/var/www/run/ftd.sock;
    }
}
```

(The `/form` prefix also covers `/form/admin/` and `/form/t/`; add explicit
blocks only if you move `ADMIN_PREFIX`/`TRACK_PATH` elsewhere.)

`/etc/systemd/system/ftd.service`:

```
[Unit]
Description=ftd form collector
After=network.target postgresql.service

[Service]
EnvironmentFile=/etc/ftd.env
ExecStart=/usr/local/bin/ftd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo tee /etc/ftd.env >/dev/null <<'EOF'
DATABASE_URL=postgres://ftd:pass@localhost/ftd?sslmode=disable
SESSION_SECRET=put-a-long-random-string-here
EOF
sudo systemctl enable --now ftd
```

Started as root, ftd opens its sockets, chroots to `_ftd`'s home, and drops
privileges. Log in at `/form/admin/` and change the default password.

## Configuration

All configuration is via environment variables:

| Variable | Description | Default |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL connection string. Add `?sslmode=disable` for a local non-TLS server; use `sslmode=require`/`verify-full` for remote ones. | **Required** |
| `FASTCGI_SOCKET` | Unix socket path for the FastCGI listener (ignored with `-tcp`). | `/var/www/run/ftd.sock` |
| `FORM_PATH` | Submission endpoint path. | `/form` |
| `ADMIN_PREFIX` | Admin dashboard path prefix. | `/form/admin` |
| `TRACK_PATH` | Public tracking endpoints prefix (`/open`, `/c`, `/unsub`). | `/form/t` |
| `SESSION_SECRET` | Signs admin session cookies. Unset = random per-process key (sessions reset on restart). | Generated |
| `SESSION_COOKIE_INSECURE` | Set to drop the `Secure` cookie flag (plain-HTTP dev only). | Not set |
| `MAX_UPLOAD_MB` | Max file upload size in MB; `0` disables uploads. | `0` |
| `SMTP_HOST` / `SMTP_PORT` | SMTP relay for mailings. Sending is disabled until `SMTP_HOST` and `MAIL_FROM` are set. | Not set / `25` |
| `SMTP_USER` / `SMTP_PASS` | Optional SMTP AUTH (PLAIN; STARTTLS used when offered). | Not set |
| `MAIL_FROM` | From address for mailings. | Not set |
| `PUBLIC_BASE_URL` | Public origin (e.g. `https://example.com`) used to build tracking/unsubscribe URLs. Without it mail goes out untracked and without an unsubscribe link. | Not set |

The binary takes one flag: `-tcp <port>` listens on TCP instead of the Unix socket.

## Using it

**Forms** — point any form's `action` at `/form`. All fields are stored as
submitted. A hidden `redirect` field sends the submitter to a thank-you page
afterward; the target must be a root-relative path or a same-host URL
(cross-host redirects are rejected). With `MAX_UPLOAD_MB` set, one file field
per form is accepted and stored under `uploads/` in the chroot.

**Customers** — submissions with a recognizable `email` field auto-create or
update a customer (name/company/phone/address are picked up too; blank fields
never overwrite existing data). Create or complete records by hand on the
Customers page, or bulk-load them with CSV import (needs an `email` column;
rows upsert by email). Each customer page has the editable profile, an
activity timeline (notes/calls/emails/meetings + automatic mailing history),
and their submissions.

**Users** — the schema seeds `admin` / `change-me`. Add your team on the Users
page; the dashboard password form changes the logged-in user's password.

**Lists & mailings** — group customers into lists by email, or bulk-add by tag
match / recent submitters. Compose an HTML draft, pick a list (or all
customers), test-send it to yourself, then send. Mail goes out over the SMTP
relay in the background; the mailing page shows per-recipient delivery, opens,
clicks, and per-link click totals. Every message carries an unsubscribe link
and `List-Unsubscribe` header (when `PUBLIC_BASE_URL` is set); unsubscribed
customers and hard-bounced addresses (SMTP 5xx) are skipped automatically.
Bounces can be cleared from the customer page. Async bounces that arrive at
your relay's return-path mailbox are outside ftd's view — handle those at the
relay.

**Deliverability** — publish SPF, sign with DKIM at the relay (OpenBSD smtpd +
`opensmtpd-filter-dkimsign`, or rspamd), and set rDNS/PTR for the relay IP, or
expect spam-foldering.

## Security notes

- Set a strong `SESSION_SECRET` and change the default admin password immediately (the UI nags until you do).
- Terminate TLS at the web server. Rate limiting keys on the FastCGI peer address (`REMOTE_ADDR`); a client-supplied `X-Forwarded-For` is stored for reference but never trusted.
- Started as root, ftd chroots to `_ftd`'s home and drops privileges after opening its sockets; on OpenBSD it then pledges down to the minimal promises needed to serve.
- Admin POSTs require CSRF tokens; cookies are `Secure`/`HttpOnly`/`SameSite=Strict`; responses carry restrictive security headers.
- Submission bodies are capped at 64KB (+ upload budget) and 200 fields.
- The click-tracking redirect resolves URLs server-side by id and the submission `redirect` field is restricted to same-host targets — neither can be abused as an open redirect.

## Files

- `main.go` – listener, intake, auth, dashboard, customers.
- `crm.go` – users, lists, mailings, SMTP sending, tracking endpoints.
- `schema.sql` – idempotent schema; run it for installs *and* upgrades.
- `templates/`, `static/` – admin UI (embedded into the binary at build time).
- `sample_form.html`, `sample_form_upload.html` – example forms.
- `rc.d/ftd` – OpenBSD rc.d script (loads `/etc/ftd.env`).
