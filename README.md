# ftd

FastCGI form collector and mini-CRM. HTML forms post to it, submissions become
to-do items in an admin dashboard, and submitters become customer records you
can organize into lists and send tracked mailings to. Single Go binary,
PostgreSQL storage, hardened for OpenBSD (chroot, privilege drop, pledge).

## Features

- Accepts arbitrary form fields (stored as JSONB) plus request metadata; optional single file upload.
- Admin dashboard: submission queue with statuses (`new` → `in_progress` → `complete` → `archived`), reviewer comments, multi-user accounts, CSRF/secure-cookie/security-header hardening.
- CRM: submissions auto-create/update customers keyed on email; searchable directory, manual creation, CSV import/export, per-customer activity timeline.
- Interest tags: normalized vocabulary with per-tag provenance — set by hand, declared by forms (hidden `tags` field), or inherited automatically when a customer clicks a tagged mailing's links.
- Mailings: lists + segment tools, HTML campaigns over an SMTP relay, test-send, per-recipient delivery status, open tracking, click tracking, unsubscribe handling, bounce suppression.
- Reply capture: route your Reply-To mailbox into ftd (Postfix LMTP or a pipe helper) and customer replies appear as new to-do submissions linked to their customer record.
- Rate limiting: 8 submissions/minute per IP with a 1-hour block (both env-tunable), global 5-minute pause on bursts of 30+ distinct IPs. Blocked requests get HTTP 429 with `Retry-After`.

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

(Inline environment variables work for one-off runs like this; for a real
install put the settings in `/etc/ftd.conf` — see Configuration.)

**Database permissions:** the role in `database_url` needs the tables *and*
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

Configuration and startup (the daemon reads `/etc/ftd.conf` itself; see the
Configuration section):

```sh
install -m 755 rc.d/ftd /etc/rc.d/ftd
install -m 640 ftd.conf /etc/ftd.conf
vi /etc/ftd.conf      # uncomment and set database_url and session_secret

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
ExecStart=/usr/local/bin/ftd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo install -m 640 ftd.conf /etc/ftd.conf
sudo vi /etc/ftd.conf     # uncomment and set database_url and session_secret
sudo systemctl enable --now ftd
```

Started as root, ftd opens its sockets, chroots to `_ftd`'s home, and drops
privileges. Log in at `/form/admin/` and change the default password.

## Configuration

ftd configures itself from `/etc/ftd.conf` (postfix-style, lowercase
`key = value`, `#` comments; override the path with `-config`). The repo ships
an `ftd.conf` example listing every option, commented out — install it and
uncomment what you need. Environment variables with the same name in uppercase
(`database_url` → `DATABASE_URL`) override the file, which is handy for
development and one-off runs.

| Key | Description | Default |
| --- | --- | --- |
| `database_url` | PostgreSQL connection string. Add `?sslmode=disable` for a local non-TLS server; use `sslmode=require`/`verify-full` for remote ones. | **Required** |
| `fastcgi_socket` | Unix socket path for the FastCGI listener (ignored with `-tcp`). | `/var/www/run/ftd.sock` |
| `form_path` | Submission endpoint path. | `/form` |
| `admin_prefix` | Admin dashboard path prefix. | `/form/admin` |
| `track_path` | Public tracking endpoints prefix (`/open`, `/c`, `/unsub`, `/img`). | `/form/t` |
| `session_secret` | Signs admin session cookies. Unset = random per-process key (sessions reset on restart). | Generated |
| `session_cookie_insecure` | Set to drop the `Secure` cookie flag (plain-HTTP dev only). | Not set |
| `max_upload_mb` | Max file upload size in MB; `0` disables uploads. | `0` |
| `rate_limit_per_min` | Submissions allowed per IP per rolling minute before a block. Size it above the number of forms a legitimate visitor might submit in one sitting. | `8` |
| `rate_block_minutes` | How long an IP that exceeds the limit is blocked. | `60` |
| `smtp_host` / `smtp_port` | SMTP relay for mailings. Sending is disabled until `smtp_host` and `mail_from` are set. | Not set / `25` |
| `smtp_user` / `smtp_pass` | Optional SMTP AUTH (PLAIN; STARTTLS used when offered). | Not set |
| `mail_from` | From address for mailings. | Not set |
| `public_base_url` | Public origin (e.g. `https://example.com`) used to build tracking/unsubscribe URLs. Without it mail goes out untracked and without an unsubscribe link. | Not set |
| `reply_to` | Reply-To address on outgoing mailings — point it at the mailbox your MTA routes into ftd (below) so replies come back as to-dos. | Not set |
| `reply_lmtp_socket` | Unix socket path for the inbound-reply LMTP listener; unset disables it. | Not set |

Flags: `-tcp <port>` listens on TCP instead of the Unix socket;
`-c <path>` (or `-config <path>`) selects the configuration file; `-deliver`
(with optional `-c`) files one email from stdin and exits. On OpenBSD, pass
daemon flags through rc.d as usual — e.g. an alternate config:
`rcctl set ftd flags -c /etc/ftd2.conf`.

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
rows upsert by email). The exported `unsubscribed`/`bounced` columns are
honored on import: `true` applies the suppression, `false` or blank leaves
existing state untouched — a re-import can never make a suppressed address
mailable again. Each customer page has the editable profile, an
activity timeline (notes/calls/emails/meetings + automatic mailing history),
and their submissions.

**Tags** — the interest system. Tags live in a normalized vocabulary
(lowercase; manage it on the Tags page) and attach to customers with a
recorded source, shown as colored chips: **manual** (set by hand on the
customer page), **form** (a submitted form carried a — usually hidden —
`tags` field, e.g. `<input type="hidden" name="tags" value="widgets,pricing">`,
so each form self-classifies its submitters), **click** (the customer clicked
a link in a mailing that had tags — interest declared by behavior), and
**import** (CSV). Filter the directory by tag, click a tag on the Tags page to
see its customers, and use the list segment tool to turn a tag into a mailing
audience. Each customer page also lists exactly which mailing links they
clicked, when, and how often.

**Users** — the schema seeds `admin` / `change-me`. Add your team on the Users
page; the dashboard password form changes the logged-in user's password.

**Lists & mailings** — group customers into lists by email, or bulk-add by tag
/ recent submitters. Compose in the built-in WYSIWYG editor (bold/lists/
headings/links/CTA buttons, with an HTML-source toggle for hand editing —
plain textarea if JavaScript is off), upload images to the media library and
insert them (stored in Postgres, served publicly under `TRACK_PATH/img` so
mail clients can fetch them), and check layout in the live preview pane, which
renders the saved draft in a mail-client-style frame and marks where the
unsubscribe link and tracking pixel land. Pick a list (or all customers),
optionally tag the mailing (clickers inherit its tags), test-send it to
yourself, then send. At send time the composed content is wrapped in a
bulletproof table layout (MSO conditionals, 600px centered presentation
table, inlined fonts) so it renders correctly in Outlook and friends — the
preview shows the exact same skeleton. Compose only the content; if you paste
a full `<html>` document instead, it is sent verbatim as the power-user
escape hatch. Messages go out as `multipart/alternative` with an
auto-generated plain-text version (links become `text (url)`, lists become
bullets), so text-only mail clients get clean text instead of raw HTML.
Interrupted deliveries (crash/restart mid-send) resume automatically on
startup: never-attempted recipients are mailed, while recipients caught
mid-delivery are marked failed with an "interrupted" note instead of being
auto-resent — SMTP may already have accepted those messages, and ftd never
risks automatic duplicates. Redeliver them deliberately with the "Retry
failed recipients" button. Mail goes out over the SMTP
relay in the background; the mailing page shows per-recipient delivery, opens,
clicks, and per-link click totals. Every message carries an unsubscribe link
and `List-Unsubscribe` header (when `public_base_url` is set); unsubscribed
customers and hard-bounced addresses (SMTP 5xx) are skipped automatically.
Bounces can be cleared from the customer page. Async bounces that arrive at
your relay's return-path mailbox are outside ftd's view — handle those at the
relay.

**Replies become to-dos** — when a customer answers a mailing, the reply can
land straight in the submission inbox as a new to-do card, linked to their
customer record (the text body, decoded subject, and sender are extracted;
bounces and auto-responders are discarded). Set `reply_to` to the mailbox
address, then route that address into ftd with Postfix either way:

*LMTP (recommended — Postfix delivers into the running daemon):*

```
# /etc/ftd.conf
reply_to = sales@example.com
reply_lmtp_socket = /var/www/run/ftd-lmtp.sock
```

```
# /etc/postfix/main.cf
transport_maps = hash:/etc/postfix/transport
# /etc/postfix/transport
sales@example.com  lmtp:unix:/var/www/run/ftd-lmtp.sock
```

Run `postmap /etc/postfix/transport && postfix reload`. If your `master.cf`
runs the `lmtp` agent chrooted (Debian default), either set its chroot column
to `n` or place the socket under `/var/spool/postfix/` and adjust the path.
ftd creates the socket mode 0660 — make it connectable by Postfix (e.g.
`chgrp postfix` on the socket or run the socket directory group-shared).

*Pipe helper (simplest — Postfix invokes ftd per message):*

```
# /etc/aliases
sales: "|/usr/local/bin/ftd -deliver"
```

Run `newaliases`. The helper reads one message on stdin, loads
`/etc/ftd.conf` itself (override the path with `-config`), files the reply,
and exits with sysexits codes so transient database problems are requeued
rather than bounced.

**Deliverability** — publish SPF, sign with DKIM at the relay (setups below),
and set rDNS/PTR for the relay IP, or expect spam-foldering.

## DKIM signing at the relay

ftd hands mail to your local MTA (`smtp_host = 127.0.0.1`); the MTA signs it on
the way out. Either recipe below ends with the same DNS step.

### OpenBSD: OpenSMTPD + filter-dkimsign

```sh
pkg_add opensmtpd-filter-dkimsign

# 2048-bit RSA key, readable only by the filter user
install -d -o _dkimsign -g _dkimsign -m 700 /etc/mail/dkim
openssl genrsa -out /etc/mail/dkim/example.com.key 2048
chown _dkimsign:_dkimsign /etc/mail/dkim/example.com.key
chmod 400 /etc/mail/dkim/example.com.key
```

`/etc/mail/smtpd.conf` — add the filter and attach it to the listener ftd
submits on (pick any selector name; the year works well):

```
filter "dkimsign" proc-exec "filter-dkimsign -d example.com -s 2026 \
    -k /etc/mail/dkim/example.com.key" user _dkimsign group _dkimsign

listen on socket filter "dkimsign"
listen on lo0 filter "dkimsign"

action "outbound" relay
match from local for any action "outbound"
```

```sh
rcctl restart smtpd
```

### Postfix + OpenDKIM (Debian/Ubuntu flavored)

```sh
sudo apt-get install -y opendkim opendkim-tools
sudo mkdir -p /etc/opendkim/keys/example.com
sudo opendkim-genkey -D /etc/opendkim/keys/example.com -d example.com -s 2026
sudo chown -R opendkim:opendkim /etc/opendkim/keys
```

Append to `/etc/opendkim.conf` (simple single-domain setup):

```
Domain    example.com
Selector  2026
KeyFile   /etc/opendkim/keys/example.com/2026.private
Socket    inet:8891@127.0.0.1
```

Append to `/etc/postfix/main.cf`:

```
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = $smtpd_milters
milter_default_action = accept
```

```sh
sudo systemctl restart opendkim postfix
```

### DNS record (both setups)

Publish the public key as a TXT record at `2026._domainkey.example.com`:

```
2026._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=<base64 public key>"
```

With OpenDKIM the ready-made record is in
`/etc/opendkim/keys/example.com/2026.txt`. For the OpenSMTPD key, print the
`p=` value with:

```sh
openssl rsa -in /etc/mail/dkim/example.com.key -pubout -outform der | openssl base64 -A
```

Verify by mailing a Gmail address and checking "show original" for
`DKIM: PASS`, or use a tester like mail-tester.com. When you rotate keys,
pick a new selector, publish the new TXT record, then switch the signer.

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
- `inbound.go` – reply ingestion: LMTP listener and the `-deliver` stdin helper.
- `schema.sql` – idempotent schema; run it for installs *and* upgrades.
- `templates/`, `static/` – admin UI (embedded into the binary at build time).
- `sample_form.html`, `sample_form_upload.html` – example forms.
- `ftd.conf` – example configuration listing every option, commented out; install to `/etc/ftd.conf`.
- `rc.d/ftd` – OpenBSD rc.d script.
