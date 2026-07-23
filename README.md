# ftd — form To Do

Turn form posts into to-dos. HTML forms post to ftd over FastCGI, submissions
land in an admin inbox, and submitters become customer records you can
organize into lists, tag, and send tracked mailings to. Single Go binary,
PostgreSQL storage, hardened for OpenBSD (chroot, privilege drop, pledge).

## Features

- Accepts arbitrary form fields (stored as JSONB) plus request metadata; optional single file upload.
- Admin dashboard: submission queue with statuses (`new` → `in_progress` → `complete` → `archived`), live updates (new submissions appear without a reload), reviewer comments, per-card hard delete for test/junk entries (also removes a customer record that existed only because of that entry), multi-user accounts, CSRF/secure-cookie/security-header hardening.
- Email deliverability check at intake: DNS MX/A lookup on the submitted address's domain; unresolvable addresses are captured but flagged, the submitting site gets a warning to show the visitor, and flagged entries can be bulk-deleted from the dashboard.
- CRM: submissions auto-create/update customers keyed on email; searchable directory, manual creation, CSV import/export, per-customer activity timeline.
- Interest tags: normalized vocabulary with per-tag provenance — set by hand, declared by forms (hidden `tags` field), or inherited automatically when a customer clicks a tagged mailing's links.
- Mailings: lists + segment tools, HTML campaigns over an SMTP relay, test-send, per-recipient delivery status, open tracking, click tracking, unsubscribe handling, bounce suppression.
- Reply capture: route your Reply-To mailbox into ftd (Postfix LMTP or a pipe helper) and customer replies appear as new to-do submissions linked to their customer record.
- Rate limiting: 8 submissions/minute per IP with a 1-hour block (both env-tunable), global 5-minute pause on bursts of 30+ distinct IPs. Blocked requests get HTTP 429 with `Retry-After`.

## Quick start (any platform, 3 commands)

```sh
make                                          # builds ftd (fetches deps on first run)
createdb ftd && psql ftd < schema.sql         # schema is idempotent; re-run after upgrades
DATABASE_URL="postgres://user:pass@localhost/ftd?sslmode=disable" ./ftd -tcp 9000
```

Point a FastCGI-capable web server at TCP 9000, log in at `/form/admin/` as
`admin` / `change-me`, change the password. Sample forms:
`sample_form.html`, `sample_form_upload.html`. For a real install follow a
platform section below — it's the same three steps plus a service account,
a unix socket, and `/etc/ftd.conf`.

**The one Postgres rule:** load `schema.sql` as the same role ftd connects
as, so that role owns every table and sequence — then permissions can never
bite you. If your admin account differs from the ftd role, prefix the load
with `SET ROLE` (used in the recipes below):

```sh
(echo 'SET ROLE ftd;'; cat schema.sql) | psql ftd
```

## OpenBSD setup (httpd)

```sh
# 1. Packages and service account
pkg_add go postgresql-server postgresql-client
useradd -m _ftd

# 2. Postgres (first time only: init and start the cluster)
su - _postgresql -c "initdb -D /var/postgresql/data -U postgres"
rcctl enable postgresql && rcctl start postgresql

# 3. Role + database + schema (schema owned by the ftd role)
su - _postgresql -c "psql -U postgres -c \"CREATE ROLE ftd LOGIN PASSWORD 'changeme'\""
su - _postgresql -c "createdb -U postgres -O ftd ftd"
(echo 'SET ROLE ftd;'; cat schema.sql) | su - _postgresql -c "psql -U postgres ftd"

# 4. Build and install (binary, /etc/ftd.conf if absent, /etc/rc.d/ftd)
make
doas make install

# 5. Socket directory for httpd
install -d -m 750 -o _ftd -g www /var/www/run
```

`/etc/httpd.conf`:

```
server "example.com" {
    listen on * port 80

    # httpd is chrooted to /var/www: socket paths here are inside the chroot,
    # so /run/ftd.sock is the file ftd creates at /var/www/run/ftd.sock.
    location "/form"         { fastcgi socket "/run/ftd.sock" }
    location "/form/t/*"     { fastcgi socket "/run/ftd.sock" }
    location "/form/admin/*" { fastcgi socket "/run/ftd.sock" }
}
```

Configure and start (`make install` already placed the example config;
every option is listed there, commented out):

```sh
vi /etc/ftd.conf
#   database_url = postgres://ftd:changeme@localhost/ftd?sslmode=disable
#   session_secret = <any long random string>

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

# 2. Role + database + schema (schema owned by the ftd role)
sudo -u postgres psql -c "CREATE ROLE ftd LOGIN PASSWORD 'changeme'"
sudo -u postgres createdb -O ftd ftd
(echo 'SET ROLE ftd;'; cat schema.sql) | sudo -u postgres psql ftd

# 3. Build and install (binary + /etc/ftd.conf if absent)
make
sudo make install

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
blocks only if you move `admin_prefix`/`track_path` elsewhere.)

`/etc/systemd/system/ftd.service`:

```
[Unit]
Description=ftd - form To Do
After=network.target postgresql.service

[Service]
ExecStart=/usr/local/bin/ftd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo vi /etc/ftd.conf
#   database_url = postgres://ftd:changeme@localhost/ftd?sslmode=disable
#   session_secret = <any long random string>
#   socket_group = www-data

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
| `socket_user` / `socket_group` | Owner of the FastCGI socket (user:group, mode 0660), applied before privileges drop so the web server can connect. `www-data` on Debian-style Linux. Unresolvable names → mode 0666 fallback. | `www` / `www` |
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
| `reply_lmtp_user` / `reply_lmtp_group` | Owner of the LMTP socket (user:group, mode 0660) so the MTA's delivery agent — a different user than the web server — can connect. `postfix` on Linux. Unresolvable names → mode 0666 fallback. | `_postfix` / `_postfix` |

Flags: `-tcp <port>` listens on TCP instead of the Unix socket;
`-c <path>` (or `-config <path>`) selects the configuration file; `-deliver`
(with optional `-c`) files one email from stdin and exits. On OpenBSD, pass
daemon flags through rc.d as usual — e.g. an alternate config:
`rcctl set ftd flags -c /etc/ftd2.conf`.

## Using it

**Forms** — point any form's `action` at `/form`. All fields are stored as
submitted. A hidden `redirect` field sends the submitter to a thank-you page
afterward; the target must be a root-relative path or a same-host URL
(cross-host redirects are rejected). With `max_upload_mb` set, one file field
per form is accepted and stored under `uploads/` in the chroot.

### Email deliverability check

When a submission carries an email address, ftd checks (DNS) that the domain
can actually receive mail: an MX record, or failing that an A/AAAA record
(the implicit MX of RFC 5321). A lone `MX 0 .` (RFC 7505 null MX) counts as
"accepts no mail". An unresolvable address **never rejects the submission** —
the data is captured and flagged, and the response tells your site so it can
warn the visitor to double-check their address.

Only an authoritative "domain does not exist" flags an entry; resolver
timeouts or failures never penalize a visitor. Nameservers are read from
`/etc/resolv.conf` once at startup (the daemon chroots afterward); with none
configured the check is disabled and nothing is ever flagged.

**How the warning reaches your site** — the response shape depends on how the
form was submitted, and the contract is stable:

1. *Classic form post with a `redirect` field.* ftd answers
   `303 See Other` as usual, but the redirect URL gains one query parameter:
   `ftd_email=unresolvable`. Existing parameters are preserved. Toast it on
   the thank-you page:

   ```html
   <script>
   if (new URLSearchParams(location.search).get("ftd_email") === "unresolvable") {
     showToast("Heads up — your email address doesn't look deliverable. " +
               "Double-check it if you want a reply.");
   }
   </script>
   ```

2. *fetch/XHR submission.* Send `Accept: application/json` and the
   `202 Accepted` body is machine-readable:

   ```js
   const resp = await fetch("/form", {
     method: "POST",
     body: new FormData(form),
     headers: { "Accept": "application/json" },
   });
   const data = await resp.json();
   // -> { "status": "accepted", "email_unresolvable": true | false }
   if (data.email_unresolvable) {
     showToast("Your email address doesn't look deliverable — please check it.");
   }
   ```

3. *Plain form post, no redirect, no JSON.* The `202 Accepted` text body is
   either `submission received` or
   `submission received (warning: the email domain does not resolve; the
   address may be undeliverable)`.

The warning is advisory: the submission is already stored by the time the
response goes out, so a visitor with a typo'd address still lands in the
inbox (flagged) rather than being bounced.

**Cleaning up flagged entries** — flagged submissions show a red
**bad email** badge in the inbox, and a **Delete bad email (N)** button
appears in the dashboard header whenever any exist. One click (with a
confirmation) deletes all flagged submissions in a single transaction, plus
any customer records that existed *only* because of them — a customer with
any other submission, list membership, or mailing history is left alone.

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

**Direct replies** — every customer page has a Send email composer (the same
WYSIWYG editor as mailings). It sends one personal message through the
configured SMTP relay: no tracking links, no open pixel, no unsubscribe
footer, no bulletproof table wrapper — just `multipart/alternative` with an
auto-generated plain-text version. The send is logged on the activity
timeline (subject + text excerpt, attributed to the logged-in admin), and
the `reply_to` address routes the customer's answer back into the inbox.
Suppression flags don't block it: unsubscribed means "no marketing", not
"no correspondence". Submission cards in the inbox link straight to it via
their ✉ reply chip.

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
/ recent submitters. Compose in the built-in WYSIWYG editor — paragraph
format menu, bold/italic/underline/strike, lists, quotes, links (Ctrl+K,
inline dialog), images, CTA buttons, divider, undo/redo, with active-state
highlighting and an HTML-source toggle for hand editing; plain textarea if
JavaScript is off — upload images to the media library and
insert them (stored in Postgres, served publicly under `track_path/img` so
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
Set `reply_lmtp_user` / `reply_lmtp_group` (default `_postfix` as on OpenBSD;
`postfix` on Linux) and ftd chowns the socket user:group mode 0660 itself
before dropping privileges — a separate owner from the web-facing FastCGI
socket, since the MTA and the web server run as different users.

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

- Set a strong `session_secret` and change the default admin password immediately (the UI nags until you do).
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
- `Makefile` – BSD-style; `make` builds, `make install` installs the binary, config example (never overwriting an existing `/etc/ftd.conf`), and — where `/etc/rc.d` exists — the rc script. `PREFIX`/`DESTDIR` respected.
- `rc.d/ftd` – OpenBSD rc.d script.
