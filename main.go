package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/* static/*
var embeddedFS embed.FS

const (
	defaultAdminUser    = "admin"
	sessionCookieName   = "admin_session"
	csrfCookieName      = "csrf_token"
	loginCSRFCookieName = "login_csrf"
	defaultItemsPerPage = 20
	ipLimitPerMinute    = 4
	ipBlockDuration     = 24 * time.Hour
	burstWindow         = time.Minute
	globalBlockDuration = 5 * time.Minute
	globalDistinctIPs   = 30
	maxSubmissionBytes  = 64 * 1024
	maxFormFields       = 200
	sessionLifetime     = 24 * time.Hour
	sessionRefreshAfter = 6 * time.Hour
	redirectFieldName   = "redirect"
)

var allowedStatuses = map[string]struct{}{
	"new":         {},
	"in_progress": {},
	"complete":    {},
	"archived":    {},
}

type server struct {
	db                    *sql.DB
	sessionKey            []byte
	secureCookie          bool
	uploadLimit           int64
	submitPath            string
	adminPrefix           string
	defaultPasswordActive bool
}

type ctxKey string

const (
	ctxKeyUser ctxKey = "user"
	ctxKeyCSRF ctxKey = "csrf"
)

type Submission struct {
	ID           int64
	SubmittedAt  time.Time
	IP           sql.NullString
	ForwardedFor sql.NullString
	UserAgent    sql.NullString
	Referer      sql.NullString
	Status       string
	FilePath     sql.NullString
	Comment      sql.NullString
	FormData     json.RawMessage
	FormPretty   string
	Fields       []FieldEntry
}

type FieldEntry struct {
	Key   string
	Value string
}

type Customer struct {
	ID              int64
	Email           sql.NullString
	Name            sql.NullString
	Company         sql.NullString
	Phone           sql.NullString
	Address         sql.NullString
	Tags            sql.NullString
	Notes           sql.NullString
	CreatedAt       time.Time
	UpdatedAt       time.Time
	SubmissionCount int
}

type passwordFlash struct {
	Message string
	Kind    string
}

type limitErr struct {
	message    string
	retryAfter time.Duration
	status     int
}

type httpErr struct {
	message string
	status  int
}

func (e *httpErr) Error() string {
	return e.message
}

func (e *limitErr) Error() string {
	return e.message
}

func main() {
	tcpPort := flag.Int("tcp", 0, "optional TCP port for FastCGI instead of a Unix socket")
	flag.Parse()

	useTCP := *tcpPort != 0

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL must be set")
	}

	fastcgiSock := os.Getenv("FASTCGI_SOCKET")
	if fastcgiSock == "" {
		fastcgiSock = "/var/www/run/ftd.sock"
	}

	submitPath := normalizePath(os.Getenv("FORM_PATH"), "/form")
	adminPrefix := normalizePath(os.Getenv("ADMIN_PREFIX"), "/form/admin")

	uploadLimitMB := int64(0)
	if limitStr := os.Getenv("MAX_UPLOAD_MB"); limitStr != "" {
		mb, err := strconv.ParseInt(limitStr, 10, 64)
		if err != nil || mb < 0 {
			log.Fatalf("invalid MAX_UPLOAD_MB: %v", err)
		}
		uploadLimitMB = mb
	}

	allowUnix := !useTCP || strings.Contains(dbURL, "host=/")

	sessionKey, err := deriveSessionKey()
	if err != nil {
		log.Fatalf("failed to derive session key: %v", err)
	}

	secureCookie := os.Getenv("SESSION_COOKIE_INSECURE") == ""

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Keep a single persistent connection so we retain access to the PostgreSQL
	// socket after chrooting.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	if err := ensureSchemaPresent(db); err != nil {
		log.Fatalf("schema verification failed: %v", err)
	}

	if err := ensureAdminPresent(db); err != nil {
		log.Fatalf("admin verification failed: %v", err)
	}

	if err := ensureDefaultPasswordReference(db); err != nil {
		log.Fatalf("default password reference missing: %v", err)
	}

	uploadLimitBytes := uploadLimitMB * 1024 * 1024

	s := &server{
		db:           db,
		sessionKey:   sessionKey,
		secureCookie: secureCookie,
		uploadLimit:  uploadLimitBytes,
		submitPath:   submitPath,
		adminPrefix:  adminPrefix,
	}

	if err := s.refreshDefaultPasswordFlag(context.Background()); err != nil {
		log.Fatalf("failed to check admin password: %v", err)
	}

	listener, desc, err := prepareFastCGIListener(fastcgiSock, *tcpPort)
	if err != nil {
		log.Fatalf("failed to prepare FastCGI listener: %v", err)
	}

	// Chroot and drop privileges while still unpledged: chroot(2) and the setuid
	// family are not covered by any pledge promise, so they must run before the
	// sandbox is applied. All privileged setup (sockets, DB connection) is done
	// by this point.
	if err := dropPrivilegesIfRoot(); err != nil {
		log.Fatalf("privilege drop failed: %v", err)
	}

	// pledge(2) is the final lockdown, applied last and never loosened.
	allowUploads := uploadLimitBytes > 0
	if err := applyPledgeRuntime(allowUnix, allowUploads); err != nil {
		log.Fatalf("runtime pledge failed: %v", err)
	}

	log.Printf("Starting FastCGI listener for submissions and admin on %s", desc)
	if err := s.serveFastCGI(listener); err != nil {
		log.Fatalf("FastCGI server failed: %v", err)
	}
}

func dropPrivilegesIfRoot() error {
	if os.Geteuid() != 0 {
		return nil
	}

	u, err := user.Lookup("_ftd")
	if err != nil {
		return fmt.Errorf("lookup _ftd user: %w", err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse _ftd uid: %w", err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("parse _ftd gid: %w", err)
	}

	if err := syscall.Chroot(u.HomeDir); err != nil {
		return fmt.Errorf("chroot to %s: %w", u.HomeDir, err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir after chroot: %w", err)
	}

	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}

	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}

	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}

	log.Printf("Dropped privileges to _ftd (uid=%d, gid=%d) and chrooted to %s", uid, gid, u.HomeDir)
	return nil
}

func ensureAdminPresent(db *sql.DB) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM admin_users WHERE username=$1", defaultAdminUser).Scan(&count); err != nil {
		return fmt.Errorf("checking admin user: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("admin user '%s' missing; apply schema.sql to create the default account", defaultAdminUser)
	}
	return nil
}

func ensureDefaultPasswordReference(db *sql.DB) error {
	if _, err := loadDefaultPasswordHash(context.Background(), db); err != nil {
		return err
	}

	return nil
}

func loadDefaultPasswordHash(ctx context.Context, db *sql.DB) (string, error) {
	var defaultHash string
	if err := db.QueryRowContext(ctx, "SELECT value FROM admin_defaults WHERE key='admin_default_password_hash'").Scan(&defaultHash); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("default password reference missing; apply schema.sql to seed admin_defaults")
		}
		return "", fmt.Errorf("checking default password reference: %w", err)
	}

	if strings.TrimSpace(defaultHash) == "" {
		return "", fmt.Errorf("default password reference empty; apply schema.sql to seed admin_defaults")
	}

	return defaultHash, nil
}

func (s *server) refreshDefaultPasswordFlag(ctx context.Context) error {
	var hash string
	err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM admin_users WHERE username=$1", defaultAdminUser).Scan(&hash)
	if err == sql.ErrNoRows {
		return fmt.Errorf("admin user '%s' missing; apply schema.sql to create it", defaultAdminUser)
	} else if err != nil {
		return fmt.Errorf("checking admin password: %w", err)
	}

	defaultHash, err := loadDefaultPasswordHash(ctx, s.db)
	if err != nil {
		return err
	}

	s.defaultPasswordActive = hash == defaultHash
	return nil
}

func prepareFastCGIListener(path string, tcpPort int) (net.Listener, string, error) {
	if tcpPort > 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", tcpPort))
		if err != nil {
			return nil, "", fmt.Errorf("listen tcp :%d: %w", tcpPort, err)
		}
		return l, fmt.Sprintf("tcp :%d", tcpPort), nil
	}

	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, "", fmt.Errorf("listen unix: %w", err)
	}
	return l, fmt.Sprintf("unix %s", path), nil
}

func ensureSchemaPresent(db *sql.DB) error {
	required := []string{"submissions", "admin_users", "submission_blocks", "admin_defaults", "customers"}
	missing := make([]string, 0)

	for _, table := range required {
		var found sql.NullString
		if err := db.QueryRow("SELECT to_regclass($1)", "public."+table).Scan(&found); err != nil {
			return fmt.Errorf("checking table %s: %w", table, err)
		}
		if !found.Valid {
			missing = append(missing, table)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("database schema missing tables: %s (apply schema.sql before starting)", strings.Join(missing, ", "))
	}

	return nil
}

func (s *server) serveFastCGI(l net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.submitPath, s.handleSubmission)
	login := s.withAdminHeaders(http.HandlerFunc(s.handleLogin))
	logout := s.withAdminHeaders(http.HandlerFunc(s.handleLogout))
	staticPrefix := s.adminPath("/static/")
	staticFS, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		return fmt.Errorf("static filesystem: %w", err)
	}
	staticHandler := s.withAdminHeaders(http.StripPrefix(staticPrefix, http.FileServer(http.FS(staticFS))))
	archiveCompleted := s.withAdminHeaders(s.requireAuth(http.HandlerFunc(s.handleArchiveCompleted)))
	changePassword := s.withAdminHeaders(s.requireAuth(http.HandlerFunc(s.handleChangePassword)))
	archived := s.withAdminHeaders(s.requireAuth(http.HandlerFunc(s.handleArchived)))
	customers := s.withAdminHeaders(s.requireAuth(http.HandlerFunc(s.handleCustomers)))
	customerView := s.withAdminHeaders(s.requireAuth(http.HandlerFunc(s.handleCustomerView)))
	customerUpdate := s.withAdminHeaders(s.requireAuth(http.HandlerFunc(s.handleCustomerUpdate)))
	dashboard := s.withAdminHeaders(s.requireAuth(http.HandlerFunc(s.handleDashboard)))

	mux.Handle(s.adminPath("/login"), login)
	mux.Handle(s.adminPath("/logout"), logout)
	mux.Handle(staticPrefix, staticHandler)
	mux.Handle(s.adminPath("/archive-completed"), archiveCompleted)
	mux.Handle(s.adminPath("/password"), changePassword)
	mux.Handle(s.adminPath("/archived"), archived)
	mux.Handle(s.adminPath("/customers"), customers)
	mux.Handle(s.adminPath("/customers/view"), customerView)
	mux.Handle(s.adminPath("/customers/update"), customerUpdate)
	mux.Handle(s.adminPath("/"), dashboard)

	return fcgi.Serve(l, mux)
}

func (s *server) handleSubmission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	maxBody := int64(maxSubmissionBytes)
	if s.uploadLimit > 0 {
		maxBody += s.uploadLimit
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	// Real source IP as seen by the front-end (REMOTE_ADDR over FastCGI). This is
	// the trustworthy value we key rate limiting on. The X-Forwarded-For header is
	// client-supplied metadata: it may be legitimate or spoofed, so we record it
	// verbatim alongside the peer address and leave interpretation to the reader.
	realIP := normalizeIP(remoteIP(r))
	forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if lim, err := s.enforceRateLimits(r.Context(), realIP); err != nil {
		log.Printf("rate limit check error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	} else if lim != nil {
		if lim.retryAfter > 0 {
			seconds := int64(math.Ceil(lim.retryAfter.Seconds()))
			if seconds < 0 {
				seconds = 0
			}
			w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		}
		http.Error(w, lim.message, lim.status)
		return
	}

	contentType := r.Header.Get("Content-Type")
	var (
		payload       map[string]interface{}
		savedFile     string
		originalFile  string
		uploadPresent bool
	)

	var redirectTo string
	var err error
	if strings.Contains(contentType, "multipart/form-data") {
		payload, savedFile, originalFile, uploadPresent, redirectTo, err = s.parseMultipartForm(r)
		if err != nil {
			if he, ok := err.(*httpErr); ok {
				http.Error(w, he.message, he.status)
				return
			}
			log.Printf("multipart parse error: %v", err)
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		redirectTo = strings.TrimSpace(r.Form.Get(redirectFieldName))
		r.Form.Del(redirectFieldName)

		if len(r.Form) > maxFormFields {
			http.Error(w, "too many form fields", http.StatusRequestEntityTooLarge)
			return
		}
		payload = convertForm(r.Form)
	}

	if uploadPresent {
		if originalFile != "" {
			payload["_upload_original_filename"] = originalFile
		}
		payload["_upload_stored_filename"] = savedFile
	}

	formJSON, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "unable to marshal form", http.StatusInternalServerError)
		return
	}

	ua := r.UserAgent()
	ref := r.Referer()

	// Associate the submission with a customer record (created or updated from
	// the form's contact fields) so intake feeds the CRM.
	customerID := s.linkCustomer(r.Context(), payload)

	_, err = s.db.Exec(
		`INSERT INTO submissions (ip_address, forwarded_for, user_agent, referer, file_path, form_data, customer_id) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		realIP, nullIfEmpty(forwardedFor), ua, ref, nullIfEmpty(savedFile), formJSON, customerID,
	)
	if err != nil {
		log.Printf("insert submission error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if redirectTo != "" {
		target, err := validateRedirectURL(redirectTo, r.Host)
		if err != nil {
			writeRedirectDeniedPage(w)
			return
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("submission received"))
}

func convertForm(values map[string][]string) map[string]interface{} {
	result := make(map[string]interface{}, len(values))
	for k, vals := range values {
		if len(vals) == 1 {
			result[k] = vals[0]
		} else {
			result[k] = vals
		}
	}
	return result
}

func (s *server) parseMultipartForm(r *http.Request) (map[string]interface{}, string, string, bool, string, error) {
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, "", "", false, "", err
	}

	payload := make(map[string]interface{})
	fieldCount := 0
	var savedFile string
	fileHandled := false
	originalName := ""
	redirectTo := ""

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", "", false, "", err
		}

		name := part.FormName()
		if name == "" {
			continue
		}

		fileName := part.FileName()
		if fileName == "" {
			if fieldCount >= maxFormFields {
				return nil, "", "", false, "", &httpErr{message: "too many form fields", status: http.StatusRequestEntityTooLarge}
			}
			val, err := io.ReadAll(io.LimitReader(part, maxSubmissionBytes))
			if err != nil {
				return nil, "", "", false, "", err
			}
			if name == redirectFieldName {
				if redirectTo == "" {
					redirectTo = strings.TrimSpace(string(val))
				}
				continue
			}
			addTextValue(payload, name, string(val))
			fieldCount++
			continue
		}

		if fileHandled {
			return nil, "", "", false, "", &httpErr{message: "only one file upload allowed", status: http.StatusBadRequest}
		}
		originalName = fileName

		if s.uploadLimit <= 0 {
			_ = discardPart(part)
			savedFile = fmt.Sprintf("Failed Upload (%d)", http.StatusRequestEntityTooLarge)
			fileHandled = true
			continue
		}

		path, err := s.saveUploadedFile(part)
		if err != nil {
			status := http.StatusInternalServerError
			if he, ok := err.(*httpErr); ok {
				status = he.status
			}
			_ = discardPart(part)
			log.Printf("upload failed for %q: %v", part.FileName(), err)
			savedFile = fmt.Sprintf("Failed Upload (%d)", status)
			fileHandled = true
			continue
		}

		savedFile = path
		fileHandled = true
	}

	return payload, savedFile, originalName, fileHandled, redirectTo, nil
}

// validateRedirectURL constrains post-submission redirects to the same host or a
// root-relative path, preventing the endpoint from being abused as an open
// redirect. requestHost is the Host of the incoming submission (r.Host).
func validateRedirectURL(raw, requestHost string) (string, error) {
	// Backslashes are normalized to forward slashes by some browsers, enabling
	// open-redirect bypasses such as "/\evil.com"; reject them outright.
	if strings.ContainsAny(raw, "\\\x00") {
		return "", fmt.Errorf("invalid redirect")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	switch {
	case parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https":
		return "", fmt.Errorf("unsupported scheme")
	case parsed.Scheme != "" || parsed.Host != "":
		// Absolute ("https://host/...") or protocol-relative ("//host/...") URLs
		// must point at the same host that received the submission.
		if parsed.Host == "" || !strings.EqualFold(parsed.Host, requestHost) {
			return "", fmt.Errorf("cross-host redirect not allowed")
		}
		return raw, nil
	default:
		// Relative URL: require a rooted path so the result resolves against the
		// current host rather than a surprising base.
		if !strings.HasPrefix(parsed.Path, "/") {
			return "", fmt.Errorf("relative redirect must be a rooted path")
		}
		return raw, nil
	}
}

// redirectDeniedPage is served when a submission's redirect target fails
// validation (cross-host / open-redirect attempt). It is fully self-contained
// so it renders even with a strict front-end and pulls in no external assets.
const redirectDeniedPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>REDIRECT DENIED</title>
<style>
  :root { color-scheme: dark; }
  html, body { height: 100%; margin: 0; }
  body {
    background: #000;
    color: #2bff5a;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    display: flex; align-items: center; justify-content: center;
    text-shadow: 0 0 6px rgba(43,255,90,0.7);
    overflow: hidden;
  }
  .crt {
    width: min(720px, 92vw);
    padding: 28px 32px;
    border: 1px solid rgba(43,255,90,0.35);
    box-shadow: 0 0 24px rgba(43,255,90,0.25), inset 0 0 60px rgba(43,255,90,0.06);
    background:
      repeating-linear-gradient(0deg, rgba(0,0,0,0) 0 2px, rgba(0,0,0,0.35) 2px 4px);
  }
  pre { margin: 0; white-space: pre; font-size: 13px; line-height: 1.2; }
  .bot { color: #6dffa0; }
  .err { color: #ff4d4d; text-shadow: 0 0 6px rgba(255,77,77,0.7); }
  .dim { color: #1f9c3c; }
  h1 { font-size: 18px; letter-spacing: 3px; margin: 18px 0 6px; }
  .blink { animation: blink 1s steps(2, start) infinite; }
  @keyframes blink { to { visibility: hidden; } }
  .log { margin-top: 16px; font-size: 13px; }
  .log div { opacity: 0; animation: type 0.01s forwards; }
  .log div:nth-child(1){ animation-delay: .2s }
  .log div:nth-child(2){ animation-delay: .6s }
  .log div:nth-child(3){ animation-delay: 1.0s }
  .log div:nth-child(4){ animation-delay: 1.4s }
  @keyframes type { to { opacity: 1; } }
</style>
</head>
<body>
  <main class="crt" role="alert">
    <pre class="bot">      ___________            ___________
     /  _______  \          /  _______  \
    |  | <span class="err">x</span>   <span class="err">x</span> |  |        |  | <span class="err">x</span>   <span class="err">x</span> |  |
    |  |   ___   |  |        |  |   ___   |  |
    |  |  |___|  |  |        |  |  |___|  |  |
     \_|_______|_/          \_|_______|_/
       |  | |  |     [//]      |  | |  |
      _|__|_|__|_             _|__|_|__|_
     |__________|           |__________|</pre>
    <h1 class="err">// REDIRECT DENIED //</h1>
    <pre class="dim">target failed origin policy &mdash; refusing to forward.</pre>
    <div class="log">
      <div>&gt; inspecting redirect target ...</div>
      <div>&gt; cross-origin / malformed destination detected</div>
      <div class="err">&gt; ACCESS REFUSED: open-redirect attempt blocked</div>
      <div class="dim">&gt; your submission was <span class="bot">received and stored</span>. only the redirect was rejected.<span class="blink">_</span></div>
    </div>
  </main>
</body>
</html>`

func writeRedirectDeniedPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, redirectDeniedPage)
}

func addTextValue(payload map[string]interface{}, key, val string) {
	existing, ok := payload[key]
	if !ok {
		payload[key] = val
		return
	}

	switch curr := existing.(type) {
	case []string:
		payload[key] = append(curr, val)
	case string:
		payload[key] = []string{curr, val}
	default:
		payload[key] = val
	}
}

func discardPart(part *multipart.Part) error {
	_, err := io.Copy(io.Discard, part)
	return err
}

func (s *server) saveUploadedFile(part *multipart.Part) (string, error) {
	if s.uploadLimit <= 0 {
		return "", &httpErr{message: "file uploads disabled", status: http.StatusRequestEntityTooLarge}
	}

	if err := os.MkdirAll("uploads", 0750); err != nil {
		return "", err
	}

	now := time.Now().UTC().Format("20060102T150405Z")
	randHex, err := generateRandomHex(4)
	if err != nil {
		return "", err
	}

	filename := fmt.Sprintf("ftd.%s,%s", now, randHex)
	path := filepath.Join("uploads", filename)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()

	written, err := io.Copy(f, io.LimitReader(part, s.uploadLimit+1))
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}

	if written > s.uploadLimit {
		_ = os.Remove(path)
		return "", &httpErr{message: "file too large", status: http.StatusRequestEntityTooLarge}
	}

	return path, nil
}

// remoteIP returns the connecting peer's address (REMOTE_ADDR as forwarded by the
// front-end over FastCGI), stripped of any port. This is the real source IP we
// trust, as opposed to the client-supplied X-Forwarded-For header.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func normalizeIP(ip string) string {
	trimmed := strings.TrimSpace(ip)
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

func (s *server) enforceRateLimits(ctx context.Context, ip string) (*limitErr, error) {
	now := time.Now().UTC()

	if lim, err := s.checkBlock(ctx, "global", "global", now); err != nil || lim != nil {
		return lim, err
	}

	if ip == "" {
		ip = "unknown"
	}

	if lim, err := s.checkBlock(ctx, "ip", ip, now); err != nil || lim != nil {
		return lim, err
	}

	windowStart := now.Add(-burstWindow)
	var recentCount int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM submissions WHERE ip_address=$1 AND submitted_at > $2`, ip, windowStart,
	).Scan(&recentCount); err != nil {
		return nil, err
	}

	if recentCount >= ipLimitPerMinute {
		blockUntil := now.Add(ipBlockDuration)
		if err := s.setBlock(ctx, "ip", ip, blockUntil); err != nil {
			return nil, err
		}
		log.Printf("blocking ip %s for %s after %d submissions in %s", ip, ipBlockDuration, recentCount, burstWindow)
		return &limitErr{
			message:    "rate limit exceeded",
			retryAfter: ipBlockDuration,
			status:     http.StatusTooManyRequests,
		}, nil
	}

	var distinctIPs int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ip_address) FROM submissions WHERE submitted_at > $1`, windowStart,
	).Scan(&distinctIPs); err != nil {
		return nil, err
	}

	if distinctIPs >= globalDistinctIPs {
		blockUntil := now.Add(globalBlockDuration)
		if err := s.setBlock(ctx, "global", "global", blockUntil); err != nil {
			return nil, err
		}
		log.Printf("triggering global submission pause for %s after %d distinct IPs in %s", globalBlockDuration, distinctIPs, burstWindow)
		return &limitErr{
			message:    "submissions temporarily paused",
			retryAfter: globalBlockDuration,
			status:     http.StatusServiceUnavailable,
		}, nil
	}

	return nil, nil
}

func (s *server) checkBlock(ctx context.Context, scope, identifier string, now time.Time) (*limitErr, error) {
	var blockedUntil time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT blocked_until FROM submission_blocks WHERE scope=$1 AND identifier=$2`, scope, identifier,
	).Scan(&blockedUntil)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if blockedUntil.After(now) {
		retry := blockedUntil.Sub(now)
		message := "submissions temporarily paused"
		status := http.StatusServiceUnavailable
		if scope == "ip" {
			message = "rate limit exceeded"
			status = http.StatusTooManyRequests
		}
		return &limitErr{message: message, retryAfter: retry, status: status}, nil
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM submission_blocks WHERE scope=$1 AND identifier=$2`, scope, identifier); err != nil {
		return nil, err
	}

	return nil, nil
}

func (s *server) setBlock(ctx context.Context, scope, identifier string, until time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO submission_blocks (scope, identifier, blocked_until)
         VALUES ($1, $2, $3)
         ON CONFLICT (scope, identifier) DO UPDATE SET blocked_until = EXCLUDED.blocked_until`,
		scope, identifier, until,
	)
	return err
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		token, err := generateRandomHex(32)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		s.setCSRFCookie(w, loginCSRFCookieName, token)
		renderTemplate(w, "templates/login.html", map[string]interface{}{
			"CSRFToken":   token,
			"AdminPrefix": s.adminPrefix,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		if !s.validateCSRFFromCookie(r, loginCSRFCookieName, r.FormValue("csrf_token")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		var hash string
		err := s.db.QueryRow("SELECT password_hash FROM admin_users WHERE username=$1", username).Scan(&hash)
		if err == sql.ErrNoRows {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		} else if err != nil {
			log.Printf("login query error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		s.issueSession(w, username)
		http.Redirect(w, r, s.adminPath("/"), http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     s.adminPath("/"),
		HttpOnly: true,
		Secure:   s.secureCookie,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, s.adminPath("/login"), http.StatusSeeOther)
}

func (s *server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		username, issuedAt, ok := s.validateSession(cookie)
		if err != nil || !ok {
			http.Redirect(w, r, s.adminPath("/login"), http.StatusSeeOther)
			return
		}

		if time.Since(issuedAt) > sessionRefreshAfter {
			s.issueSession(w, username)
		}

		csrfToken := s.csrfToken(username)
		s.setCSRFCookie(w, csrfCookieName, csrfToken)

		ctx := context.WithValue(r.Context(), ctxKeyUser, username)
		ctx = context.WithValue(ctx, ctxKeyCSRF, csrfToken)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func deriveSessionKey() ([]byte, error) {
	if env := os.Getenv("SESSION_SECRET"); env != "" {
		return []byte(env), nil
	}

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	log.Printf("SESSION_SECRET not provided; generated ephemeral key (sessions reset on restart)")
	return key[:], nil
}

func (s *server) issueSession(w http.ResponseWriter, username string) {
	issuedAt := time.Now().UTC()
	value := s.signSession(username, issuedAt)
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     s.adminPath("/"),
		HttpOnly: true,
		Secure:   s.secureCookie,
		SameSite: http.SameSiteStrictMode,
		Expires:  issuedAt.Add(sessionLifetime),
	}
	http.SetCookie(w, cookie)
}

func (s *server) signSession(username string, issuedAt time.Time) string {
	mac := hmac.New(sha256.New, s.sessionKey)
	payload := fmt.Sprintf("%s:%d", username, issuedAt.Unix())
	mac.Write([]byte(payload))
	return fmt.Sprintf("%s:%d:%s", username, issuedAt.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func (s *server) validateSession(cookie *http.Cookie) (string, time.Time, bool) {
	if cookie == nil {
		return "", time.Time{}, false
	}
	parts := strings.SplitN(cookie.Value, ":", 3)
	if len(parts) != 3 {
		return "", time.Time{}, false
	}
	username, ts, sig := parts[0], parts[1], parts[2]
	issuedUnix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	issuedAt := time.Unix(issuedUnix, 0).UTC()

	if time.Since(issuedAt) > sessionLifetime {
		return "", time.Time{}, false
	}

	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write([]byte(fmt.Sprintf("%s:%s", username, ts)))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", time.Time{}, false
	}

	return username, issuedAt, true
}

func (s *server) csrfToken(username string) string {
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write([]byte("csrf:" + username))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *server) setCSRFCookie(w http.ResponseWriter, name, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     s.adminPath("/"),
		HttpOnly: true,
		Secure:   s.secureCookie,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(sessionLifetime),
	})
}

func (s *server) validateCSRFFromCookie(r *http.Request, name, submitted string) bool {
	c, err := r.Cookie(name)
	if err != nil || submitted == "" {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(submitted))
}

func (s *server) setAdminHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
}

func (s *server) withAdminHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setAdminHeaders(w)
		next.ServeHTTP(w, r)
	})
}

func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func mapPasswordFlash(code string) *passwordFlash {
	switch code {
	case "updated":
		return &passwordFlash{Message: "Password updated", Kind: "success"}
	case "mismatch":
		return &passwordFlash{Message: "New passwords do not match", Kind: "error"}
	case "weak":
		return &passwordFlash{Message: "Choose a longer password (min 8 characters)", Kind: "error"}
	case "auth":
		return &passwordFlash{Message: "Current password was incorrect", Kind: "error"}
	case "error":
		return &passwordFlash{Message: "Unable to update password right now", Kind: "error"}
	case "missing":
		return &passwordFlash{Message: "Fill in all password fields", Kind: "error"}
	default:
		return nil
	}
}

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderDashboard(w, r)
	case http.MethodPost:
		s.updateStatus(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) renderDashboard(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	statusFilter := r.URL.Query().Get("status")
	if statusFilter == "archived" {
		// Redirect to the archived view so archived items stay off the main dashboard by default.
		http.Redirect(w, r, s.adminPath("/archived?page="+strconv.Itoa(page)), http.StatusSeeOther)
		return
	}
	if statusFilter != "" && !isValidStatus(statusFilter) {
		http.Error(w, "invalid status filter", http.StatusBadRequest)
		return
	}

	submissions, total, err := s.listSubmissions(r.Context(), statusFilter, page, defaultItemsPerPage, true)
	if err != nil {
		log.Printf("list submissions error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := s.refreshDefaultPasswordFlag(r.Context()); err != nil {
		log.Printf("password flag error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	flash := mapPasswordFlash(r.URL.Query().Get("pw"))

	data := map[string]interface{}{
		"Submissions":     submissions,
		"Page":            page,
		"Total":           total,
		"PageSize":        defaultItemsPerPage,
		"Status":          statusFilter,
		"Path":            s.adminPath("/"),
		"IsArchived":      false,
		"CSRFToken":       r.Context().Value(ctxKeyCSRF),
		"AdminPrefix":     s.adminPrefix,
		"DefaultPassword": s.defaultPasswordActive,
		"PasswordFlash":   flash,
	}

	renderTemplate(w, "templates/dashboard.html", data)
}

func (s *server) handleArchived(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	submissions, total, err := s.listSubmissions(r.Context(), "archived", page, defaultItemsPerPage, false)
	if err != nil {
		log.Printf("list archived submissions error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := s.refreshDefaultPasswordFlag(r.Context()); err != nil {
		log.Printf("password flag error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Submissions":     submissions,
		"Page":            page,
		"Total":           total,
		"PageSize":        defaultItemsPerPage,
		"Status":          "archived",
		"Path":            s.adminPath("/archived"),
		"IsArchived":      true,
		"CSRFToken":       r.Context().Value(ctxKeyCSRF),
		"AdminPrefix":     s.adminPrefix,
		"DefaultPassword": s.defaultPasswordActive,
	}

	renderTemplate(w, "templates/dashboard.html", data)
}

func (s *server) handleArchiveCompleted(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	res, err := s.db.Exec("UPDATE submissions SET status='archived' WHERE status='complete'")
	if err != nil {
		log.Printf("bulk archive error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if n, err := res.RowsAffected(); err == nil {
		log.Printf("archived %d completed submissions", n)
	}

	target := r.Referer()
	if !strings.HasPrefix(target, s.adminPrefix) {
		target = s.adminPath("/")
	}

	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	current := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	redirect := func(code string) {
		http.Redirect(w, r, s.adminPath("/?pw="+code), http.StatusSeeOther)
	}

	if current == "" || newPassword == "" || confirm == "" {
		redirect("missing")
		return
	}

	if newPassword != confirm {
		redirect("mismatch")
		return
	}

	if len(newPassword) < 8 || len(newPassword) > 128 {
		redirect("weak")
		return
	}

	var existingHash string
	if err := s.db.QueryRowContext(r.Context(), "SELECT password_hash FROM admin_users WHERE username=$1", defaultAdminUser).Scan(&existingHash); err != nil {
		log.Printf("password fetch error: %v", err)
		redirect("error")
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(existingHash), []byte(current)) != nil {
		redirect("auth")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("password hash error: %v", err)
		redirect("error")
		return
	}

	if _, err := s.db.ExecContext(r.Context(), "UPDATE admin_users SET password_hash=$1 WHERE username=$2", string(hash), defaultAdminUser); err != nil {
		log.Printf("password update error: %v", err)
		redirect("error")
		return
	}

	if err := s.refreshDefaultPasswordFlag(r.Context()); err != nil {
		log.Printf("password flag refresh error: %v", err)
	}

	s.issueSession(w, defaultAdminUser)
	redirect("updated")
}

func (s *server) updateStatus(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	idStr := r.FormValue("id")
	status := r.FormValue("status")
	comment := strings.TrimSpace(r.FormValue("comment"))
	if status == "" || !isValidStatus(status) {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}

	if len(comment) > 4000 {
		http.Error(w, "comment too long", http.StatusRequestEntityTooLarge)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	if _, err := s.db.Exec("UPDATE submissions SET status=$1, comment=$2 WHERE id=$3", status, nullIfEmpty(comment), id); err != nil {
		log.Printf("update status error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	target := r.Referer()
	if !strings.HasPrefix(target, s.adminPrefix) {
		target = s.adminPath("/")
	}

	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *server) listSubmissions(ctx context.Context, status string, page, pageSize int, excludeArchived bool) ([]Submission, int, error) {
	offset := (page - 1) * pageSize

	args := []interface{}{}
	query := `SELECT id, submitted_at, ip_address, forwarded_for, user_agent, referer, status, file_path, comment, form_data FROM submissions`
	countQuery := `SELECT COUNT(*) FROM submissions`

	whereClauses := []string{}
	if status != "" {
		query += " WHERE status = $1"
		countQuery += " WHERE status = $1"
		args = append(args, status)
	} else if excludeArchived {
		whereClauses = append(whereClauses, "status <> 'archived'")
	}

	if len(whereClauses) > 0 && status == "" {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
		countQuery += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	query += " ORDER BY submitted_at DESC LIMIT $" + strconv.Itoa(len(args)+1) + " OFFSET $" + strconv.Itoa(len(args)+2)
	args = append(args, pageSize, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	submissions := []Submission{}
	for rows.Next() {
		var sub Submission
		if err := rows.Scan(&sub.ID, &sub.SubmittedAt, &sub.IP, &sub.ForwardedFor, &sub.UserAgent, &sub.Referer, &sub.Status, &sub.FilePath, &sub.Comment, &sub.FormData); err != nil {
			return nil, 0, err
		}
		sub.FormPretty = formatJSON(sub.FormData)
		sub.Fields = extractFields(sub.FormData)
		submissions = append(submissions, sub)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int
	if status == "" {
		if err := s.db.QueryRowContext(ctx, countQuery).Scan(&total); err != nil {
			return nil, 0, err
		}
	} else {
		if err := s.db.QueryRowContext(ctx, countQuery, status).Scan(&total); err != nil {
			return nil, 0, err
		}
	}

	return submissions, total, nil
}

// linkCustomer creates or updates a customer record from a submission's contact
// fields and returns its id (NULL when no usable email is present).
func (s *server) linkCustomer(ctx context.Context, payload map[string]interface{}) sql.NullInt64 {
	email, name, company, phone := extractContact(payload)
	if email == "" {
		return sql.NullInt64{}
	}
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO customers (email, name, company, phone)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (email) DO UPDATE SET
		     name = COALESCE(NULLIF(EXCLUDED.name, ''), customers.name),
		     company = COALESCE(NULLIF(EXCLUDED.company, ''), customers.company),
		     phone = COALESCE(NULLIF(EXCLUDED.phone, ''), customers.phone),
		     updated_at = NOW()
		 RETURNING id`,
		email, name, company, phone,
	).Scan(&id)
	if err != nil {
		log.Printf("link customer error: %v", err)
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: id, Valid: true}
}

// extractContact pulls contact details from an arbitrary form payload using
// case-insensitive matching on common field names. Email must look like an
// address (contain "@") and is lower-cased so records dedupe consistently.
func extractContact(payload map[string]interface{}) (email, name, company, phone string) {
	normalized := make(map[string]string, len(payload))
	for k, v := range payload {
		normalized[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(stringifyValue(v))
	}
	pick := func(keys ...string) string {
		for _, want := range keys {
			if val := normalized[want]; val != "" {
				return val
			}
		}
		return ""
	}

	email = strings.ToLower(pick("email", "e-mail", "email_address", "emailaddress", "your_email"))
	if !strings.Contains(email, "@") {
		email = ""
	}
	name = pick("name", "full_name", "fullname", "your_name", "contact_name")
	if name == "" {
		first := pick("first_name", "firstname", "fname")
		last := pick("last_name", "lastname", "lname")
		name = strings.TrimSpace(first + " " + last)
	}
	company = pick("company", "organization", "organisation", "business", "company_name")
	phone = pick("phone", "telephone", "phone_number", "tel", "mobile")
	return email, name, company, phone
}

func (s *server) listCustomers(ctx context.Context, q string, page, pageSize int) ([]Customer, int, error) {
	offset := (page - 1) * pageSize

	where := ""
	filterArgs := []interface{}{}
	if q != "" {
		where = " WHERE (c.email ILIKE $1 OR c.name ILIKE $1 OR c.company ILIKE $1 OR c.phone ILIKE $1)"
		filterArgs = append(filterArgs, "%"+q+"%")
	}

	args := append([]interface{}{}, filterArgs...)
	query := `SELECT c.id, c.email, c.name, c.company, c.phone, c.created_at, c.updated_at,
	    (SELECT COUNT(*) FROM submissions s WHERE s.customer_id = c.id) AS submission_count
	    FROM customers c` + where +
		" ORDER BY c.updated_at DESC LIMIT $" + strconv.Itoa(len(args)+1) + " OFFSET $" + strconv.Itoa(len(args)+2)
	args = append(args, pageSize, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	customers := []Customer{}
	for rows.Next() {
		var c Customer
		if err := rows.Scan(&c.ID, &c.Email, &c.Name, &c.Company, &c.Phone, &c.CreatedAt, &c.UpdatedAt, &c.SubmissionCount); err != nil {
			return nil, 0, err
		}
		customers = append(customers, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM customers c"+where, filterArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	return customers, total, nil
}

// getCustomer loads a customer and its linked submissions. Returns a nil
// customer (no error) when the id does not exist.
func (s *server) getCustomer(ctx context.Context, id int64) (*Customer, []Submission, error) {
	var c Customer
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, company, phone, address, tags, notes, created_at, updated_at
		 FROM customers WHERE id = $1`, id,
	).Scan(&c.ID, &c.Email, &c.Name, &c.Company, &c.Phone, &c.Address, &c.Tags, &c.Notes, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, submitted_at, ip_address, forwarded_for, user_agent, referer, status, file_path, comment, form_data
		 FROM submissions WHERE customer_id = $1 ORDER BY submitted_at DESC LIMIT 200`, id,
	)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	subs := []Submission{}
	for rows.Next() {
		var sub Submission
		if err := rows.Scan(&sub.ID, &sub.SubmittedAt, &sub.IP, &sub.ForwardedFor, &sub.UserAgent, &sub.Referer, &sub.Status, &sub.FilePath, &sub.Comment, &sub.FormData); err != nil {
			return nil, nil, err
		}
		sub.FormPretty = formatJSON(sub.FormData)
		sub.Fields = extractFields(sub.FormData)
		subs = append(subs, sub)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return &c, subs, nil
}

func (s *server) handleCustomers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	customers, total, err := s.listCustomers(r.Context(), q, page, defaultItemsPerPage)
	if err != nil {
		log.Printf("list customers error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Customers":   customers,
		"Query":       q,
		"Page":        page,
		"Total":       total,
		"PageSize":    defaultItemsPerPage,
		"Path":        s.adminPath("/customers"),
		"CSRFToken":   r.Context().Value(ctxKeyCSRF),
		"AdminPrefix": s.adminPrefix,
	}
	renderTemplate(w, "templates/customers.html", data)
}

func (s *server) handleCustomerView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	customer, subs, err := s.getCustomer(r.Context(), id)
	if err != nil {
		log.Printf("get customer error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if customer == nil {
		http.Error(w, "customer not found", http.StatusNotFound)
		return
	}

	data := map[string]interface{}{
		"Customer":    customer,
		"Submissions": subs,
		"Flash":       mapCustomerFlash(r.URL.Query().Get("saved")),
		"CSRFToken":   r.Context().Value(ctxKeyCSRF),
		"AdminPrefix": s.adminPrefix,
	}
	renderTemplate(w, "templates/customer.html", data)
}

func (s *server) handleCustomerUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email != "" && !strings.Contains(email, "@") {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	company := strings.TrimSpace(r.FormValue("company"))
	phone := strings.TrimSpace(r.FormValue("phone"))
	address := strings.TrimSpace(r.FormValue("address"))
	tags := strings.TrimSpace(r.FormValue("tags"))
	notes := strings.TrimSpace(r.FormValue("notes"))

	for _, field := range []string{name, company, phone, tags} {
		if len(field) > 500 {
			http.Error(w, "field too long", http.StatusRequestEntityTooLarge)
			return
		}
	}
	if len(address) > 2000 || len(notes) > 8000 {
		http.Error(w, "field too long", http.StatusRequestEntityTooLarge)
		return
	}

	viewURL := s.adminPath("/customers/view?id=" + strconv.FormatInt(id, 10))
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE customers SET email=$1, name=$2, company=$3, phone=$4, address=$5, tags=$6, notes=$7, updated_at=NOW() WHERE id=$8`,
		nullIfEmpty(email), nullIfEmpty(name), nullIfEmpty(company), nullIfEmpty(phone), nullIfEmpty(address), nullIfEmpty(tags), nullIfEmpty(notes), id,
	); err != nil {
		// A duplicate email trips the unique constraint; report it rather than 500.
		log.Printf("update customer error: %v", err)
		http.Redirect(w, r, viewURL+"&saved=err", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, viewURL+"&saved=1", http.StatusSeeOther)
}

func mapCustomerFlash(code string) *passwordFlash {
	switch code {
	case "1":
		return &passwordFlash{Message: "Customer saved.", Kind: "success"}
	case "err":
		return &passwordFlash{Message: "Could not save — is that email already used by another customer?", Kind: "error"}
	default:
		return nil
	}
}

func formatJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

func extractFields(raw json.RawMessage) []FieldEntry {
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fields := make([]FieldEntry, 0, len(keys))
	for _, k := range keys {
		fields = append(fields, FieldEntry{Key: k, Value: stringifyValue(data[k])})
	}
	return fields
}

func stringifyValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	case nil:
		return ""
	case []interface{}, map[string]interface{}:
		b, err := json.MarshalIndent(val, "", "  ")
		if err != nil {
			return fmt.Sprintf("%v", val)
		}
		return string(b)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func isValidStatus(status string) bool {
	_, ok := allowedStatuses[status]
	return ok
}

func nullIfEmpty(val string) interface{} {
	if val == "" {
		return nil
	}
	return val
}

func normalizePath(val, def string) string {
	if val == "" {
		val = def
	}
	if !strings.HasPrefix(val, "/") {
		val = "/" + val
	}
	val = strings.TrimRight(val, "/")
	if val == "" {
		val = "/"
	}
	return val
}

func (s *server) adminPath(suffix string) string {
	if suffix == "/" {
		return s.adminPrefix + "/"
	}
	if strings.HasPrefix(suffix, "/") {
		return s.adminPrefix + suffix
	}
	return s.adminPrefix + "/" + suffix
}

func renderTemplate(w http.ResponseWriter, path string, data interface{}) {
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"multiply": func(a, b int) int { return a * b },
	}

	// Name the template after the file's base name so that ParseFS associates the
	// parsed content with this template (ParseFS names templates by base name).
	// Otherwise Execute would run an empty template and fail.
	name := filepath.Base(path)
	tpl, err := template.New(name).Funcs(funcMap).ParseFS(embeddedFS, path)
	if err != nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.Execute(w, data); err != nil {
		log.Printf("template execute error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
