package main

import (
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
	ID          int64
	SubmittedAt time.Time
	IP          sql.NullString
	UserAgent   sql.NullString
	Referer     sql.NullString
	Status      string
	FilePath    sql.NullString
	Comment     sql.NullString
	FormData    json.RawMessage
	FormPretty  string
	Fields      []FieldEntry
}

type FieldEntry struct {
	Key   string
	Value string
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

	if err := applyPledgeInitial(allowUnix); err != nil {
		log.Fatalf("initial pledge failed: %v", err)
	}

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

	if err := applyPledgePostDB(allowUnix); err != nil {
		log.Fatalf("post-DB pledge failed: %v", err)
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

	allowUploads := uploadLimitBytes > 0
	if err := applyPledgeRuntime(allowUnix, allowUploads); err != nil {
		log.Fatalf("runtime pledge failed: %v", err)
	}

	if err := dropPrivilegesIfRoot(); err != nil {
		log.Fatalf("privilege drop failed: %v", err)
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
	required := []string{"submissions", "admin_users", "submission_blocks", "admin_defaults"}
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
	dashboard := s.withAdminHeaders(s.requireAuth(http.HandlerFunc(s.handleDashboard)))

	mux.Handle(s.adminPath("/login"), login)
	mux.Handle(s.adminPath("/logout"), logout)
	mux.Handle(staticPrefix, staticHandler)
	mux.Handle(s.adminPath("/archive-completed"), archiveCompleted)
	mux.Handle(s.adminPath("/password"), changePassword)
	mux.Handle(s.adminPath("/archived"), archived)
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

	ip := normalizeIP(clientIP(r))
	if lim, err := s.enforceRateLimits(r.Context(), ip); err != nil {
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

	_, err = s.db.Exec(
		`INSERT INTO submissions (ip_address, user_agent, referer, file_path, form_data) VALUES ($1, $2, $3, $4, $5)`,
		ip, ua, ref, nullIfEmpty(savedFile), formJSON,
	)
	if err != nil {
		log.Printf("insert submission error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if redirectTo != "" {
		target, err := validateRedirectURL(redirectTo)
		if err != nil {
			http.Error(w, "invalid redirect", http.StatusBadRequest)
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

func validateRedirectURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme")
	}

	return raw, nil
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

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
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
	query := `SELECT id, submitted_at, ip_address, user_agent, referer, status, file_path, comment, form_data FROM submissions`
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
		if err := rows.Scan(&sub.ID, &sub.SubmittedAt, &sub.IP, &sub.UserAgent, &sub.Referer, &sub.Status, &sub.FilePath, &sub.Comment, &sub.FormData); err != nil {
			return nil, 0, err
		}
		sub.FormPretty = formatJSON(sub.FormData)
		sub.Fields = extractFields(sub.FormData)
		submissions = append(submissions, sub)
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

func formatJSON(raw json.RawMessage) string {
	var buf strings.Builder
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

	tpl, err := template.New("page").Funcs(funcMap).ParseFS(embeddedFS, path)
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
