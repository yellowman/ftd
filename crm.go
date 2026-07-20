package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log"
	"mime"
	"mime/quotedprintable"
	"net/http"
	"net/smtp"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- Users -----------------------------------------------------------------

type User struct {
	Username  string
	CreatedAt time.Time
}

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)

func (s *server) handleUsers(w http.ResponseWriter, r *http.Request) {
	self, _ := r.Context().Value(ctxKeyUser).(string)

	switch r.Method {
	case http.MethodGet:
		s.renderUsers(w, r, nil)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		switch r.FormValue("action") {
		case "add":
			username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
			password := r.FormValue("password")
			confirm := r.FormValue("confirm")
			switch {
			case !usernameRe.MatchString(username):
				s.renderUsers(w, r, &passwordFlash{Message: "Usernames are 1-32 chars: lowercase letters, digits, _ . -", Kind: "error"})
				return
			case len(password) < 8 || len(password) > 128:
				s.renderUsers(w, r, &passwordFlash{Message: "Choose a longer password (min 8 characters)", Kind: "error"})
				return
			case password != confirm:
				s.renderUsers(w, r, &passwordFlash{Message: "Passwords do not match", Kind: "error"})
				return
			}
			hash, err := hashPassword(password)
			if err != nil {
				log.Printf("hash password error: %v", err)
				s.renderUsers(w, r, &passwordFlash{Message: "Unable to add user right now", Kind: "error"})
				return
			}
			if _, err := s.db.ExecContext(r.Context(),
				`INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)`, username, hash); err != nil {
				s.renderUsers(w, r, &passwordFlash{Message: "Could not add user — name already taken?", Kind: "error"})
				return
			}
			s.renderUsers(w, r, &passwordFlash{Message: "User " + username + " added.", Kind: "success"})
		case "delete":
			username := r.FormValue("username")
			if username == self {
				s.renderUsers(w, r, &passwordFlash{Message: "You cannot delete your own account.", Kind: "error"})
				return
			}
			if _, err := s.db.ExecContext(r.Context(),
				`DELETE FROM admin_users WHERE username=$1`, username); err != nil {
				log.Printf("delete user error: %v", err)
				s.renderUsers(w, r, &passwordFlash{Message: "Unable to delete user right now", Kind: "error"})
				return
			}
			s.renderUsers(w, r, &passwordFlash{Message: "User " + username + " deleted.", Kind: "success"})
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) renderUsers(w http.ResponseWriter, r *http.Request, flash *passwordFlash) {
	rows, err := s.db.QueryContext(r.Context(), `SELECT username, created_at FROM admin_users ORDER BY username`)
	if err != nil {
		log.Printf("list users error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.CreatedAt); err != nil {
			log.Printf("scan user error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		log.Printf("list users error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	self, _ := r.Context().Value(ctxKeyUser).(string)
	renderTemplate(w, "templates/users.html", map[string]interface{}{
		"Users":       users,
		"Self":        self,
		"Flash":       flash,
		"CSRFToken":   r.Context().Value(ctxKeyCSRF),
		"AdminPrefix": s.adminPrefix,
	})
}

// ---- Lists -----------------------------------------------------------------

type List struct {
	ID          int64
	Name        string
	Description sql.NullString
	CreatedAt   time.Time
	MemberCount int
}

type ListMember struct {
	CustomerID int64
	Email      sql.NullString
	Name       sql.NullString
	Company    sql.NullString
	AddedAt    time.Time
	Unsubbed   bool
}

func (s *server) handleLists(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderLists(w, r, nil)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		switch r.FormValue("action") {
		case "create":
			name := strings.TrimSpace(r.FormValue("name"))
			desc := strings.TrimSpace(r.FormValue("description"))
			if name == "" || len(name) > 200 || len(desc) > 1000 {
				s.renderLists(w, r, &passwordFlash{Message: "List name is required (max 200 chars).", Kind: "error"})
				return
			}
			if _, err := s.db.ExecContext(r.Context(),
				`INSERT INTO lists (name, description) VALUES ($1, $2)`, name, nullIfEmpty(desc)); err != nil {
				s.renderLists(w, r, &passwordFlash{Message: "Could not create list — name already taken?", Kind: "error"})
				return
			}
			s.renderLists(w, r, &passwordFlash{Message: "List created.", Kind: "success"})
		case "delete":
			id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
			if err != nil {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}
			if _, err := s.db.ExecContext(r.Context(), `DELETE FROM lists WHERE id=$1`, id); err != nil {
				log.Printf("delete list error: %v", err)
				s.renderLists(w, r, &passwordFlash{Message: "Unable to delete list right now", Kind: "error"})
				return
			}
			s.renderLists(w, r, &passwordFlash{Message: "List deleted.", Kind: "success"})
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) renderLists(w http.ResponseWriter, r *http.Request, flash *passwordFlash) {
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT l.id, l.name, l.description, l.created_at,
		    (SELECT COUNT(*) FROM list_members lm WHERE lm.list_id = l.id)
		 FROM lists l ORDER BY l.name`)
	if err != nil {
		log.Printf("list lists error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	lists := []List{}
	for rows.Next() {
		var l List
		if err := rows.Scan(&l.ID, &l.Name, &l.Description, &l.CreatedAt, &l.MemberCount); err != nil {
			log.Printf("scan list error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		lists = append(lists, l)
	}
	if err := rows.Err(); err != nil {
		log.Printf("list lists error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "templates/lists.html", map[string]interface{}{
		"Lists":       lists,
		"Flash":       flash,
		"CSRFToken":   r.Context().Value(ctxKeyCSRF),
		"AdminPrefix": s.adminPrefix,
	})
}

func (s *server) handleListView(w http.ResponseWriter, r *http.Request) {
	var (
		id   int64
		err  error
		msgs *passwordFlash
	)

	switch r.Method {
	case http.MethodGet:
		id, err = strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		id, err = strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err == nil {
			msgs = s.applyListMemberAction(r, id)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var list List
	err = s.db.QueryRowContext(r.Context(),
		`SELECT id, name, description, created_at FROM lists WHERE id=$1`, id,
	).Scan(&list.ID, &list.Name, &list.Description, &list.CreatedAt)
	if err == sql.ErrNoRows {
		http.Error(w, "list not found", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("get list error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	rows, err := s.db.QueryContext(r.Context(),
		`SELECT c.id, c.email, c.name, c.company, lm.added_at, c.unsubscribed_at IS NOT NULL
		 FROM list_members lm JOIN customers c ON c.id = lm.customer_id
		 WHERE lm.list_id = $1 ORDER BY c.email`, id)
	if err != nil {
		log.Printf("list members error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	members := []ListMember{}
	for rows.Next() {
		var m ListMember
		if err := rows.Scan(&m.CustomerID, &m.Email, &m.Name, &m.Company, &m.AddedAt, &m.Unsubbed); err != nil {
			log.Printf("scan member error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		log.Printf("list members error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "templates/list.html", map[string]interface{}{
		"List":        list,
		"Members":     members,
		"Flash":       msgs,
		"CSRFToken":   r.Context().Value(ctxKeyCSRF),
		"AdminPrefix": s.adminPrefix,
	})
}

func (s *server) applyListMemberAction(r *http.Request, listID int64) *passwordFlash {
	switch r.FormValue("action") {
	case "add":
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		if !strings.Contains(email, "@") {
			return &passwordFlash{Message: "Enter a customer email address.", Kind: "error"}
		}
		var customerID int64
		err := s.db.QueryRowContext(r.Context(), `SELECT id FROM customers WHERE email=$1`, email).Scan(&customerID)
		if err == sql.ErrNoRows {
			return &passwordFlash{Message: "No customer with that email. Create the customer first (they are created automatically from submissions).", Kind: "error"}
		} else if err != nil {
			log.Printf("member lookup error: %v", err)
			return &passwordFlash{Message: "Unable to add member right now", Kind: "error"}
		}
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT INTO list_members (list_id, customer_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			listID, customerID); err != nil {
			log.Printf("member add error: %v", err)
			return &passwordFlash{Message: "Unable to add member right now", Kind: "error"}
		}
		return &passwordFlash{Message: email + " added to list.", Kind: "success"}
	case "remove":
		customerID, err := strconv.ParseInt(r.FormValue("customer_id"), 10, 64)
		if err != nil {
			return &passwordFlash{Message: "Invalid customer.", Kind: "error"}
		}
		if _, err := s.db.ExecContext(r.Context(),
			`DELETE FROM list_members WHERE list_id=$1 AND customer_id=$2`, listID, customerID); err != nil {
			log.Printf("member remove error: %v", err)
			return &passwordFlash{Message: "Unable to remove member right now", Kind: "error"}
		}
		return &passwordFlash{Message: "Member removed.", Kind: "success"}
	}
	return &passwordFlash{Message: "Unknown action.", Kind: "error"}
}

// ---- Mailings --------------------------------------------------------------

type Mailing struct {
	ID        int64
	Subject   string
	BodyHTML  string
	ListID    sql.NullInt64
	ListName  sql.NullString
	Status    string
	CreatedBy sql.NullString
	CreatedAt time.Time
	SentAt    sql.NullTime
	Total     int
	Sent      int
	Failed    int
	Opened    int
}

type Recipient struct {
	ID        int64
	Email     string
	Status    string
	Error     sql.NullString
	SentAt    sql.NullTime
	OpenedAt  sql.NullTime
	OpenCount int
}

func (s *server) smtpConfigured() bool {
	return s.smtpAddr != "" && s.mailFrom != ""
}

func (s *server) handleMailings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderMailings(w, r, nil)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		switch r.FormValue("action") {
		case "create":
			subject := strings.TrimSpace(r.FormValue("subject"))
			if subject == "" || len(subject) > 500 {
				s.renderMailings(w, r, &passwordFlash{Message: "Subject is required (max 500 chars).", Kind: "error"})
				return
			}
			user, _ := r.Context().Value(ctxKeyUser).(string)
			var id int64
			if err := s.db.QueryRowContext(r.Context(),
				`INSERT INTO mailings (subject, body_html, created_by) VALUES ($1, '', $2) RETURNING id`,
				subject, user).Scan(&id); err != nil {
				log.Printf("create mailing error: %v", err)
				s.renderMailings(w, r, &passwordFlash{Message: "Unable to create mailing right now", Kind: "error"})
				return
			}
			http.Redirect(w, r, s.adminPath("/mailings/view?id="+strconv.FormatInt(id, 10)), http.StatusSeeOther)
		case "delete":
			id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
			if err != nil {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}
			if _, err := s.db.ExecContext(r.Context(), `DELETE FROM mailings WHERE id=$1 AND status='draft'`, id); err != nil {
				log.Printf("delete mailing error: %v", err)
				s.renderMailings(w, r, &passwordFlash{Message: "Unable to delete mailing right now", Kind: "error"})
				return
			}
			s.renderMailings(w, r, &passwordFlash{Message: "Draft deleted.", Kind: "success"})
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) renderMailings(w http.ResponseWriter, r *http.Request, flash *passwordFlash) {
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT m.id, m.subject, m.status, m.created_by, m.created_at, m.sent_at, l.name,
		    (SELECT COUNT(*) FROM mailing_recipients mr WHERE mr.mailing_id = m.id),
		    (SELECT COUNT(*) FROM mailing_recipients mr WHERE mr.mailing_id = m.id AND mr.opened_at IS NOT NULL)
		 FROM mailings m LEFT JOIN lists l ON l.id = m.list_id
		 ORDER BY m.created_at DESC LIMIT 100`)
	if err != nil {
		log.Printf("list mailings error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	mailings := []Mailing{}
	for rows.Next() {
		var m Mailing
		if err := rows.Scan(&m.ID, &m.Subject, &m.Status, &m.CreatedBy, &m.CreatedAt, &m.SentAt, &m.ListName, &m.Total, &m.Opened); err != nil {
			log.Printf("scan mailing error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		mailings = append(mailings, m)
	}
	if err := rows.Err(); err != nil {
		log.Printf("list mailings error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "templates/mailings.html", map[string]interface{}{
		"Mailings":       mailings,
		"Flash":          flash,
		"SMTPConfigured": s.smtpConfigured(),
		"CSRFToken":      r.Context().Value(ctxKeyCSRF),
		"AdminPrefix":    s.adminPrefix,
	})
}

func (s *server) loadMailing(ctx context.Context, id int64) (*Mailing, error) {
	var m Mailing
	err := s.db.QueryRowContext(ctx,
		`SELECT m.id, m.subject, m.body_html, m.list_id, m.status, m.created_by, m.created_at, m.sent_at, l.name
		 FROM mailings m LEFT JOIN lists l ON l.id = m.list_id WHERE m.id=$1`, id,
	).Scan(&m.ID, &m.Subject, &m.BodyHTML, &m.ListID, &m.Status, &m.CreatedBy, &m.CreatedAt, &m.SentAt, &m.ListName)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *server) handleMailingView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	m, err := s.loadMailing(r.Context(), id)
	if err != nil {
		log.Printf("get mailing error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if m == nil {
		http.Error(w, "mailing not found", http.StatusNotFound)
		return
	}

	// Recipient stats + rows for non-draft mailings.
	recipients := []Recipient{}
	if m.Status != "draft" {
		rows, err := s.db.QueryContext(r.Context(),
			`SELECT id, email, status, error, sent_at, opened_at, open_count
			 FROM mailing_recipients WHERE mailing_id=$1 ORDER BY email LIMIT 2000`, id)
		if err != nil {
			log.Printf("recipients error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var rc Recipient
			if err := rows.Scan(&rc.ID, &rc.Email, &rc.Status, &rc.Error, &rc.SentAt, &rc.OpenedAt, &rc.OpenCount); err != nil {
				log.Printf("scan recipient error: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			m.Total++
			switch rc.Status {
			case "sent":
				m.Sent++
			case "failed":
				m.Failed++
			}
			if rc.OpenedAt.Valid {
				m.Opened++
			}
			recipients = append(recipients, rc)
		}
		if err := rows.Err(); err != nil {
			log.Printf("recipients error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}

	// Lists for the recipient selector on drafts.
	lists := []List{}
	if m.Status == "draft" {
		rows, err := s.db.QueryContext(r.Context(), `SELECT id, name FROM lists ORDER BY name`)
		if err != nil {
			log.Printf("lists error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var l List
			if err := rows.Scan(&l.ID, &l.Name); err != nil {
				log.Printf("scan list error: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			lists = append(lists, l)
		}
		if err := rows.Err(); err != nil {
			log.Printf("lists error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}

	renderTemplate(w, "templates/mailing.html", map[string]interface{}{
		"Mailing":         m,
		"Recipients":      recipients,
		"Lists":           lists,
		"Flash":           mapMailingFlash(r.URL.Query().Get("msg")),
		"SMTPConfigured":  s.smtpConfigured(),
		"TrackingEnabled": s.publicBaseURL != "",
		"CSRFToken":       r.Context().Value(ctxKeyCSRF),
		"AdminPrefix":     s.adminPrefix,
	})
}

func mapMailingFlash(code string) *passwordFlash {
	switch code {
	case "saved":
		return &passwordFlash{Message: "Draft saved.", Kind: "success"}
	case "sending":
		return &passwordFlash{Message: "Mailing queued — sending in the background. Refresh for progress.", Kind: "success"}
	case "norecipients":
		return &passwordFlash{Message: "No sendable recipients (need subscribed customers with email addresses).", Kind: "error"}
	case "nosmtp":
		return &passwordFlash{Message: "SMTP is not configured. Set SMTP_HOST and MAIL_FROM.", Kind: "error"}
	case "notdraft":
		return &passwordFlash{Message: "Only drafts can be edited or sent.", Kind: "error"}
	case "empty":
		return &passwordFlash{Message: "Subject and body are required before sending.", Kind: "error"}
	default:
		return nil
	}
}

func (s *server) handleMailingUpdate(w http.ResponseWriter, r *http.Request) {
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
	view := s.adminPath("/mailings/view?id=" + strconv.FormatInt(id, 10))

	subject := strings.TrimSpace(r.FormValue("subject"))
	body := r.FormValue("body_html")
	if subject == "" || len(subject) > 500 || len(body) > 512*1024 {
		http.Redirect(w, r, view+"&msg=empty", http.StatusSeeOther)
		return
	}
	var listID interface{}
	if v := r.FormValue("list_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid list", http.StatusBadRequest)
			return
		}
		listID = n
	}

	res, err := s.db.ExecContext(r.Context(),
		`UPDATE mailings SET subject=$1, body_html=$2, list_id=$3 WHERE id=$4 AND status='draft'`,
		subject, body, listID, id)
	if err != nil {
		log.Printf("update mailing error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Redirect(w, r, view+"&msg=notdraft", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, view+"&msg=saved", http.StatusSeeOther)
}

func (s *server) handleMailingSend(w http.ResponseWriter, r *http.Request) {
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
	view := s.adminPath("/mailings/view?id=" + strconv.FormatInt(id, 10))

	if !s.smtpConfigured() {
		http.Redirect(w, r, view+"&msg=nosmtp", http.StatusSeeOther)
		return
	}

	m, err := s.loadMailing(r.Context(), id)
	if err != nil {
		log.Printf("get mailing error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if m == nil {
		http.Error(w, "mailing not found", http.StatusNotFound)
		return
	}
	if m.Status != "draft" {
		http.Redirect(w, r, view+"&msg=notdraft", http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(m.Subject) == "" || strings.TrimSpace(m.BodyHTML) == "" {
		http.Redirect(w, r, view+"&msg=empty", http.StatusSeeOther)
		return
	}

	// Materialize the recipient set: subscribed customers with an email, from
	// the selected list or (no list) every customer.
	recipQuery := `SELECT c.id, c.email FROM customers c
	    WHERE c.email IS NOT NULL AND c.unsubscribed_at IS NULL`
	args := []interface{}{}
	if m.ListID.Valid {
		recipQuery = `SELECT c.id, c.email FROM customers c
		    JOIN list_members lm ON lm.customer_id = c.id
		    WHERE lm.list_id = $1 AND c.email IS NOT NULL AND c.unsubscribed_at IS NULL`
		args = append(args, m.ListID.Int64)
	}
	rows, err := s.db.QueryContext(r.Context(), recipQuery, args...)
	if err != nil {
		log.Printf("recipient query error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type rcpt struct {
		customerID int64
		email      string
	}
	rcpts := []rcpt{}
	for rows.Next() {
		var rc rcpt
		if err := rows.Scan(&rc.customerID, &rc.email); err != nil {
			log.Printf("recipient scan error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		rcpts = append(rcpts, rc)
	}
	if err := rows.Err(); err != nil {
		log.Printf("recipient query error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if len(rcpts) == 0 {
		http.Redirect(w, r, view+"&msg=norecipients", http.StatusSeeOther)
		return
	}

	for _, rc := range rcpts {
		token, err := generateRandomHex(16)
		if err != nil {
			log.Printf("token error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT INTO mailing_recipients (mailing_id, customer_id, email, token) VALUES ($1, $2, $3, $4)`,
			id, rc.customerID, rc.email, token); err != nil {
			log.Printf("recipient insert error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}

	if _, err := s.db.ExecContext(r.Context(), `UPDATE mailings SET status='sending' WHERE id=$1`, id); err != nil {
		log.Printf("mailing status error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	go s.runMailingSend(id)
	http.Redirect(w, r, view+"&msg=sending", http.StatusSeeOther)
}

// runMailingSend delivers a mailing's pending recipients one message at a time
// and finalizes the mailing status. It runs in the background after send is
// requested; progress is visible in the mailing view as rows update.
func (s *server) runMailingSend(id int64) {
	ctx := context.Background()

	m, err := s.loadMailing(ctx, id)
	if err != nil || m == nil {
		log.Printf("mailing %d: load for send failed: %v", id, err)
		return
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, token FROM mailing_recipients WHERE mailing_id=$1 AND status='pending' ORDER BY id`, id)
	if err != nil {
		log.Printf("mailing %d: recipient load failed: %v", id, err)
		return
	}
	type pending struct {
		id    int64
		email string
		token string
	}
	work := []pending{}
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.email, &p.token); err != nil {
			rows.Close()
			log.Printf("mailing %d: recipient scan failed: %v", id, err)
			return
		}
		work = append(work, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		log.Printf("mailing %d: recipient load failed: %v", id, err)
		return
	}

	sent, failed := 0, 0
	for _, p := range work {
		msg := s.buildMessage(m, p.email, p.token)
		err := s.sendSMTP(p.email, msg)
		if err != nil {
			failed++
			log.Printf("mailing %d: send to %s failed: %v", id, p.email, err)
			truncated := err.Error()
			if len(truncated) > 500 {
				truncated = truncated[:500]
			}
			if _, dbErr := s.db.ExecContext(ctx,
				`UPDATE mailing_recipients SET status='failed', error=$1 WHERE id=$2`, truncated, p.id); dbErr != nil {
				log.Printf("mailing %d: recipient update failed: %v", id, dbErr)
			}
			continue
		}
		sent++
		if _, dbErr := s.db.ExecContext(ctx,
			`UPDATE mailing_recipients SET status='sent', sent_at=NOW() WHERE id=$1`, p.id); dbErr != nil {
			log.Printf("mailing %d: recipient update failed: %v", id, dbErr)
		}
	}

	final := "sent"
	if sent == 0 && failed > 0 {
		final = "failed"
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE mailings SET status=$1, sent_at=NOW() WHERE id=$2`, final, id); err != nil {
		log.Printf("mailing %d: final status update failed: %v", id, err)
	}
	log.Printf("mailing %d: finished (%d sent, %d failed)", id, sent, failed)
}

// buildMessage assembles the RFC 5322 message for one recipient: quoted-printable
// HTML body with an optional tracking pixel and an unsubscribe footer/header
// when PUBLIC_BASE_URL is configured.
func (s *server) buildMessage(m *Mailing, email, token string) []byte {
	var openURL, unsubURL string
	if s.publicBaseURL != "" {
		openURL = s.publicBaseURL + s.trackPath + "/open?t=" + token
		unsubURL = s.publicBaseURL + s.trackPath + "/unsub?t=" + token
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", s.mailFrom)
	fmt.Fprintf(&buf, "To: %s\r\n", email)
	fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.Subject))
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	if unsubURL != "" {
		fmt.Fprintf(&buf, "List-Unsubscribe: <%s>\r\n", unsubURL)
	}
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	buf.WriteString("\r\n")

	body := m.BodyHTML
	if unsubURL != "" {
		body += "\n<p style=\"font-size:12px;color:#888\"><a href=\"" + unsubURL + "\">Unsubscribe</a></p>"
	}
	if openURL != "" {
		body += "\n<img src=\"" + openURL + "\" width=\"1\" height=\"1\" alt=\"\">"
	}

	qp := quotedprintable.NewWriter(&buf)
	_, _ = qp.Write([]byte(body))
	_ = qp.Close()
	return buf.Bytes()
}

func (s *server) sendSMTP(to string, msg []byte) error {
	var auth smtp.Auth
	if s.smtpUser != "" {
		host := s.smtpAddr
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		auth = smtp.PlainAuth("", s.smtpUser, s.smtpPass, host)
	}
	return smtp.SendMail(s.smtpAddr, auth, s.mailFrom, []string{to}, msg)
}

// ---- Public tracking endpoints ---------------------------------------------

// trackingPixel is a 1x1 transparent GIF.
var trackingPixel = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

var tokenRe = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (s *server) handleTrackOpen(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	if tokenRe.MatchString(token) {
		if _, err := s.db.ExecContext(r.Context(),
			`UPDATE mailing_recipients SET open_count = open_count + 1,
			     opened_at = COALESCE(opened_at, NOW()) WHERE token=$1`, token); err != nil {
			log.Printf("track open error: %v", err)
		}
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Content-Length", strconv.Itoa(len(trackingPixel)))
	_, _ = w.Write(trackingPixel)
}

const unsubscribePage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>UNSUBSCRIBED</title>
<style>
  :root { color-scheme: dark; }
  html, body { height: 100%%; margin: 0; }
  body {
    background: #000; color: #2bff5a;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    display: flex; align-items: center; justify-content: center;
    text-shadow: 0 0 6px rgba(43,255,90,0.7);
  }
  .crt {
    width: min(640px, 92vw); padding: 28px 32px;
    border: 1px solid rgba(43,255,90,0.35);
    box-shadow: 0 0 24px rgba(43,255,90,0.25), inset 0 0 60px rgba(43,255,90,0.06);
    background: repeating-linear-gradient(0deg, rgba(0,0,0,0) 0 2px, rgba(0,0,0,0.35) 2px 4px);
  }
  h1 { font-size: 18px; letter-spacing: 3px; margin: 0 0 10px; }
  p { margin: 6px 0; color: #6dffa0; }
  .dim { color: #1f9c3c; }
</style>
</head>
<body>
  <main class="crt" role="status">
    <h1>// UNSUBSCRIBED //</h1>
    <p>&gt; %s</p>
    <p class="dim">&gt; no further mailings will be sent to this address.</p>
  </main>
</body>
</html>`

func (s *server) handleTrackUnsub(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	if !tokenRe.MatchString(token) {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	var customerID sql.NullInt64
	err := s.db.QueryRowContext(r.Context(),
		`SELECT customer_id FROM mailing_recipients WHERE token=$1`, token).Scan(&customerID)
	if err == sql.ErrNoRows {
		http.Error(w, "invalid token", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("unsub lookup error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if customerID.Valid {
		if _, err := s.db.ExecContext(r.Context(),
			`UPDATE customers SET unsubscribed_at = COALESCE(unsubscribed_at, NOW()) WHERE id=$1`,
			customerID.Int64); err != nil {
			log.Printf("unsub update error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprintf(w, unsubscribePage, "your address has been removed from our mailing lists.")
}
