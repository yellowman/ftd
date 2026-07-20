package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/quotedprintable"
	"net/http"
	"net/smtp"
	"net/textproto"
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
	case "addtag":
		// Segment tool: add every customer whose tags contain the given text.
		tag := strings.TrimSpace(r.FormValue("tag"))
		if tag == "" || len(tag) > 200 {
			return &passwordFlash{Message: "Enter a tag to match.", Kind: "error"}
		}
		res, err := s.db.ExecContext(r.Context(),
			`INSERT INTO list_members (list_id, customer_id)
			 SELECT $1, id FROM customers WHERE tags ILIKE $2
			 ON CONFLICT DO NOTHING`, listID, "%"+tag+"%")
		if err != nil {
			log.Printf("addtag error: %v", err)
			return &passwordFlash{Message: "Unable to add members right now", Kind: "error"}
		}
		n, _ := res.RowsAffected()
		return &passwordFlash{Message: fmt.Sprintf("Added %d customer(s) tagged “%s”.", n, tag), Kind: "success"}
	case "addrecent":
		// Segment tool: add every customer with a submission in the last N days.
		days, err := strconv.Atoi(r.FormValue("days"))
		if err != nil || days < 1 || days > 3650 {
			return &passwordFlash{Message: "Enter a number of days (1-3650).", Kind: "error"}
		}
		res, err := s.db.ExecContext(r.Context(),
			`INSERT INTO list_members (list_id, customer_id)
			 SELECT DISTINCT $1::integer, customer_id FROM submissions
			 WHERE customer_id IS NOT NULL AND submitted_at > NOW() - make_interval(days => $2)
			 ON CONFLICT DO NOTHING`, listID, days)
		if err != nil {
			log.Printf("addrecent error: %v", err)
			return &passwordFlash{Message: "Unable to add members right now", Kind: "error"}
		}
		n, _ := res.RowsAffected()
		return &passwordFlash{Message: fmt.Sprintf("Added %d customer(s) active in the last %d days.", n, days), Kind: "success"}
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
	Clicked   int
}

type Recipient struct {
	ID         int64
	Email      string
	Status     string
	Error      sql.NullString
	SentAt     sql.NullTime
	OpenedAt   sql.NullTime
	OpenCount  int
	ClickedAt  sql.NullTime
	ClickCount int
}

type MailingLink struct {
	URL        string
	ClickCount int
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
	mailingLinks := []MailingLink{}
	if m.Status != "draft" {
		rows, err := s.db.QueryContext(r.Context(),
			`SELECT id, email, status, error, sent_at, opened_at, open_count, clicked_at, click_count
			 FROM mailing_recipients WHERE mailing_id=$1 ORDER BY email LIMIT 2000`, id)
		if err != nil {
			log.Printf("recipients error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var rc Recipient
			if err := rows.Scan(&rc.ID, &rc.Email, &rc.Status, &rc.Error, &rc.SentAt, &rc.OpenedAt, &rc.OpenCount, &rc.ClickedAt, &rc.ClickCount); err != nil {
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
			if rc.ClickedAt.Valid {
				m.Clicked++
			}
			recipients = append(recipients, rc)
		}
		if err := rows.Err(); err != nil {
			log.Printf("recipients error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		linkRows, err := s.db.QueryContext(r.Context(),
			`SELECT url, click_count FROM mailing_links WHERE mailing_id=$1 ORDER BY click_count DESC, url`, id)
		if err != nil {
			log.Printf("links error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer linkRows.Close()
		for linkRows.Next() {
			var ml MailingLink
			if err := linkRows.Scan(&ml.URL, &ml.ClickCount); err != nil {
				log.Printf("scan link error: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			mailingLinks = append(mailingLinks, ml)
		}
		if err := linkRows.Err(); err != nil {
			log.Printf("links error: %v", err)
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
		"Links":           mailingLinks,
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
	case "testsent":
		return &passwordFlash{Message: "Test message sent.", Kind: "success"}
	case "testfail":
		return &passwordFlash{Message: "Test send failed — check the server log.", Kind: "error"}
	case "testbad":
		return &passwordFlash{Message: "Enter a valid test email address.", Kind: "error"}
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

	// Materialize the recipient set: subscribed, non-bounced customers with an
	// email, from the selected list or (no list) every customer.
	recipQuery := `SELECT c.id, c.email FROM customers c
	    WHERE c.email IS NOT NULL AND c.unsubscribed_at IS NULL AND c.bounced_at IS NULL`
	args := []interface{}{}
	if m.ListID.Valid {
		recipQuery = `SELECT c.id, c.email FROM customers c
		    JOIN list_members lm ON lm.customer_id = c.id
		    WHERE lm.list_id = $1 AND c.email IS NOT NULL AND c.unsubscribed_at IS NULL AND c.bounced_at IS NULL`
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

// linkHrefRe matches absolute http(s) links in a mailing body so they can be
// rewritten through the click-tracking redirect.
var linkHrefRe = regexp.MustCompile(`href="(https?://[^"]+)"`)

// prepareMailingLinks stores each unique link in a mailing body and returns
// url -> link id for rewriting. Click redirects resolve the URL by id, so the
// tracking endpoint never accepts an arbitrary URL parameter.
func (s *server) prepareMailingLinks(ctx context.Context, mailingID int64, body string) (map[string]int64, error) {
	links := map[string]int64{}
	if s.publicBaseURL == "" {
		return links, nil
	}
	for _, match := range linkHrefRe.FindAllStringSubmatch(body, -1) {
		url := match[1]
		if _, seen := links[url]; seen {
			continue
		}
		var linkID int64
		if err := s.db.QueryRowContext(ctx,
			`INSERT INTO mailing_links (mailing_id, url) VALUES ($1, $2)
			 ON CONFLICT (mailing_id, url) DO UPDATE SET url = EXCLUDED.url
			 RETURNING id`, mailingID, url).Scan(&linkID); err != nil {
			return nil, err
		}
		links[url] = linkID
	}
	return links, nil
}

// isHardSMTPError reports whether a send failed with a permanent (5xx) SMTP
// status, meaning the address itself was rejected rather than a transient
// relay problem.
func isHardSMTPError(err error) bool {
	var tpErr *textproto.Error
	if errors.As(err, &tpErr) {
		return tpErr.Code >= 500 && tpErr.Code < 600
	}
	return false
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

	links, err := s.prepareMailingLinks(ctx, id, m.BodyHTML)
	if err != nil {
		log.Printf("mailing %d: link preparation failed: %v", id, err)
		links = map[string]int64{}
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, customer_id, email, token FROM mailing_recipients WHERE mailing_id=$1 AND status='pending' ORDER BY id`, id)
	if err != nil {
		log.Printf("mailing %d: recipient load failed: %v", id, err)
		return
	}
	type pending struct {
		id         int64
		customerID sql.NullInt64
		email      string
		token      string
	}
	work := []pending{}
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.customerID, &p.email, &p.token); err != nil {
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
		msg := s.buildMessage(m, p.email, p.token, links)
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
			// A permanent rejection marks the customer as bounced so future
			// mailings skip the address (clearable from the customer page).
			if p.customerID.Valid && isHardSMTPError(err) {
				if _, dbErr := s.db.ExecContext(ctx,
					`UPDATE customers SET bounced_at = COALESCE(bounced_at, NOW()) WHERE id=$1`,
					p.customerID.Int64); dbErr != nil {
					log.Printf("mailing %d: bounce mark failed: %v", id, dbErr)
				}
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
// HTML body with links rewritten through click tracking, an open-tracking pixel,
// and an unsubscribe footer/header when PUBLIC_BASE_URL is configured. links
// maps body URL -> mailing_links id; pass nil to skip click rewriting.
func (s *server) buildMessage(m *Mailing, email, token string, links map[string]int64) []byte {
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
	if s.publicBaseURL != "" && len(links) > 0 {
		for url, linkID := range links {
			tracked := s.publicBaseURL + s.trackPath + "/c?t=" + token + "&l=" + strconv.FormatInt(linkID, 10)
			body = strings.ReplaceAll(body, `href="`+url+`"`, `href="`+tracked+`"`)
		}
	}
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

// handleTrackClick resolves (recipient token, link id) to the stored URL,
// records the click (which also implies an open), and redirects. The URL is
// never taken from the request, so this cannot act as an open redirect.
func (s *server) handleTrackClick(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	linkID, err := strconv.ParseInt(r.URL.Query().Get("l"), 10, 64)
	if !tokenRe.MatchString(token) || err != nil {
		http.Error(w, "invalid link", http.StatusBadRequest)
		return
	}

	var url string
	var recipientID int64
	dbErr := s.db.QueryRowContext(r.Context(),
		`SELECT ml.url, mr.id FROM mailing_recipients mr
		 JOIN mailing_links ml ON ml.mailing_id = mr.mailing_id
		 WHERE mr.token = $1 AND ml.id = $2`, token, linkID,
	).Scan(&url, &recipientID)
	if dbErr == sql.ErrNoRows {
		http.Error(w, "unknown link", http.StatusNotFound)
		return
	} else if dbErr != nil {
		log.Printf("track click lookup error: %v", dbErr)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE mailing_recipients SET click_count = click_count + 1,
		     clicked_at = COALESCE(clicked_at, NOW()),
		     open_count = GREATEST(open_count, 1),
		     opened_at = COALESCE(opened_at, NOW())
		 WHERE id = $1`, recipientID); err != nil {
		log.Printf("track click update error: %v", err)
	}
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE mailing_links SET click_count = click_count + 1 WHERE id = $1`, linkID); err != nil {
		log.Printf("track link update error: %v", err)
	}

	http.Redirect(w, r, url, http.StatusSeeOther)
}

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

// ---- Test send -------------------------------------------------------------

// handleMailingTest sends the current draft to a single arbitrary address with
// a "[TEST] " subject prefix. No recipient row is stored, so the embedded
// tracking token records nothing.
func (s *server) handleMailingTest(w http.ResponseWriter, r *http.Request) {
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

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if !strings.Contains(email, "@") {
		http.Redirect(w, r, view+"&msg=testbad", http.StatusSeeOther)
		return
	}
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
	if strings.TrimSpace(m.BodyHTML) == "" {
		http.Redirect(w, r, view+"&msg=empty", http.StatusSeeOther)
		return
	}

	token, err := generateRandomHex(16)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	testCopy := *m
	testCopy.Subject = "[TEST] " + m.Subject
	if err := s.sendSMTP(email, s.buildMessage(&testCopy, email, token, nil)); err != nil {
		log.Printf("test send to %s failed: %v", email, err)
		http.Redirect(w, r, view+"&msg=testfail", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, view+"&msg=testsent", http.StatusSeeOther)
}

// ---- Activity timeline -----------------------------------------------------

type TimelineEntry struct {
	Kind      string
	Body      string
	CreatedBy sql.NullString
	CreatedAt time.Time
}

// loadTimeline merges manual activities with mailing deliveries for a customer,
// newest first.
func (s *server) loadTimeline(ctx context.Context, customerID int64) ([]TimelineEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT kind, body, created_by, created_at FROM activities WHERE customer_id = $1
		 UNION ALL
		 SELECT 'mailing',
		     m.subject || CASE
		         WHEN mr.clicked_at IS NOT NULL THEN ' (clicked)'
		         WHEN mr.opened_at IS NOT NULL THEN ' (opened)'
		         ELSE '' END,
		     m.created_by, mr.sent_at
		 FROM mailing_recipients mr JOIN mailings m ON m.id = mr.mailing_id
		 WHERE mr.customer_id = $1 AND mr.sent_at IS NOT NULL
		 ORDER BY created_at DESC LIMIT 200`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []TimelineEntry{}
	for rows.Next() {
		var e TimelineEntry
		if err := rows.Scan(&e.Kind, &e.Body, &e.CreatedBy, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

var activityKinds = map[string]struct{}{"note": {}, "call": {}, "email": {}, "meeting": {}}

func (s *server) handleCustomerNote(w http.ResponseWriter, r *http.Request) {
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
	kind := r.FormValue("kind")
	body := strings.TrimSpace(r.FormValue("body"))
	if _, ok := activityKinds[kind]; !ok || body == "" || len(body) > 8000 {
		http.Error(w, "invalid activity", http.StatusBadRequest)
		return
	}
	user, _ := r.Context().Value(ctxKeyUser).(string)
	if _, err := s.db.ExecContext(r.Context(),
		`INSERT INTO activities (customer_id, kind, body, created_by) VALUES ($1, $2, $3, $4)`,
		id, kind, body, user); err != nil {
		log.Printf("activity insert error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.adminPath("/customers/view?id="+strconv.FormatInt(id, 10)), http.StatusSeeOther)
}

func (s *server) handleCustomerClearBounce(w http.ResponseWriter, r *http.Request) {
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
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE customers SET bounced_at = NULL WHERE id=$1`, id); err != nil {
		log.Printf("clear bounce error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.adminPath("/customers/view?id="+strconv.FormatInt(id, 10)), http.StatusSeeOther)
}

// ---- CSV import/export -----------------------------------------------------

var csvHeader = []string{"email", "name", "company", "phone", "address", "tags", "notes", "created_at", "unsubscribed", "bounced"}

func (s *server) handleCustomerExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT email, name, company, phone, address, tags, notes, created_at,
		     unsubscribed_at IS NOT NULL, bounced_at IS NOT NULL
		 FROM customers ORDER BY id`)
	if err != nil {
		log.Printf("export query error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="customers.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write(csvHeader)
	for rows.Next() {
		var email, name, company, phone, address, tags, notes sql.NullString
		var createdAt time.Time
		var unsubbed, bounced bool
		if err := rows.Scan(&email, &name, &company, &phone, &address, &tags, &notes, &createdAt, &unsubbed, &bounced); err != nil {
			log.Printf("export scan error: %v", err)
			return
		}
		_ = cw.Write([]string{
			email.String, name.String, company.String, phone.String, address.String,
			tags.String, notes.String, createdAt.UTC().Format(time.RFC3339),
			strconv.FormatBool(unsubbed), strconv.FormatBool(bounced),
		})
	}
	if err := rows.Err(); err != nil {
		log.Printf("export error: %v", err)
	}
	cw.Flush()
}

const maxImportBytes = 10 << 20 // 10MB

// handleCustomerImport upserts customers (keyed by email) from an uploaded CSV.
// The file is parsed from the multipart stream entirely in memory: under the
// chroot/pledge sandbox there may be no writable filesystem to spill to.
func (s *server) handleCustomerImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBytes+64*1024)

	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected multipart upload", http.StatusBadRequest)
		return
	}

	var csrfToken string
	var csvData []byte
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "invalid upload", http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "csrf_token":
			b, _ := io.ReadAll(io.LimitReader(part, 1024))
			csrfToken = string(b)
		case "file":
			b, err := io.ReadAll(io.LimitReader(part, maxImportBytes+1))
			if err != nil {
				http.Error(w, "invalid upload", http.StatusBadRequest)
				return
			}
			if len(b) > maxImportBytes {
				http.Error(w, "file too large (max 10MB)", http.StatusRequestEntityTooLarge)
				return
			}
			csvData = b
		default:
			_, _ = io.Copy(io.Discard, part)
		}
	}

	if !s.validateCSRFFromCookie(r, csrfCookieName, csrfToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if len(csvData) == 0 {
		http.Error(w, "no file uploaded", http.StatusBadRequest)
		return
	}

	reader := csv.NewReader(bytes.NewReader(csvData))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		http.Error(w, "invalid CSV", http.StatusBadRequest)
		return
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	if _, ok := col["email"]; !ok {
		http.Error(w, "CSV needs an 'email' column", http.StatusBadRequest)
		return
	}
	field := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}

	imported, skipped := 0, 0
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			skipped++
			continue
		}
		email := strings.ToLower(field(rec, "email"))
		if !strings.Contains(email, "@") {
			skipped++
			continue
		}
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT INTO customers (email, name, company, phone, address, tags, notes)
			 VALUES ($1, NULLIF($2,''), NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), NULLIF($7,''))
			 ON CONFLICT (email) DO UPDATE SET
			     name = COALESCE(NULLIF(EXCLUDED.name, ''), customers.name),
			     company = COALESCE(NULLIF(EXCLUDED.company, ''), customers.company),
			     phone = COALESCE(NULLIF(EXCLUDED.phone, ''), customers.phone),
			     address = COALESCE(NULLIF(EXCLUDED.address, ''), customers.address),
			     tags = COALESCE(NULLIF(EXCLUDED.tags, ''), customers.tags),
			     notes = COALESCE(NULLIF(EXCLUDED.notes, ''), customers.notes),
			     updated_at = NOW()`,
			email, field(rec, "name"), field(rec, "company"), field(rec, "phone"),
			field(rec, "address"), field(rec, "tags"), field(rec, "notes")); err != nil {
			log.Printf("import row error for %s: %v", email, err)
			skipped++
			continue
		}
		imported++
	}

	http.Redirect(w, r,
		s.adminPath("/customers?imported="+strconv.Itoa(imported)+"&skipped="+strconv.Itoa(skipped)),
		http.StatusSeeOther)
}
