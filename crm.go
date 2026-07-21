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
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
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

	allTags, err := s.listTagNames(r.Context())
	if err != nil {
		log.Printf("list tags error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	mailings, err := s.listMailings(r.Context(), id)
	if err != nil {
		log.Printf("list mailings error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "templates/list.html", map[string]interface{}{
		"List":        list,
		"Members":     members,
		"AllTags":     allTags,
		"Mailings":    mailings,
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
		// Segment tool: add every customer carrying the given tag.
		tag := normalizeTagName(r.FormValue("tag"))
		if tag == "" {
			return &passwordFlash{Message: "Pick a tag.", Kind: "error"}
		}
		res, err := s.db.ExecContext(r.Context(),
			`INSERT INTO list_members (list_id, customer_id)
			 SELECT $1::integer, ct.customer_id FROM customer_tags ct
			 JOIN tags t ON t.id = ct.tag_id WHERE t.name = $2
			 ON CONFLICT DO NOTHING`, listID, tag)
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
	Tags      sql.NullString
	Total     int
	Sent      int
	Failed    int
	Opened    int
	Clicked   int
}

type Recipient struct {
	ID         int64
	CustomerID sql.NullInt64
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
		`SELECT m.id, m.subject, m.status, m.created_by, m.created_at, m.sent_at, m.list_id, l.name,
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
		if err := rows.Scan(&m.ID, &m.Subject, &m.Status, &m.CreatedBy, &m.CreatedAt, &m.SentAt, &m.ListID, &m.ListName, &m.Total, &m.Opened); err != nil {
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
		`SELECT m.id, m.subject, m.body_html, m.list_id, m.status, m.created_by, m.created_at, m.sent_at, l.name,
		    (SELECT string_agg(t.name, ', ' ORDER BY t.name) FROM mailing_tags mt JOIN tags t ON t.id = mt.tag_id WHERE mt.mailing_id = m.id)
		 FROM mailings m LEFT JOIN lists l ON l.id = m.list_id WHERE m.id=$1`, id,
	).Scan(&m.ID, &m.Subject, &m.BodyHTML, &m.ListID, &m.Status, &m.CreatedBy, &m.CreatedAt, &m.SentAt, &m.ListName, &m.Tags)
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

	// Recipient stats + rows for non-draft mailings. Summary counts come from
	// a dedicated aggregate over every row; the LIMIT below caps only the
	// displayed table, so large campaigns still report true totals.
	recipients := []Recipient{}
	mailingLinks := []MailingLink{}
	if m.Status != "draft" {
		if err := s.db.QueryRowContext(r.Context(),
			`SELECT COUNT(*),
			    COUNT(*) FILTER (WHERE status = 'sent'),
			    COUNT(*) FILTER (WHERE status = 'failed'),
			    COUNT(*) FILTER (WHERE opened_at IS NOT NULL),
			    COUNT(*) FILTER (WHERE clicked_at IS NOT NULL)
			 FROM mailing_recipients WHERE mailing_id=$1`, id,
		).Scan(&m.Total, &m.Sent, &m.Failed, &m.Opened, &m.Clicked); err != nil {
			log.Printf("recipient stats error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		rows, err := s.db.QueryContext(r.Context(),
			`SELECT id, customer_id, email, status, error, sent_at, opened_at, open_count, clicked_at, click_count
			 FROM mailing_recipients WHERE mailing_id=$1 ORDER BY email LIMIT 2000`, id)
		if err != nil {
			log.Printf("recipients error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var rc Recipient
			if err := rows.Scan(&rc.ID, &rc.CustomerID, &rc.Email, &rc.Status, &rc.Error, &rc.SentAt, &rc.OpenedAt, &rc.OpenCount, &rc.ClickedAt, &rc.ClickCount); err != nil {
				log.Printf("scan recipient error: %v", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
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

	// Media library for the editor on drafts.
	media := []Media{}
	if m.Status == "draft" {
		media, err = s.listMedia(r.Context())
		if err != nil {
			log.Printf("media list error: %v", err)
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

	tagList := []string{}
	if m.Tags.Valid {
		tagList = splitTagList(m.Tags.String)
	}

	renderTemplate(w, "templates/mailing.html", map[string]interface{}{
		"Mailing":         m,
		"TagList":         tagList,
		"Recipients":      recipients,
		"Links":           mailingLinks,
		"Lists":           lists,
		"Media":           media,
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
		return &passwordFlash{Message: "This mailing is not a draft — it may already be sending or sent.", Kind: "error"}
	case "empty":
		return &passwordFlash{Message: "Subject and body are required before sending.", Kind: "error"}
	case "testsent":
		return &passwordFlash{Message: "Test message sent.", Kind: "success"}
	case "testfail":
		return &passwordFlash{Message: "Test send failed — check the server log.", Kind: "error"}
	case "testbad":
		return &passwordFlash{Message: "Enter a valid test email address.", Kind: "error"}
	case "retrying":
		return &passwordFlash{Message: "Retrying delivery in the background. Refresh for progress.", Kind: "success"}
	case "notfailed":
		return &passwordFlash{Message: "This mailing cannot be retried right now.", Kind: "error"}
	case "noretryable":
		return &passwordFlash{Message: "Nothing to retry — remaining failures are hard-bounced addresses (clear the bounce on the customer page first).", Kind: "error"}
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

	// Replace the mailing's tag set (propagated to customers who click).
	if _, err := s.db.ExecContext(r.Context(), `DELETE FROM mailing_tags WHERE mailing_id=$1`, id); err != nil {
		log.Printf("mailing tags clear error: %v", err)
	}
	for _, name := range splitTagList(r.FormValue("tags")) {
		var tagID int64
		if err := s.db.QueryRowContext(r.Context(),
			`INSERT INTO tags (name) VALUES ($1)
			 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
			 RETURNING id`, name).Scan(&tagID); err != nil {
			log.Printf("mailing tag upsert error: %v", err)
			continue
		}
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT INTO mailing_tags (mailing_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			id, tagID); err != nil {
			log.Printf("mailing tag link error: %v", err)
		}
	}

	// The compose page is one form with several submit buttons. Edits are
	// saved above first, so sending always uses what is on screen — never a
	// stale audience or body from an earlier save.
	switch r.FormValue("do") {
	case "send":
		s.sendMailingFlow(w, r, id)
	case "test":
		s.testSendFlow(w, r, id, r.FormValue("test_email"))
	default:
		http.Redirect(w, r, view+"&msg=saved", http.StatusSeeOther)
	}
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
	s.sendMailingFlow(w, r, id)
}

// handleMailingRetry re-runs delivery for a failed mailing: recipients that
// failed transiently (their customer is not bounced) go back to pending, along
// with any never-attempted rows, and the worker restarts. Already-sent
// recipients are untouched, so nobody is mailed twice.
func (s *server) handleMailingRetry(w http.ResponseWriter, r *http.Request) {
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

	// Both fully-failed and partially-failed ("sent" with failed recipients)
	// mailings are retryable. Read the current status, then claim it with a
	// CAS so exactly one retry wins and we can restore the status if there
	// turns out to be nothing to requeue.
	var prev string
	err = s.db.QueryRowContext(r.Context(),
		`SELECT status FROM mailings WHERE id=$1`, id).Scan(&prev)
	if err == sql.ErrNoRows {
		http.Error(w, "mailing not found", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("mailing retry lookup error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if prev != "failed" && prev != "sent" {
		http.Redirect(w, r, view+"&msg=notfailed", http.StatusSeeOther)
		return
	}

	res, err := s.db.ExecContext(r.Context(),
		`UPDATE mailings SET status='sending' WHERE id=$1 AND status=$2`, id, prev)
	if err != nil {
		log.Printf("mailing retry claim error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		http.Redirect(w, r, view+"&msg=notfailed", http.StatusSeeOther)
		return
	}

	// Requeue transient failures; leave hard-bounced customers suppressed.
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE mailing_recipients mr SET status='pending', error=NULL
		 WHERE mr.mailing_id=$1 AND mr.status IN ('failed','sending')
		   AND NOT EXISTS (SELECT 1 FROM customers c WHERE c.id = mr.customer_id AND c.bounced_at IS NOT NULL)`,
		id); err != nil {
		log.Printf("mailing retry requeue error: %v", err)
		s.markMailingFailed(r.Context(), id)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Nothing became pending (e.g. every failure is a hard-bounced customer):
	// release the claim, restoring the prior status, instead of re-finalizing
	// a no-op delivery run.
	var pending int
	if err := s.db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM mailing_recipients WHERE mailing_id=$1 AND status='pending'`, id).Scan(&pending); err != nil {
		log.Printf("mailing retry pending count error: %v", err)
		s.markMailingFailed(r.Context(), id)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if pending == 0 {
		if _, err := s.db.ExecContext(r.Context(),
			`UPDATE mailings SET status=$1 WHERE id=$2 AND status='sending'`, prev, id); err != nil {
			log.Printf("mailing retry restore error: %v", err)
		}
		http.Redirect(w, r, view+"&msg=noretryable", http.StatusSeeOther)
		return
	}

	go s.runMailingSend(id)
	http.Redirect(w, r, view+"&msg=retrying", http.StatusSeeOther)
}

// markMailingFailed finalizes a mailing that cannot proceed, so it never shows
// as "sending" forever. The guard keeps a finished mailing's status intact.
func (s *server) markMailingFailed(ctx context.Context, id int64) {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE mailings SET status='failed', sent_at=NOW() WHERE id=$1 AND status='sending'`, id); err != nil {
		log.Printf("mailing %d: failure finalize error: %v", id, err)
	}
}

// sendMailingFlow atomically claims the draft, then loads and validates it,
// materializes the recipient set, and starts the background delivery worker.
// The status flip draft->sending is the mutex: concurrent send attempts lose
// the UPDATE race and are turned away, and because editing requires
// status='draft', claiming FIRST freezes the mailing — the subject, body, and
// audience read afterwards are exactly what will be sent, immune to a
// concurrent tab saving different content between check and claim.
func (s *server) sendMailingFlow(w http.ResponseWriter, r *http.Request, id int64) {
	view := s.adminPath("/mailings/view?id=" + strconv.FormatInt(id, 10))

	if !s.smtpConfigured() {
		http.Redirect(w, r, view+"&msg=nosmtp", http.StatusSeeOther)
		return
	}

	// Claim before reading anything. Exactly one request wins this UPDATE;
	// everyone else sees notdraft instead of enqueueing a second batch.
	res, err := s.db.ExecContext(r.Context(),
		`UPDATE mailings SET status='sending' WHERE id=$1 AND status='draft'`, id)
	if err != nil {
		log.Printf("mailing claim error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		// Not a draft — or no such mailing at all.
		if m, err := s.loadMailing(r.Context(), id); err == nil && m == nil {
			http.Error(w, "mailing not found", http.StatusNotFound)
			return
		}
		http.Redirect(w, r, view+"&msg=notdraft", http.StatusSeeOther)
		return
	}

	unclaim := func() {
		if _, err := s.db.ExecContext(r.Context(),
			`UPDATE mailings SET status='draft' WHERE id=$1 AND status='sending'`, id); err != nil {
			log.Printf("mailing unclaim error: %v", err)
		}
	}

	// Load the now-frozen mailing; this is authoritative for audience and body.
	m, err := s.loadMailing(r.Context(), id)
	if err != nil || m == nil {
		log.Printf("get mailing error after claim: %v", err)
		unclaim()
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(m.Subject) == "" || strings.TrimSpace(m.BodyHTML) == "" {
		unclaim()
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
		s.markMailingFailed(r.Context(), id)
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
			s.markMailingFailed(r.Context(), id)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		rcpts = append(rcpts, rc)
	}
	if err := rows.Err(); err != nil {
		log.Printf("recipient query error: %v", err)
		s.markMailingFailed(r.Context(), id)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if len(rcpts) == 0 {
		// Nothing to enqueue: release the claim so the draft stays editable.
		unclaim()
		http.Redirect(w, r, view+"&msg=norecipients", http.StatusSeeOther)
		return
	}

	for _, rc := range rcpts {
		token, err := generateRandomHex(16)
		if err != nil {
			log.Printf("token error: %v", err)
			s.markMailingFailed(r.Context(), id)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		// The unique (mailing_id, customer_id) index makes retries after a
		// partial failure safe: existing rows are kept, not duplicated.
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT INTO mailing_recipients (mailing_id, customer_id, email, token) VALUES ($1, $2, $3, $4)
			 ON CONFLICT (mailing_id, customer_id) DO NOTHING`,
			id, rc.customerID, rc.email, token); err != nil {
			log.Printf("recipient insert error: %v", err)
			s.markMailingFailed(r.Context(), id)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
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

// resumeStalledMailings restarts delivery for mailings left in 'sending' by a
// crash, restart, or deploy. Only never-attempted ('pending') recipients are
// auto-resumed; rows caught mid-delivery are marked failed rather than
// requeued, because SMTP may already have accepted them and automatic
// redelivery would duplicate mail (the admin can retry them deliberately).
// A 'sending' mailing with no recipient rows at all crashed between claim and
// enqueue and is finalized as failed (the draft mutex has already fired, so
// it could never complete otherwise).
func (s *server) resumeStalledMailings(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT m.id,
		    (SELECT COUNT(*) FROM mailing_recipients mr WHERE mr.mailing_id = m.id),
		    (SELECT COUNT(*) FROM mailing_recipients mr WHERE mr.mailing_id = m.id AND mr.status = 'pending')
		 FROM mailings m WHERE m.status = 'sending'`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type stalled struct {
		id             int64
		total, pending int
	}
	found := []stalled{}
	for rows.Next() {
		var st stalled
		if err := rows.Scan(&st.id, &st.total, &st.pending); err != nil {
			return err
		}
		found = append(found, st)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, st := range found {
		if st.total == 0 {
			log.Printf("mailing %d: stuck in sending with no recipients; marking failed", st.id)
			s.markMailingFailed(ctx, st.id)
			continue
		}
		// Rows stuck in 'sending' were claimed by a worker that died
		// mid-delivery. SMTP may already have accepted those messages, so
		// automatically requeueing them risks duplicates. Mark them failed
		// with an explanatory error instead: the admin can consciously
		// redeliver via "Retry failed recipients". Rows still 'pending' were
		// never attempted and resume safely.
		res, err := s.db.ExecContext(ctx,
			`UPDATE mailing_recipients SET status='failed',
			     error='interrupted mid-delivery by a restart; the message may or may not have been sent'
			 WHERE mailing_id=$1 AND status='sending'`, st.id)
		if err != nil {
			log.Printf("mailing %d: marking stuck recipients failed: %v", st.id, err)
		} else if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("mailing %d: %d recipient(s) were mid-delivery at the crash; marked failed (not auto-resent — delivery state unknown)", st.id, n)
		}
		log.Printf("mailing %d: resuming delivery (%d of %d recipients pending)", st.id, st.pending, st.total)
		go s.runMailingSend(st.id)
	}
	return nil
}

// recordRecipient applies a recipient status update with retries. The outcome
// of an SMTP conversation cannot be rolled back, so the database record must
// stick even through a transient connection hiccup; a plain single attempt
// would strand the row in 'sending'. Returns false if every attempt failed.
func (s *server) recordRecipient(ctx context.Context, mailingID int64, query string, args ...interface{}) bool {
	delays := []time.Duration{0, time.Second, 5 * time.Second}
	for i, d := range delays {
		if d > 0 {
			time.Sleep(d)
		}
		if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
			log.Printf("mailing %d: recipient update attempt %d/%d failed: %v", mailingID, i+1, len(delays), err)
			continue
		}
		return true
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
		s.markMailingFailed(ctx, id)
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
		s.markMailingFailed(ctx, id)
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
			s.markMailingFailed(ctx, id)
			return
		}
		work = append(work, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		log.Printf("mailing %d: recipient load failed: %v", id, err)
		s.markMailingFailed(ctx, id)
		return
	}

	sent, failed := 0, 0
	for _, p := range work {
		// Claim the row before touching SMTP. If another worker (an overlapping
		// resume/retry, or a second process) got here first, RowsAffected is 0
		// and this recipient is skipped — no double delivery.
		claim, dbErr := s.db.ExecContext(ctx,
			`UPDATE mailing_recipients SET status='sending' WHERE id=$1 AND status='pending'`, p.id)
		if dbErr != nil {
			log.Printf("mailing %d: recipient claim failed: %v", id, dbErr)
			continue
		}
		if n, _ := claim.RowsAffected(); n != 1 {
			continue
		}

		msg := s.buildMessage(m, p.email, p.token, links)
		err := s.sendSMTP(p.email, msg)
		if err != nil {
			failed++
			log.Printf("mailing %d: send to %s failed: %v", id, p.email, err)
			truncated := err.Error()
			if len(truncated) > 500 {
				truncated = truncated[:500]
			}
			s.recordRecipient(ctx, id,
				`UPDATE mailing_recipients SET status='failed', error=$1 WHERE id=$2`, truncated, p.id)
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
		// The message is irrevocably handed to the relay; failing to record
		// that would leave the row in 'sending', and a later resume would
		// requeue it and deliver a duplicate. recordRecipient retries hard.
		if !s.recordRecipient(ctx, id,
			`UPDATE mailing_recipients SET status='sent', sent_at=NOW() WHERE id=$1`, p.id) {
			log.Printf("mailing %d: CRITICAL: delivered to %s but could not record it; row left in 'sending' — a resume/retry may deliver a duplicate", id, p.email)
		}
	}

	// Finalize from database truth, not this worker's in-memory counters: after
	// a partial retry the counters only cover the requeued subset, and another
	// overlapping worker may still own in-flight rows.
	var remaining, dbSent, dbFailed int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FILTER (WHERE status IN ('pending','sending')),
		    COUNT(*) FILTER (WHERE status = 'sent'),
		    COUNT(*) FILTER (WHERE status = 'failed')
		 FROM mailing_recipients WHERE mailing_id=$1`, id).Scan(&remaining, &dbSent, &dbFailed); err != nil {
		// Leave the mailing in 'sending'; startup resume can finish the job.
		log.Printf("mailing %d: finalize count failed: %v", id, err)
		return
	}
	if remaining > 0 {
		// Another worker still owns rows; whoever finishes last finalizes.
		log.Printf("mailing %d: this worker done (%d sent, %d failed); %d recipients still in flight elsewhere", id, sent, failed, remaining)
		return
	}

	final := "sent"
	if dbSent == 0 && dbFailed > 0 {
		final = "failed"
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE mailings SET status=$1, sent_at=NOW() WHERE id=$2 AND status='sending'`, final, id); err != nil {
		log.Printf("mailing %d: final status update failed: %v", id, err)
	}
	log.Printf("mailing %d: finished (%d sent, %d failed overall; this worker %d/%d)", id, dbSent, dbFailed, sent, failed)
}

// emailLayoutTop/Bottom form the bulletproof table skeleton wrapped around the
// composed body at send (and preview) time: XHTML+MSO namespaces, an Outlook
// DPI fix, a ghost table for Outlook's renderer (which ignores max-width), and
// a centered 600px presentation table with fonts inlined on the td. Authors
// compose only the content; layout survival in Outlook/Gmail/etc. is ftd's job.
const emailLayoutTop = `<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="x-apple-disable-message-reformatting">
<!--[if mso]>
<noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript>
<![endif]-->
<style>
  body, table, td { font-family: Arial, Helvetica, sans-serif !important; }
  table { border-collapse: collapse; }
  img { border: 0; line-height: 100%; outline: none; text-decoration: none; max-width: 100%; height: auto; }
</style>
</head>
<body style="margin:0;padding:0;background-color:#ececec;">
<center role="article" aria-roledescription="email" style="width:100%;background-color:#ececec;">
<!--[if mso]>
<table role="presentation" width="600" align="center" cellpadding="0" cellspacing="0" border="0"><tr><td>
<![endif]-->
<table role="presentation" align="center" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;margin:0 auto;background-color:#ffffff;">
<tr><td style="padding:28px 32px;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;color:#1a1a1a;">
`

const emailLayoutBottom = `
</td></tr>
</table>
<!--[if mso]>
</td></tr></table>
<![endif]-->
</center>
</body>
</html>`

// wrapEmailLayout wraps composed content in the table skeleton. Bodies that are
// already full documents (a pasted "<html"/doctype) are passed through
// untouched as the power-user escape hatch.
func wrapEmailLayout(body string) string {
	probe := strings.ToLower(body)
	if strings.Contains(probe, "<html") || strings.Contains(probe, "<!doctype") {
		return body
	}
	return emailLayoutTop + body + emailLayoutBottom
}

// buildMessage assembles the RFC 5322 message for one recipient as
// multipart/alternative: an auto-generated text/plain rendition first (for
// text-only clients), then the quoted-printable HTML with links rewritten
// through click tracking, an open-tracking pixel, and an unsubscribe
// footer/header when PUBLIC_BASE_URL is configured. links maps body URL ->
// mailing_links id; pass nil to skip click rewriting.
func (s *server) buildMessage(m *Mailing, email, token string, links map[string]int64) []byte {
	var openURL, unsubURL string
	if s.publicBaseURL != "" {
		openURL = s.publicBaseURL + s.trackPath + "/open?t=" + token
		unsubURL = s.publicBaseURL + s.trackPath + "/unsub?t=" + token
	}

	htmlBody := m.BodyHTML
	if s.publicBaseURL != "" && len(links) > 0 {
		for url, linkID := range links {
			tracked := s.publicBaseURL + s.trackPath + "/c?t=" + token + "&l=" + strconv.FormatInt(linkID, 10)
			htmlBody = strings.ReplaceAll(htmlBody, `href="`+url+`"`, `href="`+tracked+`"`)
		}
	}

	// The text part mirrors the final HTML (tracked links included, so clicks
	// from text-mode clients still count) with the unsubscribe URL spelled out.
	textBody := htmlToText(htmlBody)
	if unsubURL != "" {
		textBody += "\r\n\r\n--\r\nUnsubscribe: " + unsubURL
		htmlBody += "\n<p style=\"font-size:12px;color:#888\"><a href=\"" + unsubURL + "\">Unsubscribe</a></p>"
	}
	if openURL != "" {
		htmlBody += "\n<img src=\"" + openURL + "\" width=\"1\" height=\"1\" alt=\"\">"
	}
	htmlBody = wrapEmailLayout(htmlBody)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", s.mailFrom)
	fmt.Fprintf(&buf, "To: %s\r\n", email)
	// A Reply-To identical to From is noise; replies go there anyway.
	if s.replyTo != "" && !sameAddress(s.replyTo, s.mailFrom) {
		fmt.Fprintf(&buf, "Reply-To: %s\r\n", s.replyTo)
	}
	fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.Subject))
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	if unsubURL != "" {
		fmt.Fprintf(&buf, "List-Unsubscribe: <%s>\r\n", unsubURL)
	}
	buf.WriteString("MIME-Version: 1.0\r\n")

	mw := multipart.NewWriter(&buf)
	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", mw.Boundary())

	writePart := func(ctype, content string) {
		part, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {ctype + "; charset=utf-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return
		}
		qp := quotedprintable.NewWriter(part)
		_, _ = qp.Write([]byte(content))
		_ = qp.Close()
	}
	// Least-preferred alternative first, per RFC 2046.
	writePart("text/plain", textBody)
	writePart("text/html", htmlBody)
	_ = mw.Close()

	return buf.Bytes()
}

// sameAddress compares two header values by their email address, so
// "Sales <sales@x.com>" and "sales@x.com" count as the same; falls back to a
// case-insensitive string compare when either does not parse.
func sameAddress(a, b string) bool {
	pa, errA := mail.ParseAddress(a)
	pb, errB := mail.ParseAddress(b)
	if errA == nil && errB == nil {
		return strings.EqualFold(pa.Address, pb.Address)
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func (s *server) sendSMTP(to string, msg []byte) error {
	var auth smtp.Auth
	if s.smtpUser != "" {
		// SplitHostPort is the inverse of the JoinHostPort used to build
		// smtpAddr: it unbrackets IPv6 literals ("[::1]:25" -> "::1"), which a
		// naive cut at the last colon would mangle and break AUTH.
		host, _, err := net.SplitHostPort(s.smtpAddr)
		if err != nil {
			host = s.smtpAddr
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
	var recipientID, mailingID int64
	var customerID sql.NullInt64
	dbErr := s.db.QueryRowContext(r.Context(),
		`SELECT ml.url, mr.id, mr.mailing_id, mr.customer_id FROM mailing_recipients mr
		 JOIN mailing_links ml ON ml.mailing_id = mr.mailing_id
		 WHERE mr.token = $1 AND ml.id = $2`, token, linkID,
	).Scan(&url, &recipientID, &mailingID, &customerID)
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

	// Per-recipient x per-link matrix (interest profiles + future scoring).
	if _, err := s.db.ExecContext(r.Context(),
		`INSERT INTO mailing_clicks (recipient_id, link_id) VALUES ($1, $2)
		 ON CONFLICT (recipient_id, link_id) DO UPDATE SET
		     click_count = mailing_clicks.click_count + 1,
		     last_clicked_at = NOW()`, recipientID, linkID); err != nil {
		log.Printf("click matrix error: %v", err)
	}

	// Clicking inherits the mailing's tags: interest declared by behavior.
	if customerID.Valid {
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT INTO customer_tags (customer_id, tag_id, source)
			 SELECT $1, mt.tag_id, 'click' FROM mailing_tags mt WHERE mt.mailing_id = $2
			 ON CONFLICT DO NOTHING`, customerID.Int64, mailingID); err != nil {
			log.Printf("click tag propagation error: %v", err)
		}
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
	var email string
	err := s.db.QueryRowContext(r.Context(),
		`SELECT customer_id, email FROM mailing_recipients WHERE token=$1`, token).Scan(&customerID, &email)
	if err == sql.ErrNoRows {
		http.Error(w, "invalid token", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("unsub lookup error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Suppress by customer link when present, and always by the recipient's
	// email as well: the row's customer_id may be NULL (customer deleted and
	// possibly re-created since), and the success page below must only be
	// shown if the address really cannot receive further list mail.
	if customerID.Valid {
		if _, err := s.db.ExecContext(r.Context(),
			`UPDATE customers SET unsubscribed_at = COALESCE(unsubscribed_at, NOW()) WHERE id=$1`,
			customerID.Int64); err != nil {
			log.Printf("unsub update error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE customers SET unsubscribed_at = COALESCE(unsubscribed_at, NOW()) WHERE email=$1`,
		strings.ToLower(email)); err != nil {
		log.Printf("unsub update error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
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
	s.testSendFlow(w, r, id, r.FormValue("email"))
}

func (s *server) testSendFlow(w http.ResponseWriter, r *http.Request, id int64, rawEmail string) {
	view := s.adminPath("/mailings/view?id=" + strconv.FormatInt(id, 10))

	email := strings.ToLower(strings.TrimSpace(rawEmail))
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
	RefID     sql.NullInt64 // mailing id for kind="mailing" entries
}

// loadTimeline merges manual activities with mailing deliveries for a customer,
// newest first.
func (s *server) loadTimeline(ctx context.Context, customerID int64) ([]TimelineEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT kind, body, created_by, created_at, NULL::integer AS ref_id
		 FROM activities WHERE customer_id = $1
		 UNION ALL
		 SELECT 'mailing',
		     m.subject || CASE
		         WHEN mr.clicked_at IS NOT NULL THEN ' (clicked)'
		         WHEN mr.opened_at IS NOT NULL THEN ' (opened)'
		         ELSE '' END,
		     m.created_by, mr.sent_at, m.id
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
		if err := rows.Scan(&e.Kind, &e.Body, &e.CreatedBy, &e.CreatedAt, &e.RefID); err != nil {
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
		`SELECT email, name, company, phone, address,
		     (SELECT string_agg(t.name, ',' ORDER BY t.name) FROM customer_tags ct JOIN tags t ON t.id = ct.tag_id WHERE ct.customer_id = customers.id),
		     notes, created_at,
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
		var custID int64
		if err := s.db.QueryRowContext(r.Context(),
			`INSERT INTO customers (email, name, company, phone, address, notes)
			 VALUES ($1, NULLIF($2,''), NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), NULLIF($6,''))
			 ON CONFLICT (email) DO UPDATE SET
			     name = COALESCE(NULLIF(EXCLUDED.name, ''), customers.name),
			     company = COALESCE(NULLIF(EXCLUDED.company, ''), customers.company),
			     phone = COALESCE(NULLIF(EXCLUDED.phone, ''), customers.phone),
			     address = COALESCE(NULLIF(EXCLUDED.address, ''), customers.address),
			     notes = COALESCE(NULLIF(EXCLUDED.notes, ''), customers.notes),
			     updated_at = NOW()
			 RETURNING id`,
			email, field(rec, "name"), field(rec, "company"), field(rec, "phone"),
			field(rec, "address"), field(rec, "notes")).Scan(&custID); err != nil {
			log.Printf("import row error for %s: %v", email, err)
			skipped++
			continue
		}
		if tags := splitTagList(field(rec, "tags")); len(tags) > 0 {
			s.applyTags(r.Context(), custID, tags, "import")
		}
		imported++
	}

	http.Redirect(w, r,
		s.adminPath("/customers?imported="+strconv.Itoa(imported)+"&skipped="+strconv.Itoa(skipped)),
		http.StatusSeeOther)
}

// ---- Tags ------------------------------------------------------------------

type TagChip struct {
	Name   string
	Source string
}

type TagInfo struct {
	ID            int64
	Name          string
	CustomerCount int
	CreatedAt     time.Time
}

// tagNameRe constrains normalized tag names: lowercase alphanumerics with
// single spaces, dashes, underscores or dots between; 1-50 chars.
var tagNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9 ._-]{0,49}$`)

// normalizeTagName lowercases, trims, and collapses whitespace; returns ""
// when the result is not a valid tag name.
func normalizeTagName(raw string) string {
	name := strings.ToLower(strings.Join(strings.Fields(raw), " "))
	if !tagNameRe.MatchString(name) {
		return ""
	}
	return name
}

// splitTagList turns a comma-separated string into normalized tag names,
// dropping invalid entries and duplicates.
func splitTagList(raw string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		name := normalizeTagName(part)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

const maxTagsPerApply = 10

// extractFormTags pulls self-classification tags from a submitted form's
// "tags" field (string or repeated values), normalized and capped.
func extractFormTags(payload map[string]interface{}) []string {
	raw, ok := payload["tags"]
	if !ok {
		return nil
	}
	var parts []string
	switch v := raw.(type) {
	case string:
		parts = strings.Split(v, ",")
	case []string:
		parts = v
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok {
				parts = append(parts, str)
			}
		}
	default:
		return nil
	}
	tags := splitTagList(strings.Join(parts, ","))
	if len(tags) > maxTagsPerApply {
		tags = tags[:maxTagsPerApply]
	}
	return tags
}

// applyTags associates tags (created if missing) with a customer, recording how
// the association was made. Existing associations are left untouched, so a
// manual tag is not downgraded to source=form by a later submission.
func (s *server) applyTags(ctx context.Context, customerID int64, names []string, source string) {
	if len(names) > maxTagsPerApply {
		names = names[:maxTagsPerApply]
	}
	for _, name := range names {
		var tagID int64
		err := s.db.QueryRowContext(ctx,
			`INSERT INTO tags (name) VALUES ($1)
			 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
			 RETURNING id`, name).Scan(&tagID)
		if err != nil {
			log.Printf("tag upsert error for %q: %v", name, err)
			continue
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO customer_tags (customer_id, tag_id, source) VALUES ($1, $2, $3)
			 ON CONFLICT DO NOTHING`, customerID, tagID, source); err != nil {
			log.Printf("customer tag error for %q: %v", name, err)
		}
	}
}

func (s *server) listTagNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM tags ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

func (s *server) customerTagChips(ctx context.Context, customerID int64) ([]TagChip, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT t.name, ct.source FROM customer_tags ct
		 JOIN tags t ON t.id = ct.tag_id
		 WHERE ct.customer_id = $1 ORDER BY t.name`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	chips := []TagChip{}
	for rows.Next() {
		var c TagChip
		if err := rows.Scan(&c.Name, &c.Source); err != nil {
			return nil, err
		}
		chips = append(chips, c)
	}
	return chips, rows.Err()
}

// handleCustomerTag adds or removes a single tag on a customer (chip UI).
func (s *server) handleCustomerTag(w http.ResponseWriter, r *http.Request) {
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
	name := normalizeTagName(r.FormValue("tag"))
	if name == "" {
		http.Error(w, "invalid tag name", http.StatusBadRequest)
		return
	}

	switch r.FormValue("action") {
	case "add":
		s.applyTags(r.Context(), id, []string{name}, "manual")
	case "remove":
		if _, err := s.db.ExecContext(r.Context(),
			`DELETE FROM customer_tags WHERE customer_id=$1 AND tag_id=(SELECT id FROM tags WHERE name=$2)`,
			id, name); err != nil {
			log.Printf("tag remove error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.adminPath("/customers/view?id="+strconv.FormatInt(id, 10)), http.StatusSeeOther)
}

// handleTags is the tag vocabulary admin page: list with usage counts, delete.
func (s *server) handleTags(w http.ResponseWriter, r *http.Request) {
	var flash *passwordFlash
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		switch r.FormValue("action") {
		case "delete":
			id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
			if err != nil {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}
			if _, err := s.db.ExecContext(r.Context(), `DELETE FROM tags WHERE id=$1`, id); err != nil {
				log.Printf("tag delete error: %v", err)
				flash = &passwordFlash{Message: "Unable to delete tag right now", Kind: "error"}
			} else {
				flash = &passwordFlash{Message: "Tag deleted everywhere.", Kind: "success"}
			}
		case "create":
			name := normalizeTagName(r.FormValue("name"))
			if name == "" {
				flash = &passwordFlash{Message: "Tag names are 1-50 chars: lowercase letters, digits, space . _ -", Kind: "error"}
			} else if _, err := s.db.ExecContext(r.Context(),
				`INSERT INTO tags (name) VALUES ($1) ON CONFLICT DO NOTHING`, name); err != nil {
				log.Printf("tag create error: %v", err)
				flash = &passwordFlash{Message: "Unable to create tag right now", Kind: "error"}
			} else {
				flash = &passwordFlash{Message: "Tag “" + name + "” available.", Kind: "success"}
			}
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := s.db.QueryContext(r.Context(),
		`SELECT t.id, t.name, t.created_at,
		    (SELECT COUNT(*) FROM customer_tags ct WHERE ct.tag_id = t.id)
		 FROM tags t ORDER BY t.name`)
	if err != nil {
		log.Printf("tags query error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	tags := []TagInfo{}
	for rows.Next() {
		var t TagInfo
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.CustomerCount); err != nil {
			log.Printf("tags scan error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		tags = append(tags, t)
	}
	if err := rows.Err(); err != nil {
		log.Printf("tags query error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "templates/tags.html", map[string]interface{}{
		"Tags":        tags,
		"Flash":       flash,
		"CSRFToken":   r.Context().Value(ctxKeyCSRF),
		"AdminPrefix": s.adminPrefix,
	})
}

// ---- Click history ---------------------------------------------------------

type ClickEntry struct {
	Subject string
	URL     string
	Count   int
	FirstAt time.Time
	LastAt  time.Time
}

// customerClickHistory lists which mailing links a customer has clicked —
// the raw material for interest profiles and future engagement scoring.
func (s *server) customerClickHistory(ctx context.Context, customerID int64) ([]ClickEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT m.subject, ml.url, mc.click_count, mc.first_clicked_at, mc.last_clicked_at
		 FROM mailing_clicks mc
		 JOIN mailing_recipients mr ON mr.id = mc.recipient_id
		 JOIN mailing_links ml ON ml.id = mc.link_id
		 JOIN mailings m ON m.id = mr.mailing_id
		 WHERE mr.customer_id = $1
		 ORDER BY mc.last_clicked_at DESC LIMIT 100`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []ClickEntry{}
	for rows.Next() {
		var e ClickEntry
		if err := rows.Scan(&e.Subject, &e.URL, &e.Count, &e.FirstAt, &e.LastAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ---- Media (uploaded images for mailings) ----------------------------------

type Media struct {
	ID          int64
	Filename    string
	ContentType string
	CreatedBy   sql.NullString
	CreatedAt   time.Time
	PublicURL   string
}

const maxMediaBytes = 2 << 20 // 2MB per image

var allowedMediaTypes = map[string]struct{}{
	"image/png": {}, "image/jpeg": {}, "image/gif": {}, "image/webp": {},
}

// mediaURL builds the URL recipients (and the editor) use for an image.
// Absolute when PUBLIC_BASE_URL is set — required for images in real mail.
func (s *server) mediaURL(id int64) string {
	return s.publicBaseURL + s.trackPath + "/img?id=" + strconv.FormatInt(id, 10)
}

func (s *server) listMedia(ctx context.Context) ([]Media, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, filename, content_type, created_by, created_at FROM media ORDER BY id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Media{}
	for rows.Next() {
		var m Media
		if err := rows.Scan(&m.ID, &m.Filename, &m.ContentType, &m.CreatedBy, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.PublicURL = s.mediaURL(m.ID)
		items = append(items, m)
	}
	return items, rows.Err()
}

// handleMediaUpload accepts an image upload (multipart, parsed in memory: the
// chroot may have no writable filesystem) or deletes one (action=delete).
func (s *server) handleMediaUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	back := s.adminPath("/mailings")
	if ref := r.Header.Get("Referer"); strings.HasPrefix(ref, s.adminPrefix) {
		back = ref
	}

	ctype := r.Header.Get("Content-Type")
	if !strings.Contains(ctype, "multipart/form-data") {
		// Simple form post: delete action.
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !s.validateCSRFFromCookie(r, csrfCookieName, r.FormValue("csrf_token")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.FormValue("action") != "delete" {
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
		id, err := strconv.ParseInt(r.FormValue("media_id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		if _, err := s.db.ExecContext(r.Context(), `DELETE FROM media WHERE id=$1`, id); err != nil {
			log.Printf("media delete error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMediaBytes+64*1024)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected multipart upload", http.StatusBadRequest)
		return
	}

	var csrfToken, filename string
	var data []byte
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
		case "image":
			filename = part.FileName()
			b, err := io.ReadAll(io.LimitReader(part, maxMediaBytes+1))
			if err != nil {
				http.Error(w, "invalid upload", http.StatusBadRequest)
				return
			}
			if len(b) > maxMediaBytes {
				http.Error(w, "image too large (max 2MB)", http.StatusRequestEntityTooLarge)
				return
			}
			data = b
		default:
			_, _ = io.Copy(io.Discard, part)
		}
	}

	if !s.validateCSRFFromCookie(r, csrfCookieName, csrfToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if len(data) == 0 {
		http.Error(w, "no image uploaded", http.StatusBadRequest)
		return
	}

	// Sniff the real content type; never trust the client's.
	detected := http.DetectContentType(data)
	if _, ok := allowedMediaTypes[detected]; !ok {
		http.Error(w, "unsupported image type (png, jpeg, gif, webp)", http.StatusUnsupportedMediaType)
		return
	}
	if filename == "" {
		filename = "image"
	}
	if len(filename) > 200 {
		filename = filename[:200]
	}

	user, _ := r.Context().Value(ctxKeyUser).(string)
	if _, err := s.db.ExecContext(r.Context(),
		`INSERT INTO media (filename, content_type, data, created_by) VALUES ($1, $2, $3, $4)`,
		filename, detected, data, user); err != nil {
		log.Printf("media insert error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// handleMediaServe is the public image endpoint recipients' mail clients hit.
func (s *server) handleMediaServe(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var ctype string
	var data []byte
	dbErr := s.db.QueryRowContext(r.Context(),
		`SELECT content_type, data FROM media WHERE id=$1`, id).Scan(&ctype, &data)
	if dbErr == sql.ErrNoRows {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if dbErr != nil {
		log.Printf("media serve error: %v", dbErr)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// ---- Preview ---------------------------------------------------------------

// previewFooterMock marks where the unsubscribe link and pixel are appended.
const previewFooterMock = `
<div style="margin-top:28px;padding-top:12px;border-top:1px dashed #cccccc;font-size:12px;color:#888888">
<p><a href="#">Unsubscribe</a> &larr; the unsubscribe link is appended here on send</p>
<p>&#9633; 1&times;1 open-tracking pixel is appended here (invisible in real mail)</p>
</div>`

// handleMailingPreview renders the saved draft body inside a mail-client-like
// shell (light 600px column) so image placement and layout can be checked
// before sending. Framed by the compose page, so frame-ancestors is relaxed
// to same-origin for this response only.
func (s *server) handleMailingPreview(w http.ResponseWriter, r *http.Request) {
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
		log.Printf("preview load error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if m == nil {
		http.Error(w, "mailing not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src * data:; style-src 'unsafe-inline'; frame-ancestors 'self'")

	// Render through the same wrapper used at send time, so the preview is the
	// exact table skeleton recipients get. Full-document bodies (the escape
	// hatch) are shown verbatim, without the placement mock.
	body := m.BodyHTML
	probe := strings.ToLower(body)
	if strings.Contains(probe, "<html") || strings.Contains(probe, "<!doctype") {
		_, _ = io.WriteString(w, body)
		return
	}
	_, _ = io.WriteString(w, wrapEmailLayout(body+previewFooterMock))
}

// ---- Plain-text alternative --------------------------------------------------

var (
	brRe     = regexp.MustCompile(`(?i)<br\s*/?>`)
	pCloseRe = regexp.MustCompile(`(?i)</(p|div|h[1-6]|li|tr|table|ul|ol|blockquote)>`)
	liRe     = regexp.MustCompile(`(?i)<li[^>]*>`)
	aRe      = regexp.MustCompile(`(?is)<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>`)
	imgRe    = regexp.MustCompile(`(?is)<img[^>]*>`)
	tagRe    = regexp.MustCompile(`(?s)<[^>]*>`)
	blankRe  = regexp.MustCompile(`\n{3,}`)
)

// htmlToText derives a readable text/plain rendition of an HTML body: block
// boundaries become newlines, list items become bullets, links become
// "text (url)", images disappear, entities are decoded.
func htmlToText(html string) string {
	t := html
	t = brRe.ReplaceAllString(t, "\n")
	t = liRe.ReplaceAllString(t, "\n  * ")
	t = pCloseRe.ReplaceAllString(t, "\n\n")
	t = aRe.ReplaceAllStringFunc(t, func(m string) string {
		sub := aRe.FindStringSubmatch(m)
		text := strings.TrimSpace(tagRe.ReplaceAllString(sub[2], ""))
		url := sub[1]
		if text == "" || text == url {
			return url
		}
		return text + " (" + url + ")"
	})
	t = imgRe.ReplaceAllString(t, "")
	t = tagRe.ReplaceAllString(t, "")
	t = strings.ReplaceAll(t, "\r", "")
	lines := strings.Split(t, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(strings.TrimLeft(l, " \t"), " \t")
	}
	t = strings.Join(lines, "\n")
	t = blankRe.ReplaceAllString(t, "\n\n")
	return strings.TrimSpace(unescapeEntities(t))
}

// unescapeEntities decodes the entities the editor and common bodies produce.
func unescapeEntities(s string) string {
	replacements := []struct{ from, to string }{
		{"&nbsp;", " "}, {"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"},
		{"&quot;", `"`}, {"&#39;", "'"}, {"&hellip;", "…"}, {"&mdash;", "—"},
		{"&ndash;", "–"}, {"&bull;", "*"},
	}
	for _, r := range replacements {
		s = strings.ReplaceAll(s, r.from, r.to)
	}
	return s
}

// ---- Association queries (the "everything links" layer) ---------------------

// customerLists returns the lists a customer belongs to.
func (s *server) customerLists(ctx context.Context, customerID int64) ([]List, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT l.id, l.name FROM lists l
		 JOIN list_members lm ON lm.list_id = l.id
		 WHERE lm.customer_id = $1 ORDER BY l.name`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	lists := []List{}
	for rows.Next() {
		var l List
		if err := rows.Scan(&l.ID, &l.Name); err != nil {
			return nil, err
		}
		lists = append(lists, l)
	}
	return lists, rows.Err()
}

// listMailings returns mailings targeted at a list.
func (s *server) listMailings(ctx context.Context, listID int64) ([]Mailing, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, subject, status, created_at, sent_at FROM mailings
		 WHERE list_id = $1 ORDER BY created_at DESC LIMIT 50`, listID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Mailing{}
	for rows.Next() {
		var m Mailing
		if err := rows.Scan(&m.ID, &m.Subject, &m.Status, &m.CreatedAt, &m.SentAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
