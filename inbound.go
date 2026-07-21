package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"os"
	"strings"
)

// Inbound mail handling: customer replies to mailings (or any mail routed to
// ftd by the MTA) are filed as submissions — to-do items in the inbox, linked
// to the sender's customer record. Two Postfix-native entry points share this
// code: the LMTP listener (transport_maps -> lmtp:unix:/...) and the
// `ftd -deliver` helper (aliases/pipe: one message on stdin per invocation).

const (
	maxInboundBytes  = 1 << 20 // whole message cap
	maxReplyBodySize = 8000    // stored body excerpt
)

type inboundMail struct {
	From    string
	Subject string
	Body    string
	Drop    string // non-empty: reason this message should be discarded
}

// decodeCTE wraps a part reader according to its Content-Transfer-Encoding.
func decodeCTE(r io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	default:
		return r
	}
}

// findTextPart walks a MIME tree (depth-limited) and returns the best text
// rendition: the first text/plain part, else the first text/html converted to
// text, else the raw body.
func findTextPart(contentType, cte string, body io.Reader, depth int) string {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "text/plain"
	}

	if strings.HasPrefix(mediaType, "multipart/") && depth < 4 {
		boundary := params["boundary"]
		if boundary == "" {
			return ""
		}
		mr := multipart.NewReader(body, boundary)
		htmlFallback := ""
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			partType := strings.ToLower(part.Header.Get("Content-Type"))
			text := findTextPart(part.Header.Get("Content-Type"),
				part.Header.Get("Content-Transfer-Encoding"), part, depth+1)
			switch {
			case strings.HasPrefix(partType, "multipart/"):
				// A nested container (e.g. multipart/alternative inside
				// multipart/mixed) already picked its best rendition in the
				// recursive call — use it.
				if strings.TrimSpace(text) != "" {
					return text
				}
			case strings.HasPrefix(partType, "text/plain"), partType == "":
				if strings.TrimSpace(text) != "" {
					return text
				}
			case strings.HasPrefix(partType, "text/html"):
				if htmlFallback == "" {
					htmlFallback = text
				}
			}
		}
		return htmlFallback
	}

	data, err := io.ReadAll(io.LimitReader(decodeCTE(body, cte), maxInboundBytes))
	if err != nil {
		return ""
	}
	if strings.HasPrefix(mediaType, "text/html") {
		return htmlToText(string(data))
	}
	if strings.HasPrefix(mediaType, "text/") || mediaType == "" {
		return string(data)
	}
	return ""
}

// parseInboundMail extracts sender, subject, and a text body from a raw
// RFC 5322 message, flagging auto-generated mail for discard.
func parseInboundMail(raw []byte) (*inboundMail, error) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	im := &inboundMail{}

	if addr, err := mail.ParseAddress(msg.Header.Get("From")); err == nil {
		im.From = strings.ToLower(addr.Address)
	}
	if im.From == "" {
		im.Drop = "no parseable From address"
	} else if strings.Contains(im.From, "mailer-daemon") || strings.HasPrefix(im.From, "postmaster@") {
		im.Drop = "bounce/postmaster sender"
	}
	if as := strings.ToLower(strings.TrimSpace(msg.Header.Get("Auto-Submitted"))); as != "" && as != "no" {
		im.Drop = "auto-submitted: " + as
	}

	dec := mime.WordDecoder{}
	if subj, err := dec.DecodeHeader(msg.Header.Get("Subject")); err == nil {
		im.Subject = subj
	} else {
		im.Subject = msg.Header.Get("Subject")
	}

	body := findTextPart(msg.Header.Get("Content-Type"),
		msg.Header.Get("Content-Transfer-Encoding"), msg.Body, 0)
	body = strings.TrimSpace(strings.ReplaceAll(body, "\r\n", "\n"))
	if len(body) > maxReplyBodySize {
		body = body[:maxReplyBodySize] + "\n[truncated]"
	}
	im.Body = body

	return im, nil
}

// storeReply files an inbound message as a submission linked to the sender's
// customer record (created if new, like form intake).
func (s *server) storeReply(ctx context.Context, im *inboundMail) error {
	payload := map[string]interface{}{
		"email":          im.From,
		"_reply_from":    im.From,
		"_reply_subject": im.Subject,
		"_reply_body":    im.Body,
	}

	customerID := s.linkCustomer(ctx, payload)

	formJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal reply: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO submissions (ip_address, user_agent, referer, form_data, customer_id)
		 VALUES (NULL, 'email-reply', NULL, $1, $2)`, formJSON, customerID); err != nil {
		return fmt.Errorf("insert reply: %w", err)
	}
	log.Printf("reply filed from %s (%q)", im.From, im.Subject)
	return nil
}

func (s *server) handleInbound(ctx context.Context, raw []byte) error {
	im, err := parseInboundMail(raw)
	if err != nil {
		return err
	}
	if im.Drop != "" {
		log.Printf("inbound mail discarded (%s)", im.Drop)
		return nil
	}
	return s.storeReply(ctx, im)
}

// ---- LMTP listener ----------------------------------------------------------

// serveLMTP accepts deliveries from the MTA on a unix socket. Minimal LMTP:
// enough for a local Postfix/OpenSMTPD delivery agent, not the open internet —
// the socket's filesystem permissions are the access control.
func (s *server) serveLMTP(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("lmtp accept error: %v", err)
			return
		}
		go s.lmtpSession(conn)
	}
}

func (s *server) lmtpSession(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(io.LimitReader(conn, 4*maxInboundBytes))
	w := bufio.NewWriter(conn)
	say := func(line string) {
		_, _ = w.WriteString(line + "\r\n")
		_ = w.Flush()
	}

	say("220 ftd LMTP ready")
	rcpts := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "LHLO"):
			say("250-ftd")
			say("250-8BITMIME")
			say("250 SIZE " + fmt.Sprint(maxInboundBytes))
		case strings.HasPrefix(cmd, "MAIL FROM"):
			say("250 2.1.0 ok")
		case strings.HasPrefix(cmd, "RCPT TO"):
			rcpts++
			say("250 2.1.5 ok")
		case cmd == "DATA":
			if rcpts == 0 {
				say("503 5.5.1 no recipients")
				continue
			}
			say("354 go ahead")
			var b strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				trimmed := strings.TrimRight(dl, "\r\n")
				if trimmed == "." {
					break
				}
				// Dot-unstuffing per RFC 5321 §4.5.2.
				if strings.HasPrefix(trimmed, "..") {
					trimmed = trimmed[1:]
				}
				if b.Len()+len(trimmed) < maxInboundBytes {
					b.WriteString(trimmed + "\r\n")
				}
			}
			err := s.handleInbound(context.Background(), []byte(b.String()))
			// LMTP: one status line per accepted RCPT.
			for i := 0; i < rcpts; i++ {
				if err != nil {
					log.Printf("lmtp delivery error: %v", err)
					say("451 4.3.0 temporary failure")
				} else {
					say("250 2.0.0 delivered")
				}
			}
			rcpts = 0
		case cmd == "RSET" || cmd == "NOOP":
			rcpts = 0
			say("250 2.0.0 ok")
		case cmd == "QUIT":
			say("221 2.0.0 bye")
			return
		default:
			say("500 5.5.2 unrecognized")
		}
	}
}

// ---- `ftd -deliver` helper --------------------------------------------------

// Postfix-compatible sysexits.
const (
	exTempFail    = 75 // EX_TEMPFAIL: postfix requeues and retries
	exUnavailable = 69 // EX_UNAVAILABLE: permanent failure
)

// runDeliver is the `ftd -deliver` entry point: read one message from stdin,
// file it, exit. Exit codes follow sysexits so Postfix requeues on transient
// database problems instead of bouncing.
func runDeliver(configFile string) int {
	loadConfigFile(configFile)

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Print("deliver: DATABASE_URL not set")
		return exTempFail
	}

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxInboundBytes))
	if err != nil {
		log.Printf("deliver: read stdin: %v", err)
		return exTempFail
	}
	if len(raw) == 0 {
		log.Print("deliver: empty message")
		return exUnavailable
	}

	db, err := openDB(dbURL)
	if err != nil {
		log.Printf("deliver: database: %v", err)
		return exTempFail
	}
	defer db.Close()

	s := &server{db: db}
	if err := s.handleInbound(context.Background(), raw); err != nil {
		log.Printf("deliver: %v", err)
		return exTempFail
	}
	return 0
}
