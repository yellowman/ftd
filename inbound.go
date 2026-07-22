package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"time"
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
	From      string
	Subject   string
	Body      string
	MessageID string // Message-ID header, or a content hash when absent
	Drop      string // non-empty: reason this message should be discarded
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

	// Dedupe key: the Message-ID, or a hash of the raw message when a broken
	// sender omits one. MTA retries after a lost acknowledgment redeliver the
	// same message; this key lets storeReply file it exactly once.
	im.MessageID = strings.Trim(strings.TrimSpace(msg.Header.Get("Message-ID")), "<>")
	if im.MessageID == "" {
		sum := sha256.Sum256(raw)
		im.MessageID = "sha256:" + hex.EncodeToString(sum[:])
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
// customer record (created if new, like form intake). Filing is idempotent on
// the message's dedupe key: a redelivery of an already-stored message is
// acknowledged as success without creating a second to-do, backed by a
// partial unique index so even concurrent redeliveries cannot double-file.
func (s *server) storeReply(ctx context.Context, im *inboundMail) error {
	payload := map[string]interface{}{
		"email":             im.From,
		"_reply_from":       im.From,
		"_reply_subject":    im.Subject,
		"_reply_body":       im.Body,
		"_reply_message_id": im.MessageID,
	}

	customerID := s.linkCustomer(ctx, payload)

	formJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal reply: %w", err)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO submissions (ip_address, user_agent, referer, form_data, customer_id)
		 VALUES (NULL, 'email-reply', NULL, $1, $2)
		 ON CONFLICT ((form_data->>'_reply_message_id'))
		     WHERE user_agent = 'email-reply' AND form_data->>'_reply_message_id' IS NOT NULL
		     DO NOTHING`, formJSON, customerID)
	if err != nil {
		return fmt.Errorf("insert reply: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		log.Printf("duplicate delivery of %s from %s ignored", im.MessageID, im.From)
		return nil
	}
	log.Printf("reply filed from %s (%q)", im.From, im.Subject)
	return nil
}

// errBadMessage marks permanently malformed input: the same bytes will fail
// on every retry, so the MTA must bounce it, not requeue it. Transient errors
// (database unavailable) stay unwrapped and get temporary-failure codes.
var errBadMessage = errors.New("unparseable message")

func (s *server) handleInbound(ctx context.Context, raw []byte) error {
	im, err := parseInboundMail(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", errBadMessage, err)
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
//
// Transient Accept errors (fd exhaustion, aborted connections) must not end
// the loop: the MTA retries deliveries, so the listener has to survive for
// the life of the process. Only a closed listener stops it.
func (s *server) serveLMTP(l net.Listener) {
	var delay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Printf("lmtp listener closed; inbound replies disabled")
				return
			}
			if delay == 0 {
				delay = 100 * time.Millisecond
			} else if delay *= 2; delay > 5*time.Second {
				delay = 5 * time.Second
			}
			log.Printf("lmtp accept error (retrying in %v): %v", delay, err)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go s.lmtpSession(conn)
	}
}

// lmtpMaxLine bounds a single protocol or content line (RFC 5321 allows 998
// content chars; the headroom tolerates sloppy senders). Memory per session is
// bounded per line and per message — deliberately not per connection: the MTA
// reuses one session for many deliveries, so a connection-lifetime cap would
// start failing healthy deliveries once enough cumulative bytes had passed.
const lmtpMaxLine = 4096

// readLMTPLine reads one newline-terminated line, retaining at most max bytes.
// An overlong line is consumed to its end (keeping the protocol in sync) and
// reported via tooLong so the caller can refuse it cleanly.
func readLMTPLine(r *bufio.Reader, max int) (line string, tooLong bool, err error) {
	var b strings.Builder
	for {
		frag, err := r.ReadSlice('\n')
		if len(frag) > 0 {
			if b.Len() < max {
				n := max - b.Len()
				if n > len(frag) {
					n = len(frag)
				}
				b.Write(frag[:n])
				if n < len(frag) {
					tooLong = true
				}
			} else {
				tooLong = true
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return b.String(), tooLong, err
	}
}

func (s *server) lmtpSession(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReaderSize(conn, lmtpMaxLine)
	w := bufio.NewWriter(conn)
	say := func(line string) {
		_, _ = w.WriteString(line + "\r\n")
		_ = w.Flush()
	}

	say("220 ftd LMTP ready")
	rcpts := 0
	for {
		line, tooLong, err := readLMTPLine(r, lmtpMaxLine)
		if err != nil {
			return
		}
		if tooLong {
			say("500 5.5.2 line too long")
			continue
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
			overflow := false
			for {
				dl, lineTooLong, err := readLMTPLine(r, lmtpMaxLine)
				if err != nil {
					return
				}
				if lineTooLong {
					// Content line beyond RFC limits: refuse the message but
					// keep consuming to the terminating dot.
					overflow = true
					continue
				}
				trimmed := strings.TrimRight(dl, "\r\n")
				if trimmed == "." {
					break
				}
				// Dot-unstuffing per RFC 5321 §4.5.2: any non-terminator line
				// whose first character is a period loses that period —
				// regardless of the second character, not only "..".
				if len(trimmed) > 1 && trimmed[0] == '.' {
					trimmed = trimmed[1:]
				}
				if b.Len()+len(trimmed) < maxInboundBytes {
					b.WriteString(trimmed + "\r\n")
				} else {
					// Keep consuming to the terminating dot so the protocol
					// stays in sync, but the message must be refused: storing
					// a silently truncated (possibly mid-MIME) reply while
					// telling the MTA "delivered" would lose content.
					overflow = true
				}
			}
			if overflow {
				log.Printf("lmtp: message exceeds %d bytes; refused", maxInboundBytes)
				for i := 0; i < rcpts; i++ {
					say("552 5.3.4 message exceeds size limit")
				}
				rcpts = 0
				continue
			}
			err := s.handleInbound(context.Background(), []byte(b.String()))
			// LMTP: one status line per accepted RCPT. Permanent errors get a
			// 5xx so the MTA bounces instead of retrying forever; transient
			// (database) errors get 451 and a later retry succeeds.
			for i := 0; i < rcpts; i++ {
				switch {
				case err == nil:
					say("250 2.0.0 delivered")
				case errors.Is(err, errBadMessage):
					log.Printf("lmtp delivery rejected: %v", err)
					say("554 5.6.0 message cannot be parsed")
				default:
					log.Printf("lmtp delivery error: %v", err)
					say("451 4.3.0 temporary failure")
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

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxInboundBytes+1))
	if err != nil {
		log.Printf("deliver: read stdin: %v", err)
		return exTempFail
	}
	if len(raw) == 0 {
		log.Print("deliver: empty message")
		return exUnavailable
	}
	if len(raw) > maxInboundBytes {
		// Refuse rather than store a silently truncated message; permanent
		// failure so Postfix bounces instead of retrying forever.
		log.Printf("deliver: message exceeds %d bytes; refused", maxInboundBytes)
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
		if errors.Is(err, errBadMessage) {
			// Permanently malformed: bounce, don't requeue.
			return exUnavailable
		}
		return exTempFail
	}
	return 0
}
