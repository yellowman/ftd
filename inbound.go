package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
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

	"github.com/lib/pq"
)

// Inbound mail handling: customer replies to mailings (or any mail routed to
// ftd by the MTA) are filed as submissions — to-do items in the inbox, linked
// to the sender's customer record. Two Postfix-native entry points share this
// code: the LMTP listener (transport_maps -> lmtp:unix:/...) and the
// `ftd -deliver` helper (aliases/pipe: one message on stdin per invocation).

const (
	maxInboundBytes  = 1 << 20 // whole message cap
	maxReplyBodySize = 8000    // stored body excerpt
	maxThreadRefs    = 20      // In-Reply-To/References ids considered per message
	// Follow-ups appended to one to-do before overflow files a fresh to-do
	// instead, bounding a single row's growth.
	maxAppendedReplies = 100
)

type inboundMail struct {
	From      string
	Subject   string
	Body      string
	MessageID string   // Message-ID header, or a content hash when absent
	Refs      []string // message IDs this mail answers (In-Reply-To + References)
	Drop      string   // non-empty: reason this message should be discarded
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

	// The thread this mail belongs to: In-Reply-To names the direct parent,
	// References the whole ancestor chain. storeReply matches these against
	// message IDs ftd has sent or received to find the to-do being answered.
	seen := map[string]bool{}
	for _, header := range []string{msg.Header.Get("In-Reply-To"), msg.Header.Get("References")} {
		for _, id := range parseMsgIDList(header) {
			if !seen[id] && len(im.Refs) < maxThreadRefs {
				seen[id] = true
				im.Refs = append(im.Refs, id)
			}
		}
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

// parseMsgIDList splits a References/In-Reply-To header into bare message IDs
// (angle brackets stripped), skipping anything too long or non-id-shaped.
func parseMsgIDList(header string) []string {
	var ids []string
	for _, field := range strings.Fields(header) {
		id := strings.Trim(field, "<>")
		if id != "" && len(id) <= 256 {
			ids = append(ids, id)
		}
	}
	return ids
}

// repliesArraySQL yields a submission's appended-replies array, or an empty
// array when the key is absent — or is not an array at all, which a hostile
// form post could arrange by submitting a field named "_replies" (form fields
// become JSONB keys verbatim; an unguarded jsonb_array_elements over a scalar
// would make every inbound delivery error out permanently).
const repliesArraySQL = `(CASE WHEN jsonb_typeof(form_data->'_replies') = 'array'
    THEN form_data->'_replies' ELSE '[]'::jsonb END)`

// replyAlreadyFiled reports whether a message ID is already in the inbox in
// either form: as the root of a to-do created from a reply, or appended to a
// to-do as a follow-up. Roots are also guarded by the partial unique index,
// but appended follow-ups leave no indexed row, so MTA redeliveries need this
// explicit check.
func (s *server) replyAlreadyFiled(ctx context.Context, msgID string) (bool, error) {
	var dup bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (
		     SELECT 1 FROM submissions
		     WHERE (user_agent = 'email-reply' AND form_data->>'_reply_message_id' = $1)
		        OR EXISTS (SELECT 1 FROM jsonb_array_elements(`+repliesArraySQL+`) e
		                   WHERE e->>'message_id' = $1))`, msgID).Scan(&dup)
	return dup, err
}

type replyTarget struct {
	id         int64
	customerID sql.NullInt64
}

// findReplyTarget resolves which to-do a reply answers, from the message IDs
// in its In-Reply-To/References. Candidates come from two directions:
// operator-sent messages (sent_emails records the Message-ID stamped on each
// outgoing reply, and which submission it answered) and thread siblings — a
// to-do created from an earlier inbound message, or one already carrying a
// referenced message as a follow-up. A long thread can reference several
// to-dos (an archived original plus the fresh to-do its later follow-up
// opened), so all candidates are ranked together: non-archived first — the
// conversation keeps flowing into the live item — then sent-mail matches over
// siblings, newest first.
func (s *server) findReplyTarget(ctx context.Context, refs []string) (*replyTarget, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	var t replyTarget
	err := s.db.QueryRowContext(ctx,
		`SELECT id, customer_id FROM (
		     SELECT sub.id, sub.customer_id, sub.status, 1 AS src, se.id AS recency
		     FROM sent_emails se JOIN submissions sub ON sub.id = se.submission_id
		     WHERE se.message_id = ANY($1)
		   UNION ALL
		     SELECT id, customer_id, status, 2 AS src, id AS recency
		     FROM submissions
		     WHERE form_data->>'_reply_message_id' = ANY($1)
		        OR EXISTS (SELECT 1 FROM jsonb_array_elements(`+repliesArraySQL+`) e
		                   WHERE e->>'message_id' = ANY($1))
		 ) candidates
		 ORDER BY (status = 'archived'), src, recency DESC LIMIT 1`,
		pq.Array(refs)).Scan(&t.id, &t.customerID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reply target lookup: %w", err)
	}
	return &t, nil
}

// appendReply files a follow-up onto an existing to-do and pulls a completed
// item back to 'new' so it resurfaces in the active inbox. The guards make it
// decline — returning false, with the caller deciding what happens instead —
// when the to-do was archived meanwhile, the follow-up cap is reached, or a
// concurrent redelivery already appended this same message.
func (s *server) appendReply(ctx context.Context, subID int64, im *inboundMail) (bool, error) {
	entry, err := json.Marshal([]map[string]interface{}{{
		"from":        im.From,
		"subject":     im.Subject,
		"body":        im.Body,
		"message_id":  im.MessageID,
		"received_at": time.Now().UTC().Format(time.RFC3339),
	}})
	if err != nil {
		return false, fmt.Errorf("marshal follow-up: %w", err)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE submissions
		 SET form_data = jsonb_set(form_data, '{_replies}', `+repliesArraySQL+` || $2::jsonb),
		     status = CASE WHEN status = 'complete' THEN 'new' ELSE status END
		 WHERE id = $1 AND status <> 'archived'
		   AND jsonb_array_length(`+repliesArraySQL+`) < $3
		   AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(`+repliesArraySQL+`) e
		                   WHERE e->>'message_id' = $4)`,
		subID, string(entry), maxAppendedReplies, im.MessageID)
	if err != nil {
		return false, fmt.Errorf("append reply: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// storeReply files an inbound message as a to-do. When its thread headers
// identify an existing to-do of the same customer, the message is appended
// there as a follow-up instead of opening a duplicate — reopening the to-do
// ('complete' goes back to 'new') since the customer is clearly not done with
// it. An archived to-do stays archived: the follow-up becomes a fresh to-do.
// Otherwise the message becomes a new submission linked to the sender's
// customer record (created if new, like form intake).
//
// Filing is idempotent on the message's dedupe key: a redelivery of an
// already-stored message is acknowledged as success without filing twice,
// backed by the up-front check (both filing forms), the appendReply
// message-id guard, and — for new-row inserts — a partial unique index that
// holds even under concurrent redeliveries.
func (s *server) storeReply(ctx context.Context, im *inboundMail) error {
	dup, err := s.replyAlreadyFiled(ctx, im.MessageID)
	if err != nil {
		return fmt.Errorf("reply dedupe check: %w", err)
	}
	if dup {
		log.Printf("duplicate delivery of %s from %s ignored", im.MessageID, im.From)
		return nil
	}

	payload := map[string]interface{}{
		"email":             im.From,
		"_reply_from":       im.From,
		"_reply_subject":    im.Subject,
		"_reply_body":       im.Body,
		"_reply_message_id": im.MessageID,
	}

	customerID := s.linkCustomer(ctx, payload)

	target, err := s.findReplyTarget(ctx, im.Refs)
	if err != nil {
		return err
	}
	// Append only when the sender resolves to the same customer the to-do
	// belongs to: thread headers are sender-controlled, so a matching
	// References line alone must not let one customer's mail land inside
	// another's to-do. A mismatch simply files a fresh to-do.
	if target != nil && customerID.Valid && target.customerID.Valid && customerID.Int64 == target.customerID.Int64 {
		appended, err := s.appendReply(ctx, target.id, im)
		if err != nil {
			return err
		}
		if appended {
			log.Printf("reply from %s (%q) appended to submission #%d", im.From, im.Subject, target.id)
			return nil
		}
		// Declined: archived meanwhile, cap reached, or a concurrent delivery
		// of this same message won the append. Re-check before filing fresh
		// so the last case doesn't double-file.
		if dup, err := s.replyAlreadyFiled(ctx, im.MessageID); err != nil {
			return fmt.Errorf("reply dedupe recheck: %w", err)
		} else if dup {
			log.Printf("duplicate delivery of %s from %s ignored", im.MessageID, im.From)
			return nil
		}
	}

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
