package main

// DNS deliverability check for submitted email addresses: does the domain
// have an MX record, or failing that an A/AAAA record (the implicit MX of
// RFC 5321)? Submissions are stored either way; a failed check only flags
// the row and warns the submitter.
//
// The inputs here are hostile on both sides. The domain comes straight from
// form input, so it is validated against hostname syntax before it is passed
// to the resolver or written to a log. The DNS answers come from whoever
// runs the domain's nameservers, so their contents are never stored, echoed,
// or connected to — the only facts used are "records exist" and the RFC 7505
// null-MX marker ("MX 0 ."), which declares the domain accepts no mail.
// Lookup volume is bounded by the submission rate limit.
//
// The daemon chroots after startup, which breaks Go's usual resolver (it
// re-reads /etc/resolv.conf, gone inside the chroot). The nameservers are
// therefore captured once at startup, while the file is still visible, and
// every query dials those addresses directly.

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const emailCheckTimeout = 3 * time.Second

type emailVerdict int

const (
	emailOK emailVerdict = iota // domain resolves; no warning
	// emailInvalid means the address cannot receive mail: syntactically
	// impossible (malformed domain, bad IP literal), or the domain
	// authoritatively does not exist (NXDOMAIN/NODATA), or it publishes a
	// null MX. Syntax failures flag without a DNS query — they are stronger
	// evidence of undeliverability than a missing record.
	emailInvalid
	emailUnknown // no email, DNS trouble, or checker disabled
)

type emailChecker struct {
	resolver *net.Resolver
	next     atomic.Uint32 // rotates across nameservers
}

// newEmailChecker must run before chroot/privilege drop so /etc/resolv.conf
// is still readable. With no usable nameservers the check is disabled (nil
// checker) and every verdict is emailUnknown.
func newEmailChecker() *emailChecker {
	servers := parseResolvConf("/etc/resolv.conf")
	if len(servers) == 0 {
		log.Printf("email DNS check disabled: no nameservers in /etc/resolv.conf")
		return nil
	}

	c := &emailChecker{}
	c.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Ignore the address Go derived from its own (post-chroot,
			// possibly bogus) config; use the servers captured at startup.
			server := servers[int(c.next.Add(1))%len(servers)]
			d := net.Dialer{Timeout: emailCheckTimeout}
			return d.DialContext(ctx, network, server)
		},
	}
	log.Printf("email DNS check enabled via %s", strings.Join(servers, ", "))
	return c
}

// parseResolvConf extracts nameserver addresses; anything that does not
// parse as an IP literal is ignored.
func parseResolvConf(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(fields[1]); ip != nil {
				servers = append(servers, net.JoinHostPort(ip.String(), "53"))
			}
		}
		if len(servers) == 3 {
			break
		}
	}
	return servers
}

// verdict classifies the deliverability of an email address by its domain.
// The syntax half runs even with DNS disabled (nil receiver): a malformed
// address needs no lookup to be undeliverable.
func (c *emailChecker) verdict(ctx context.Context, email string) emailVerdict {
	at := strings.LastIndexByte(email, '@')
	if at < 1 || at == len(email)-1 {
		return emailInvalid
	}
	domain := email[at+1:]

	// Bracketed address literals (user@[192.0.2.1], user@[IPv6:...]) are
	// legal per RFC 5321 and need no lookup: valid IP or nothing.
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		lit := strings.TrimPrefix(domain[1:len(domain)-1], "IPv6:")
		if net.ParseIP(lit) != nil {
			return emailOK
		}
		return emailInvalid
	}

	// Internationalized domains would need punycode conversion to check;
	// skip them rather than mis-flag a real address.
	for i := 0; i < len(domain); i++ {
		if domain[i] >= 0x80 {
			return emailUnknown
		}
	}

	domain = strings.TrimSuffix(domain, ".")
	if !validMailDomain(domain) {
		return emailInvalid
	}

	if c == nil {
		return emailUnknown // syntax passed; DNS half is disabled
	}

	ctx, cancel := context.WithTimeout(ctx, emailCheckTimeout)
	defer cancel()

	mxs, err := c.resolver.LookupMX(ctx, domain)
	if err == nil {
		real := 0
		for _, mx := range mxs {
			if strings.TrimSuffix(strings.TrimSpace(mx.Host), ".") != "" {
				real++
			}
		}
		if real > 0 {
			return emailOK
		}
		if len(mxs) > 0 {
			return emailInvalid // null MX: the domain declares it takes no mail
		}
		// err == nil with no records: fall through to the implicit MX.
	} else if !isDNSNotFound(err) {
		return emailUnknown // SERVFAIL/timeout is our problem, not the visitor's
	}

	addrs, err := c.resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		if isDNSNotFound(err) {
			return emailInvalid
		}
		return emailUnknown
	}
	if len(addrs) > 0 {
		return emailOK
	}
	return emailInvalid
}

func isDNSNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// validMailDomain enforces hostname syntax (RFC 1035 labels) so only clean,
// bounded ASCII names reach the resolver and the logs.
func validMailDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
