package email

import (
	"fmt"
	"mime/multipart"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"
)

// Send mail with Amazon SES.
//
// Besides DKIM, SES also takes care of SPF (Sender Policy Framework): TXT record
// that allows you to list what servers are allowed to send mail with given domain from.
// (This is with their servers.)
//
// Also, the holy trinity of email trust is DMARC
// (Domain-based Message Authentication, Reporting, and Conformance).
// Basically TXT record with policy for what should happen to emails that claim to be
// from your domain but aren't (per DKIM and SPF), e.g. place in spam.
type Mailer struct {
	Host string // SES SMTP endpoint
	Port string
	// SES verifies the `From` domain by you proving that you are able to publish
	// CNAME record pointing to their servers. On their servers, emails are signed
	// with their DKIM (DomainKeys Identified Mail).
	//
	// DKIM works because SES is able to publish TXT record with the public key,
	// and receivers can use the public key to check that the email was not modified
	// and sent by the service claiming to send it.
	From string
	Auth Auth
}

func NewSESMailerFromEnv() *Mailer {
	host := os.Getenv("SES_SMTP_HOST")
	if host == "" {
		host = "email-smtp.us-east-1.amazonaws.com"
	}
	port := os.Getenv("SES_SMTP_PORT")
	if port == "" {
		port = "587"
	}

	// Actually just the Access Key ID and Secret Access Key.
	username := os.Getenv("SES_SMTP_USERNAME")
	password := os.Getenv("SES_SMTP_PASSWORD")
	from := os.Getenv("SES_FROM_ADDRESS")
	// todo(jc): Invalid if any of these are empty.

	return &Mailer{
		Host: host,
		Port: port,
		From: from,
		// `PlainAuth` only transmits the password once the connection is
		// encrypted; net/smtp enforces this, see below in `Send`.
		Auth: Auth{Username: username, Password: password},
	}
}

type Email struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// net/smtp's `SendMail` opens the connection, upgrades it with STARTTLS
// when the server advertises it (SES always does on 587), authenticates, and sends.
func (mailer *Mailer) Send(email Email) error {
	message, err := mailer.buildMessage(email)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(mailer.Host, mailer.Port)
	// The last arg is the envelope-recipient list; SES uses it for actual
	// routing, independent of `To`. This is how CC/BCC works.
	return SendMail(addr, mailer.Auth, mailer.From, []string{email.To}, message)
}

// Assemble a RFC 5322, or Internet Message Format (IMF) message.
func (mailer *Mailer) buildMessage(email Email) ([]byte, error) {
	var b strings.Builder
	writeHeader := func(k, v string) {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	normalizeCRLF := func(s string) string {
		s = strings.ReplaceAll(s, "\r\n", "\n")
		return strings.ReplaceAll(s, "\n", "\r\n")
	}

	writeHeader("From", mailer.From)
	writeHeader("To", email.To)
	writeHeader("Subject", email.Subject)
	writeHeader("Date", time.Now().Format(time.RFC1123Z))
	writeHeader("MIME-Version", "1.0")

	if email.HTML == "" {
		writeHeader("Content-Type", `text/plain; charset="UTF-8"`)
		b.WriteString("\r\n")
		b.WriteString(normalizeCRLF(email.Text))
		return []byte(b.String()), nil
	}

	// MIME (Multipurpose Internet Mail Extensions) lets one message carry
	// multiple alternative representations of the same content. multipart.Writer
	// picks a random, collision-resistant boundary for us.
	mw := multipart.NewWriter(&b)
	writeHeader("Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
	b.WriteString("\r\n")

	// Order matters: least-preferred (plain) first, most-preferred (HTML) last.
	// Clients render the last part they can display.
	part := func(contentType, body string) error {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type": {contentType},
		})
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(normalizeCRLF(body)))
		return err
	}

	if err := part(`text/plain; charset="UTF-8"`, email.Text); err != nil {
		return nil, err
	}
	if err := part(`text/html; charset="UTF-8"`, email.HTML); err != nil {
		return nil, err
	}

	// Close writes the terminating --boundary-- delimiter.
	if err := mw.Close(); err != nil {
		return nil, err
	}

	return []byte(b.String()), nil
}
