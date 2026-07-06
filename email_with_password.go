package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strings"
	"time"
)

func (h *Handler) emailLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// `mail.ParseAddress` enforces a syntactically valid address and strips any
	// display name, so we store and match on the bare address.
	parsed, err := mail.ParseAddress(r.PostFormValue("email"))
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	email := strings.ToLower(parsed.Address)

	code, err := h.issueLoginCode(email)
	if err != nil {
		log.Print(err)
		http.Error(w, "Something went wrong. Try again.", http.StatusInternalServerError)
		return
	}

	// The server runs over TLS, so the callback link is https. r.Host carries
	// the host:port the client used.
	link := "https://" + r.Host + "/login/email/" + code

	// Log the link so local development can finish the flow without a real
	// inbox or configured SES credentials.
	log.Printf("email login: link for %s -> %s", email, link)

	if err := h.sendLoginEmail(email, link); err != nil {
		// Non-fatal: the link is in the logs. In production you'd surface this.
		log.Printf("email login: send failed: %v", err)
	}

	renderCheckEmail(w, email)
}

func (h *Handler) emailVerify(w http.ResponseWriter, r *http.Request) {
	identityId, err := h.redeemLoginCode(r.PathValue("code"))
	if err != nil {
		// Unknown, already-used, or empty code. Send them back to the start.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	device := r.UserAgent()
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	session, err := h.CreateSession(identityId, ip, device, time.Hour*24*7)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := h.RecordActivity(identityId, "Logged in via email from "+ip); err != nil {
		log.Print(err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session,
		HttpOnly: true,
		Path:     "/",
	})
	http.Redirect(w, r, "/loggedIn", http.StatusFound)
}

func (h *Handler) sendLoginEmail(to, link string) error {
	if h.mailer == nil {
		return errors.New("mailer not configured")
	}
	return h.mailer.Send(Email{
		To:      to,
		Subject: "Your sign-in link",
		Text:    "Open this link to finish signing in:\n\n" + link + "\n\nIf you didn't request this, you can ignore this email.",
		HTML: `<p>Open this link to finish signing in:</p>` +
			`<p><a href="` + link + `">` + link + `</a></p>` +
			`<p>If you didn't request this, you can ignore this email.</p>`,
	})
}

// loginCodeTTL bounds how long an emailed link stays valid. A short window
// limits the damage if a code leaks after it's sent (inbox, proxy logs) but
// before it's used.
const loginCodeTTL = 15 * time.Minute

// issueLoginCode finds or creates the identity for email, stores a fresh
// one-time code on it, and returns the raw code for the email link.
//
// Only the SHA-256 hash of the code is stored: it's a bearer credential, like a
// session token, so we treat it the way hashToken protects those at rest — a
// database reader can't turn the column back into a working link. The code is
// 16 bytes of CSPRNG output, so a fast unsalted hash is enough (slow, salted
// hashes are for low-entropy passwords, not high-entropy tokens).
//
// Writing the code overwrites any previous one, so only the most recently
// emailed link works.
func (h *Handler) issueLoginCode(email string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)

	tx, err := h.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// Find the existing identity for this email, or create one on first sight.
	var identityId int64
	err = tx.QueryRow("SELECT id FROM identities WHERE email = ?", email).Scan(&identityId)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		name := email
		if i := strings.IndexByte(email, '@'); i > 0 {
			name = email[:i]
		}
		result, err := tx.Exec("INSERT INTO identities (name, email) VALUES (?, ?)", name, email)
		if err != nil {
			return "", err
		}
		if identityId, err = result.LastInsertId(); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	}

	if _, err := tx.Exec(
		"UPDATE identities SET temporary_code = ?, code_expires_at = ? WHERE id = ?",
		hashToken(code), time.Now().Add(loginCodeTTL).Unix(), identityId,
	); err != nil {
		return "", err
	}

	return code, tx.Commit()
}

// redeemLoginCode looks up the identity holding this code, clears it, and
// returns the identity if the code hadn't expired — all in one transaction, so
// a link works at most once even under concurrent requests.
func (h *Handler) redeemLoginCode(code string) (int64, error) {
	if code == "" {
		return 0, errors.New("empty code")
	}
	hashed := hashToken(code)

	tx, err := h.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var identityId int64
	var expiresAt int64
	if err := tx.QueryRow(
		"SELECT id, code_expires_at FROM identities WHERE temporary_code = ?", hashed,
	).Scan(&identityId, &expiresAt); err != nil {
		return 0, err
	}

	// Burn the code keyed on the code itself: a concurrent redeem of the same
	// link matches zero rows once we've cleared it, so exactly one wins.
	result, err := tx.Exec(
		"UPDATE identities SET temporary_code = NULL, code_expires_at = NULL WHERE temporary_code = ?",
		hashed,
	)
	if err != nil {
		return 0, err
	}
	if n, err := result.RowsAffected(); err != nil {
		return 0, err
	} else if n != 1 {
		return 0, errors.New("login code already used")
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	// Check expiry only after the code is spent, so an expired link can't be
	// retried against the same value.
	if time.Now().Unix() >= expiresAt {
		return 0, errors.New("login code expired")
	}

	return identityId, nil
}

func renderCheckEmail(w http.ResponseWriter, email string) {
	fmt.Fprintf(w, `<!doctype html>
	<html>
		<head></head>
		<body>
			<p>Check <strong>%s</strong> for a link to finish signing in.</p>
		</body>
	</html>`, template.HTMLEscapeString(email))
}

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
	Auth smtp.Auth
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

	return &Mailer{
		Host: host,
		Port: port,
		From: from,
		// `PlainAuth` only transmits the password once the connection is
		// encrypted; net/smtp enforces this, see below in `Send`.
		Auth: smtp.PlainAuth("", username, password, host),
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
	//
	// `SendMail` will attempt to use TLS when the server on the other end advertises it.
	return smtp.SendMail(addr, mailer.Auth, mailer.From, []string{email.To}, message)
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

