package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"

	email "github.com/ymfpfp/user-auth/email"
)

func emailMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func (w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

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
	})
	mux.HandleFunc("/{code}", func (w http.ResponseWriter, r *http.Request) {
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

		session, err := h.createSession(identityId, ip, device, time.Hour*24*7)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := h.recordActivity(identityId, "Logged in via email from "+ip); err != nil {
			log.Print(err)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    session,
			HttpOnly: true,
			Path:     "/",
		})
		http.Redirect(w, r, "/loggedIn", http.StatusFound)
	})

	return mux
}

func (h *Handler) sendLoginEmail(to, link string) error {
	if h.mailer == nil {
		return errors.New("mailer not configured")
	}
	return h.mailer.Send(email.Email{
		To: to,
		Subject: "Your sign-in link",
		Text: "Open this link to finish signing in:\n\n" + link + "\n\nIf you didn't request this, you can ignore this email.",
		// todo(jc): Replace this with a template?
		HTML: `<p>Open this link to finish signing in:</p>` +
			`<p><a href="` + link + `">` + link + `</a></p>` +
			`<p>If you didn't request this, you can ignore this email.</p>`,
	})
}

func (h *Handler) issueLoginCode(email string) (string, error) {
	code, err := randomToken()
	if err != nil {
		return "", err
	}

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
		hashToken(code), time.Now().Add(temporaryCodeTTL).Unix(), identityId,
	); err != nil {
		return "", err
	}

	return code, tx.Commit()
}

// redeemLoginCode looks up the identity holding this code, clears it, and
// returns the identity if the code hadn't expired — all in one transaction, so
// a link works at most once even under concurrent requests.
func (h *Handler) redeemLoginCode(code string) (string, error) {
	if code == "" {
		return "", errors.New("empty code")
	}
	hashed := hashToken(code)

	tx, err := h.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var identityId string
	var expiresAt int64
	if err := tx.QueryRow(
		"SELECT id, code_expires_at FROM identities WHERE temporary_code = ?", hashed,
	).Scan(&identityId, &expiresAt); err != nil {
		return "", err
	}

	// Prevent concurrent attempts.
	result, err := tx.Exec(
		"UPDATE identities SET temporary_code = NULL, code_expires_at = NULL WHERE temporary_code = ?",
		hashed,
	)
	if err != nil {
		return "", err
	}
	if n, err := result.RowsAffected(); err != nil {
		return "", err
	} else if n != 1 {
		return "", errors.New("login code already used")
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	// Check expiry only after the code is spent, so an expired link can't be
	// retried against the same value.
	if time.Now().Unix() >= expiresAt {
		return "", errors.New("login code expired")
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

