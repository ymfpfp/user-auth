package main

import (
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	email "github.com/ymfpfp/user-auth/email"
)

func emailMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

		link := url.URL{
			Scheme: "https",
			Host:   r.Host,
			Path:   "/login/email/" + code,
		}

		if err := h.sendLoginEmail(email, link.String()); err != nil {
			// todo(jc): Non-fatal: the link is in the logs. In production you'd surface this.
			log.Printf("email login: send failed: %v", err)
			setCookie(
				w,
				"flash",
				"Something went wrong. Try again.",
			)
		} else {
			// "Flash" a message.
			setCookie(
				w,
				"flash",
				"Check your email "+email+" for a login code.",
			)
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("/{code}", func(w http.ResponseWriter, r *http.Request) {
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

		session, err := h.createSession(identityId, ip, device)
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
		To:      to,
		Subject: "Your sign-in link",
		Text:    "Open this link to finish signing in:\n\n" + link + "\n\nIf you didn't request this, you can ignore this email.",
		// todo(jc): Replace this with a template?
		HTML: `<p>Open this link to finish signing in:</p>` +
			`<p><a href="` + link + `">` + link + `</a></p>` +
			`<p>If you didn't request this, you can ignore this email.</p>`,
	})
}

func (h *Handler) issueLoginCode(email string) (string, error) {
	var identityId string
	err := h.db.QueryRow("SELECT uuid FROM identities WHERE email = ?", email).Scan(&identityId)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// First time using this email, create a new account.
		name := email
		if i := strings.IndexByte(email, '@'); i > 0 {
			name = email[:i]
		}
		identityId, err = h.createIdentity(name, email)
		if err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	}

	code, err := h.newTemporaryCode(identityId, emailPurpose)
	if err != nil {
		return "", err
	}
	return code, nil
}

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

	temporaryCode, err := getTemporaryCodeWithTx(tx, hashed, emailPurpose)
	if err != nil {
		return "", err
	}

	err = deleteTemporaryCodeWithTx(tx, temporaryCode.Id)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	// Check expiry only after the code is spent, so an expired link can't be
	// retried against the same value.
	if time.Now().Unix() >= temporaryCode.ExpiresAt {
		return "", errors.New("login code expired")
	}

	return temporaryCode.IdentityId, nil
}
