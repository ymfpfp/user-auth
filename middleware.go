package main

import (
	"context"
	"io"
	"net/http"
)

func clearCookies(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		http.SetCookie(w, &http.Cookie{
			Name:     cookie.Name,
			Value:    "",
			HttpOnly: true,
			MaxAge:   -1,
			Path:     "/",
			// Secure: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func drainAndClose(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		},
	)
}

type contextKey string

const sessionKey contextKey = "session"

func sessionFromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(sessionKey).(Session)
	return session, ok
}

// Gate a handler and inject session data in.
func (h *Handler) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			sessionId, err := r.Cookie("session")
			if err != nil {
				clearCookies(w, r)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			session, err := h.getSession(sessionId.Value)
			if err != nil {
				clearCookies(w, r)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			// Inject into context.
			ctx := context.WithValue(r.Context(), sessionKey, session)

			next.ServeHTTP(w, r.WithContext(ctx))
		},
	)
}
