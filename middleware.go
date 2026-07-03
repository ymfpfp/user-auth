package main

import (
	"context"
	"io"
	"net/http"

	"github.com/ymfpfp/user-auth/data"
	"github.com/ymfpfp/user-auth/utils"
)

type contextKey string

const sessionKey contextKey = "session"

func SessionFromContext(ctx context.Context) (data.Session, bool) {
	session, ok := ctx.Value(sessionKey).(data.Session)
	return session, ok
}

func DrainAndClose(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		},
	)
}

// Gate a handler and inject session data in.
func (h *Handler) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			sessionId, err := r.Cookie("session")
			if err != nil {
				utils.ClearCookies(w, r)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			session, err := h.GetSession(sessionId.Value)
			if err != nil {
				utils.ClearCookies(w, r)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			// Inject into context.
			ctx := context.WithValue(r.Context(), sessionKey, session)

			next.ServeHTTP(w, r.WithContext(ctx))
		},
	)
}
