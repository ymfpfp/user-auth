package main

import (
	"context"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

func setCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:  name,
		Value: value,
		// JS cannot read this cookie.
		HttpOnly: true,
		// Only over HTTPS.
		Secure: true,
		// Applies to all paths.
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})
}

func deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
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

// Logging middleware.

// Intercept status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) WriteHeader(code int) {
	recorder.status = code
	recorder.ResponseWriter.WriteHeader(code)
}

func (h *Handler) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			requestId, err := randomToken()
			if err != nil {

			}
			w.Header().Set("X-Request-ID", requestId)

			// Build child logger.
			logger := h.logger.With(zap.String("request_id", requestId))
			ctx := context.WithValue(r.Context(), loggerKey, logger)

			recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			defer func() {
				level := zapcore.InfoLevel
				switch {
				case recorder.status >= 500:
					level = zapcore.ErrorLevel
				case recorder.status >= 400:
					level = zapcore.WarnLevel
				}
				logger.Log(
					level,
					"request",
					zap.Duration("duration", time.Since(start)),
					zap.String("ip", r.RemoteAddr),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
					zap.Int("status", recorder.status),
				)
			}()
			next.ServeHTTP(recorder, r.WithContext(ctx))
		},
	)
}

type contextKey string

const (
	sessionKey contextKey = "session"
	loggerKey  contextKey = "logger"
)

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

// Gate this handler by POST.
func (h *Handler) post(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}

			next.ServeHTTP(w, r)
		},
	)
}
