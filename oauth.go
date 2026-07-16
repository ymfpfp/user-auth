package main

import (
	"log"
	"net"
	"net/http"

	"github.com/ymfpfp/user-auth/oauth"
	"go.uber.org/zap"
)

const (
	googleCallback string = "/oauth/callback/google"
	githubCallback string = "/oauth/callback/github"
)

func oauthMux(h *Handler) *http.ServeMux {
	config := h.config
	mux := http.NewServeMux()

	googleConfig, err := oauth.GetConfig(oauth.GoogleConfigEndpoint)
	if err != nil {
		log.Fatal("Unable to configure Google OIDC: ", err)
	}
	googleClient := oauth.Client{
		Callback: googleCallback,
		Id:       config.GoogleClientId,
		Scopes:   "openid email profile",
		Secret:   config.GoogleClientSecret,
	}
	googleProvider := oauth.NewOIDCProvider(googleConfig, googleClient)
	mux.Handle("/oauth/login/google", googleProvider.Redirect())
	mux.Handle("/oauth/callback/google", googleProvider.Callback(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			logger := loggerFromContext(ctx)

			claims, ok := oauth.ClaimsFromContext(ctx)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// Upsert user and provider.
			id, _, err := h.upsertLoginFromClaims(claims)
			if err != nil {
				logger.Error("Unable to upsert login from claims", zap.Error(err))
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// Create a new session.
			// Get device and IP addr.
			device := r.UserAgent()
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			session, err := h.createSession(id, ip, device)
			if err != nil {
				logger.Error(
					"oauth create session",
					zap.String("identityId", id),
					zap.Error(err),
				)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			h.recordActivity(ctx, id, "Logged in via Google from "+ip)

			// Return session cookie.
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    session,
				HttpOnly: true,
				Path:     "/",
			})

			http.Redirect(w, r, "/loggedIn", http.StatusFound)
		},
	)))

	// In typical OAuth libraries, these are pre-filled properly for you;
	// here we'll fill them just with what we need.
	//
	// GitHub access tokens are long-lived. Typical OAuth apps will have get a
	// refresh token to maintain longevity; in that case, we'd also store a refresh token in
	// the db.
	githubConfig := oauth.Config{
		Issuer:                 "GitHub",
		AuthorizationEndpoint:  "https://github.com/login/oauth/authorize",
		TokenEndpoint:          "https://github.com/login/oauth/access_token",
		ResponseTypesSupported: []string{"code"},
		ScopesSupported:        []string{"repo", "read:user", "user:email"},
	}
	githubClient := oauth.Client{
		Callback: githubCallback,
		Id:       config.GithubClientId,
		Scopes:   "repo read:user user:email",
		Secret:   config.GithubClientSecret,
	}
	githubProvider := oauth.NewGithubOIDCProvider(githubConfig, githubClient)
	mux.Handle("/oauth/connect/github", h.authenticated(githubProvider.Redirect()))
	mux.Handle(githubCallback, h.authenticated(githubProvider.Callback(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// todo(jc): Implement "Connect with GitHub" and remove auth gate.

			ctx := r.Context()
			session, ok := sessionFromContext(ctx)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			tokens, ok := oauth.TokensFromContext(ctx)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			claims, ok := oauth.ClaimsFromContext(ctx)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// Store GitHub as a provider.
			err := h.linkProvider(session.IdentityId, claims.Issuer, claims.Subject, tokens.AccessToken)
			if err != nil {
				logger := loggerFromContext(ctx)
				logger.Error(
					"Unable to link GitHub",
					zap.Error(err),
					zap.String("identityId", session.IdentityId),
				)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			h.recordActivity(ctx, session.IdentityId, "Connected GitHub")

			http.Redirect(w, r, "/", http.StatusSeeOther)
		},
	))))
	return mux
}
