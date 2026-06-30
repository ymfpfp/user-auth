package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"

	jwt "github.com/ymfpfp/user-auth/jwt"
)

func drainAndClose(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		},
	)
}

type Sessions struct {
	sessions map[string]map[string]any
	mu sync.Mutex
}

func EmptySession() Sessions {
	return Sessions{
		sessions: make(map[string]map[string]any),
	}
}

type Handler struct {
	db *sql.DB
	config *Config
	sessions Sessions
}

func newSessionId() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Handler) Mux() http.Handler {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Create unique session.
		sessions := &h.sessions
		sessions.mu.Lock()
		defer sessions.mu.Unlock()

		state := newSessionId()
		sessions.sessions[state] = map[string]any{}

		http.SetCookie(w, &http.Cookie{
			Name: "state",
			Value: state,
			SameSite: http.SameSiteLaxMode,
			Path: "/",
		})

		// Redirect to OAuth provider.
		redirect := url.URL{
			Scheme: "https",
			Host: "accounts.google.com",
			Path: "/o/oauth2/auth",
		}
		q := redirect.Query()
		// Client ID is public identifier for application trying to access user's data
		q.Set("client_id", h.config.ClientId)
		// TODO: Don't make this static.
		q.Set("redirect_uri", "http://127.0.0.1:9000/oauth2/callback")
		// TODO: Don't make this static.
		// See scopes: https://developers.google.com/identity/protocols/oauth2/scopes
		q.Set("scope", "openid profile email https://www.googleapis.com/auth/photoslibrary")
		// TODO: Make this more general purpose?
		// In the OAuth standard, `response_type` is fixed to `token` but nowadays
		// Authorization Code Flow with `code` is preferred - you get an authorization code,
		// then exchange it server-side for tokens, rather than getting a token directly back
		// which is bad for security and also bad for refresh tokens.
		q.Set("response_type", "code")
		q.Set("state", state)
		redirect.RawQuery = q.Encode()

		log.Print(redirect.String())

		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	serveMux.HandleFunc("/oauth2/callback", h.handleOAuth) 
	mux := drainAndClose(serveMux)
	return mux
}

// Handle OAuth callback.
func (h *Handler) handleOAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	state := q.Get("state")
	code := q.Get("code")

	cookie, err := r.Cookie("state")
	if err != nil || cookie.Value != state {
		http.Error(w, "Invalid request", http.StatusForbidden)
		log.Panic(err)
		return
	}

	type ExchangeRequest struct {
		Code string `json:"code"`
		ClientId string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RedirectUri string `json:"redirect_uri"`
		GrantType string `json:"grant_type"`
	}
	exchange := ExchangeRequest {
		// Exchange code for token.
		Code: code,
		ClientId: h.config.ClientId,
		// Client secret confirms that the request is indeed coming from my app.
		ClientSecret: h.config.ClientSecret,
		// TODO: Why exactly is this necessary?
		RedirectUri: "http://127.0.0.1:9000/oauth2/callback",
		// Must be set to `authorization_code` per the standard, this returns the 
		// authorization code.
		GrantType: "authorization_code",
	}
	buffer := new(bytes.Buffer)
	err = json.NewEncoder(buffer).Encode(&exchange)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusForbidden)
		log.Panic(err)
		return
	}
	tokenResponse, err := http.Post(
		"https://oauth2.googleapis.com/token",
		"application/json",
		buffer,
	)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusForbidden)
		log.Panic(err)
		return
	}
	defer tokenResponse.Body.Close()

	var token struct {
		IdToken string `json:"id_token"`
	}
	err = json.NewDecoder(tokenResponse.Body).Decode(&token)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusForbidden)
		log.Panic(err)
		return
	}

	// The JWT is technically OIDC? Other things that get returned are access and refresh token 
	// Google OAuth returns a JWT signed with asymmetric cryptography, RS256 = RSA + SHA-256.
	// We should verify the JWT with Google public keys.
	jwtToken, err := jwt.FromPayload(token.IdToken)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusForbidden)
		log.Panic(err)
		return
	}

	// Need to grab the JWK.
	jwks, err := jwt.GetJWKS("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		http.Error(w, "Invalid request", http.StatusForbidden)
		log.Panic(err)
		return
	}

	jwk, err := jwks.GetJWK(jwtToken.Header.Kid)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusForbidden)
		log.Panic(err)
		return
	}
		
	verified, err := jwtToken.Verify(jwk, map[string]any{
		"aud": h.config.ClientId,
		"iss": "https://accounts.google.com",
	})
	if verified == false || err != nil {
		http.Error(w, "Invalid request", http.StatusForbidden)
		log.Panic(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(jwtToken.Claims)
}

