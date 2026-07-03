package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

func TokensFromContext (ctx context.Context) (Tokens, bool) {
	tokens, ok := ctx.Value(tokensKey).(Tokens)
	return tokens, ok
}

func randomState() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (provider Provider) Redirect() http.Handler {
	// Check that we're not providing invalid scopes in.
	scopes := strings.SplitSeq(provider.Client.Scopes, " ")
	for scope := range scopes {
		if !slices.Contains(provider.Config.ScopesSupported, scope) {
			log.Fatalf("Unsupported scope %s given provider %s", scope, provider.Config.Issuer)
	 	}
	}

	// Prefer the modern authorization code flow.
	if !slices.Contains(provider.Config.ResponseTypesSupported, "code") {
		log.Fatalf("Provider %s does not support authorization code flow", provider.Config.Issuer)
	}

	return http.HandlerFunc(
		func (w http.ResponseWriter, r *http.Request) {
			// Generate random state to prevent CSRF.
			state, err := randomState()
			if err != nil {
				log.Print("Unable to generate random state token: ", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name: "state",
				Value: state,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				// Secure: true,
				Path: "/",
			})

			// Redirect to OAuth provider.
			redirect, err := url.Parse(provider.Config.AuthorizationEndpoint)
			if err != nil {
				log.Print("Unable to redirect to OAuth provider: ", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			redirectUri := url.URL {
				Scheme: "https",
				Host: r.Host,
				Path: provider.Client.Callback,
			}

			nonce, err := randomState()
			if err != nil {
				log.Print("Unable to generate random nonce: ", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			q := redirect.Query()
			// Client ID is public identifier for application trying to access user's data.
			q.Set("client_id", provider.Client.Id)
			// todo(jc): Nonce
			q.Set("nonce", nonce)
			q.Set("redirect_uri", redirectUri.String())
			q.Set("response_type", "code")
			q.Set("scope", provider.Client.Scopes)
			q.Set("state", state)
			redirect.RawQuery = q.Encode()

			log.Print("Redirecting to ", redirect.String())
			http.Redirect(w, r, redirect.String(), http.StatusFound)
		},
	)
}

func (provider Provider) Callback(callback http.Handler) http.Handler {
	return http.HandlerFunc(
		func (w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()

			callbackErr := q.Get("error")
			if callbackErr == "access_denied" {
				http.Error(w, "User denied", http.StatusConflict)
				return
			} else if len(callbackErr) != 0 {
				// Not empty, some other error.
				log.Print("OAuth callback returned error: ", callbackErr)
				http.Error(w, callbackErr, http.StatusBadRequest)
				return
			}

			state := q.Get("state")
			// We use authorization code flow.
			code := q.Get("code")

			// Check that the cookie and state match to prevent being MITM'd.
			if cookie, err := r.Cookie("state"); err != nil || cookie.Value != state {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// Delete the cookie.
			http.SetCookie(w, &http.Cookie{
				Name: "state",
				Value: "",
				HttpOnly: true,
				MaxAge: -1,
				Path: "/",
				// Secure: true,
				SameSite: http.SameSiteLaxMode,
			})

			redirectUri := url.URL {
				Scheme: "https",
				Host: r.Host,
				Path: provider.Client.Callback,
			}
			request := TokenRequest {
				// Exchange code for token.
				Code: code,
				ClientId: provider.Client.Id,
				// Client secret confirms that the request is indeed coming from my app.
				ClientSecret: provider.Client.Secret,
				// todo(jc): Why is this necessary? 
				RedirectUri: redirectUri.String(),
				// Must be set to `authorization_code` per the standard, this returns the
				// authorization code.
				GrantType: "authorization_code",
			}
			// Build with the request context so a client disconnect (or the
			// server's TimeoutHandler firing) cancels the outbound exchange.
			tokenReq, err := http.NewRequestWithContext(
				r.Context(),
				http.MethodPost,
				provider.Config.TokenEndpoint,
				request.Encode(),
			)
			if err != nil {
				log.Print("Unable to build OAuth token request: ", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			tokenReq.Header.Set("Accept", "application/json")
			tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := httpClient.Do(tokenReq)
			if err != nil {
				log.Print("Error with OAuth token request: ", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer response.Body.Close()

			var tokens Tokens
			if err = json.NewDecoder(response.Body).Decode(&tokens); err != nil {
				log.Print("Unable to decode OAuth token response: ", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// todo(jc): PKCE.

			ctx := r.Context()

			// At this point, we have the token response. It is up to the resolver to 
			// check that the token is valid and maybe inject some info into context.
			ctx, err = provider.Resolver.Resolve(tokens, ctx)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// Inject token into context, and then trigger callback, this is designed to be used as
			// middleware.
			ctx = context.WithValue(ctx, tokensKey, tokens)

			callback.ServeHTTP(w, r.WithContext(ctx))
		},
	)
}
