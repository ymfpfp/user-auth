package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"

	utils "github.com/ymfpfp/user-auth/utils"
)

type contextKey string

const (
	claimsKey contextKey = "claims"
	tokensKey contextKey = "tokens"
)

func ClaimsFromContext (ctx context.Context) (Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(Claims)
	return claims, ok
}

func TokensFromContext (ctx context.Context) (Tokens, bool) {
	tokens, ok := ctx.Value(tokensKey).(Tokens)
	return tokens, ok
}

func randomState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func Redirect(provider Provider) http.Handler {
	// Check that we're not providing invalid scopes in.
	scopes := strings.SplitSeq(provider.Client.Scopes, " ")
	for scope := range scopes {
		if !utils.Contains(provider.Config.ScopesSupported, scope) {
			log.Fatalf("Unsupported scope %s given provider %s", scope, provider.Config.Issuer)
	 	}
	}

	// Prefer the modern authorization code flow.
	if !utils.Contains(provider.Config.ResponseTypesSupported, "code") {
		log.Fatalf("Provider %s does not support authorization code flow", provider.Config.Issuer)
	}

	return http.HandlerFunc(
		func (w http.ResponseWriter, r *http.Request) {
			// Generate random state to prevent CSRF.
			state := randomState()

			http.SetCookie(w, &http.Cookie{
				Name: "state",
				Value: state,
				SameSite: http.SameSiteLaxMode,
				Path: "/",
			})

			// Redirect to OAuth provider.
			redirect, err := url.Parse(provider.Config.AuthorizationEndpoint)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// todo(jc): TLS
			redirectUri := url.URL {
				Scheme: "http",
				Host: r.Host,
				Path: provider.Client.Callback,
			}

			q := redirect.Query()
			// Client ID is public identifier for application trying to access user's data.
			q.Set("client_id", provider.Client.Id)
			q.Set("redirect_uri", redirectUri.String())
			q.Set("scope", provider.Client.Scopes)
			q.Set("response_type", "code")
			q.Set("state", state)
			redirect.RawQuery = q.Encode()

			log.Print(redirect.String())
			http.Redirect(w, r, redirect.String(), http.StatusFound)
		},
	)
}

func Callback(provider Provider, callback http.Handler) http.Handler {
	return http.HandlerFunc(
		func (w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()

			state := q.Get("state")
			// We use authorization code flow.
			code := q.Get("code")

			cookie, err := r.Cookie("state")
			// Check that the cookie and state match to prevent being MITM'd.
			if err != nil || cookie.Value != state {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// todo(jc): TLS
			redirectUri := url.URL {
				Scheme: "http",
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
			encodedRequest, err := request.Encode() 
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			response, err := http.Post(
				provider.Config.TokenEndpoint,
				"application/json",
				encodedRequest,
			)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			defer response.Body.Close()

			var tokens Tokens
			err = json.NewDecoder(response.Body).Decode(&tokens)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// At this point, we have the token response. It is up to the resolver to 
			// check that the token is valid and maybe return some info (`claims` generalized). 
			claims, err := provider.Resolver.Resolve(tokens)	
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			// Inject into context, and then trigger callback, this is designed to be used as
			// middleware.
			ctx := r.Context()
			ctx = context.WithValue(ctx, claimsKey, claims)
			ctx = context.WithValue(ctx, tokensKey, tokens)

			callback.ServeHTTP(w, r.WithContext(ctx))
		},
	)
}
