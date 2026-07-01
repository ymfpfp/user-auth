package oauth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/ymfpfp/user-auth/jwt"
	utils "github.com/ymfpfp/user-auth/utils"
)

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
			q.Set("response_type", provider.PreferredResponseType())
			q.Set("state", state)
			redirect.RawQuery = q.Encode()

			log.Print(redirect.String())
			http.Redirect(w, r, redirect.String(), http.StatusFound)
		},
	)
}

func Callback(provider Provider) http.Handler {
	jwks, err := jwt.GetJWKS(provider.Config.JWKSUri)
	if err != nil {
		log.Fatal("Unable to get JWKS ", jwks)
	}

	return http.HandlerFunc(
		func (w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()

			state := q.Get("state")
			// todo(jc): This is too specific. 
			code := q.Get("code")

			cookie, err := r.Cookie("state")
			log.Print(state, cookie.Value)
			if err != nil || cookie.Value != state {
				w.WriteHeader(http.StatusForbidden)
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
				ClientId: provider.Client.Id,
				// Client secret confirms that the request is indeed coming from my app.
				ClientSecret: provider.Client.Secret,
				// todo(jc): Why is this necessary? Also it's fixed
				RedirectUri: "http://127.0.0.1:9000/oauth2/google",
				// Must be set to `authorization_code` per the standard, this returns the
				// authorization code.
				GrantType: "authorization_code",
			}
			buffer := new(bytes.Buffer)
			err = json.NewEncoder(buffer).Encode(&exchange)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			tokenResponse, err := http.Post(
				"https://oauth2.googleapis.com/token",
				"application/json",
				buffer,
			)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			defer tokenResponse.Body.Close()

			var token struct {
				// This is the JWT for OIDC.
				// todo(jc): This should not be anon struct.
				IdToken string `json:"id_token"`
			}
			err = json.NewDecoder(tokenResponse.Body).Decode(&token)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			jwtToken, err := jwt.FromPayload(token.IdToken)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			jwk, err := jwks.GetJWK(jwtToken.Header.Kid)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			verified, err := jwtToken.Verify(jwk, map[string]any{
				"aud": provider.Client.Id,
				"iss": provider.Config.Issuer,
			})
			if verified == false || err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(jwtToken.Claims)
		},
	)
}
