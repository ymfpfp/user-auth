package oauth

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ymfpfp/user-auth/jwt"
)

type TokenRequest struct {
	Code string 
	ClientId string 
	ClientSecret string 
	RedirectUri string 
	GrantType string 
}

func (tokenRequest TokenRequest) Encode() *strings.Reader {
	form := url.Values{}
	form.Add("code", tokenRequest.Code)
	form.Add("client_id", tokenRequest.ClientId)
	form.Add("client_secret", tokenRequest.ClientSecret)
	form.Add("redirect_uri", tokenRequest.RedirectUri)
	form.Add("grant_type", tokenRequest.GrantType)
	return strings.NewReader(form.Encode())
}

type Tokens struct {
	AccessToken string `json:"access_token"`
	IdToken string `json:"id_token"`
	Nonce string `json:"nonce,omitempty"`
}

type OIDCAudience []string

func (aud *OIDCAudience) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*aud = OIDCAudience{s}
		return nil
	}

	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*aud = OIDCAudience(arr)
		return nil
	}

	return jwt.InvalidJWT
}

type OIDCClaims struct {
	Audience OIDCAudience `json:"aud"`
	Issuer string `json:"iss"`
	Subject string `json:"sub"`
	ExpiresAt float64 `json:"exp"`
	Nonce string `json:"nonce"`
	// Other claims.
	Raw map[string]any `json:"-"`
}

func ClaimsFromContext(ctx context.Context) (OIDCClaims, bool) {
	claims, ok := ctx.Value(claimsKey).(OIDCClaims)
	return claims, ok
}

type Resolver interface {
	Resolve(tokens Tokens, ctx context.Context) (context.Context, error)
}

type OIDCResolver struct {
	// An OIDC resolver has a JSON Web Key Set and a set of values to verify.
	JWKS jwt.JWKS
	// JWKSUri is where the key set is (re-)fetched from after key rotation.
	JWKSUri string
	ToVerify OIDCVerification

	// mu guards JWKS against concurrent `Resolve` calls.
	mu sync.RWMutex
	lastRefresh time.Time
}

type OIDCVerification struct {
	Audience string
	Issuer string
}

func (resolver *OIDCResolver) Resolve(tokens Tokens, ctx context.Context) (context.Context, error) {
	// In OIDC, we want to check that the claims are verified.
	jwtToken, err := jwt.FromToken(tokens.IdToken)
	if err != nil {
		return ctx, err
	}

	jwk, err := resolver.getJWK(jwtToken.Header.Kid)
	if err != nil {
		return ctx, err
	}

	verified, err := jwtToken.Verify(jwk) 
	if verified == false {
		return ctx, jwt.InvalidJWT
	} else if err != nil {
		return ctx, jwt.InvalidJWT
	}

	// Now we can construct a typed set of claims.
	var claims OIDCClaims
	if err = json.Unmarshal(jwtToken.Payload, &claims); err != nil {
		return ctx, err
	}
	// Directly unload all claims.
	if err = json.Unmarshal(jwtToken.Payload, &claims.Raw); err != nil {
		return ctx, err
	}

	// In addition to verifying the signature, we also need to verify: 
	// * `aud`. Short for audience, basically is this token meant for this client?
	// * `exp`. Short for expiration, check that the token is still valid.
	// * `iss`. Short for issuer, basically was this token issued by who we expected?

	if time.Now().Unix() >= int64(claims.ExpiresAt) ||
		 !slices.Contains(claims.Audience, resolver.ToVerify.Audience) ||
		 claims.Issuer != resolver.ToVerify.Issuer {
		return ctx, jwt.InvalidJWT
	}

	// Inject claims into the context.
	return context.WithValue(ctx, claimsKey, claims), nil
}

const jwksRefreshCooldown = time.Minute

func (resolver *OIDCResolver) getJWK(kid string) (jwt.JWK, error) {
	resolver.mu.RLock()
	jwk, err := resolver.JWKS.GetJWK(kid)
	resolver.mu.RUnlock()
	if err == nil {
		return jwk, nil
	}

	// Try refreshing the JWK.
	if refreshErr := resolver.refreshJWKS(); refreshErr != nil {
		return jwt.JWK{}, refreshErr
	}

	resolver.mu.RLock()
	defer resolver.mu.RUnlock()
	// Now attempt to get the JWK after refreshing it.
	return resolver.JWKS.GetJWK(kid)
}

// refreshJWKS re-fetches the key set, skipping the fetch if another refresh
// already happened within the cooldown window (which also collapses concurrent
// refreshes triggered by the same rotation).
func (resolver *OIDCResolver) refreshJWKS() error {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()

	if !resolver.lastRefresh.IsZero() && time.Since(resolver.lastRefresh) < jwksRefreshCooldown {
		return nil
	}

	jwks, err := jwt.GetJWKS(resolver.JWKSUri)
	if err != nil {
		return err
	}
	resolver.JWKS = jwks
	resolver.lastRefresh = time.Now()
	return nil
}

// todo(jc): OAuth resolver.
type OAuthResolver struct {
}


