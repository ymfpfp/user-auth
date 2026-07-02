package oauth

import (
	"net/url"
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

type Claims map[string]any

type Resolver interface {
	Resolve(tokens Tokens) (Claims, error)
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

func (resolver *OIDCResolver) Resolve(tokens Tokens) (Claims, error) {
	// In OIDC, we want to check that the claims are verified.
	jwtToken, err := jwt.FromPayload(tokens.IdToken)
	if err != nil {
		return jwtToken.Claims, err
	}

	jwk, err := resolver.getJWK(jwtToken.Header.Kid)
	if err != nil {
		return jwtToken.Claims, err
	}

	verified, err := jwtToken.Verify(jwk) 
	if verified == false || err != nil {
		return jwtToken.Claims, err
	}

	// In addition to verifying the signature, we also need to verify: 
	// * `aud`. Short for audience, basically is this token meant for this client?
	// * `exp`. Short for expiration, check that the token is still valid.
	// * `iss`. Short for issuer, basically was this token issued by who we expected?
	
	exp, ok := jwtToken.Claims["exp"].(float64)
	if !ok || time.Now().Unix() >= int64(exp) {
		return jwtToken.Claims, jwt.InvalidJWT
	}

	if !audienceMatches(jwtToken.Claims["aud"], resolver.ToVerify.Audience) {
		return jwtToken.Claims, jwt.InvalidJWT
	}

	if iss, ok := jwtToken.Claims["iss"].(string); !ok || iss != resolver.ToVerify.Issuer {
		return jwtToken.Claims, jwt.InvalidJWT
	}

	return jwtToken.Claims, nil
}

func audienceMatches(claim any, want string) bool {
	switch aud := claim.(type) {
	case string:
		return aud == want
	case []any:
		for _, entry := range aud {
			if s, ok := entry.(string); ok && s == want {
				return true
			}
		}
	}
	return false
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


