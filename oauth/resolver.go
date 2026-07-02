package oauth

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/ymfpfp/user-auth/jwt"
)

type TokenRequest struct {
	Code string `json:"code"`
	ClientId string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUri string `json:"redirect_uri"`
	GrantType string `json:"grant_type"`
}

func (tokenRequest *TokenRequest) Encode() (*bytes.Buffer, error) {
	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(tokenRequest)
	return buffer, err
}

type Tokens struct {
	AccessToken string `json:"access_token"`
	IdToken string `json:"id_token"`
}

type Claims map[string]any

type Resolver interface {
	Resolve(tokens Tokens) (Claims, error)
}

type OIDCResolver struct {
	// An OIDC resolver has a JSON Web Key Set and a set of values to verify.
	JWKS jwt.JWKS
	ToVerify OIDCVerification
}

type OIDCVerification struct {
	Audience string
	Issuer string
}

func (resolver OIDCResolver) Resolve(tokens Tokens) (Claims, error) {
	// In OIDC, we want to check that the claims are verified.
	jwtToken, err := jwt.FromPayload(tokens.IdToken)
	if err != nil {
		return jwtToken.Claims, err
	}

	jwk, err := resolver.JWKS.GetJWK(jwtToken.Header.Kid) 
	if err != nil {
		// todo(jc): If you can't find a matching JWK, it might just be that a new JWKS is
		// available.
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

	if jwtToken.Claims["aud"].(string) != resolver.ToVerify.Audience {
		return jwtToken.Claims, jwt.InvalidJWT
	}

	if jwtToken.Claims["iss"].(string) != resolver.ToVerify.Issuer {
		return jwtToken.Claims, jwt.InvalidJWT
	}

	return jwtToken.Claims, nil
}

