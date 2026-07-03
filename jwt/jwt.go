package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// httpClient bounds JWKS fetches so key-set retrieval can't hang forever.
var httpClient = &http.Client{Timeout: 10 * time.Second}

type AlgType string

const (
	RS256 AlgType = "RS256"
)

type JWTHeader struct {
	Alg AlgType `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type JWT struct {
	Header JWTHeader
	Payload []byte
	// Combined `{Header}.{Payload}` as bytes.
	Input []byte
	Signature []byte
}

type JWTError string

const (
	InvalidJWT JWTError = "Invalid JWT"
	UnsupportedJWT JWTError = "Unsupported JWT"
)

func (err JWTError) Error() string {
	return string(err)
}

// JSON Web Key Set.
type JWK struct {
	Alg AlgType `json:"alg"`
	// Key ID.
	Kid string `json:"kid"`
	// Key type.
	Kty string `json:"kty"`
	Use string `json:"use"`
	// Public RSA key consists of (N, E).
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWKSError string

const (
	KidNotFound JWKSError = "Key ID not found in JWKS"
)

func (err JWKSError) Error() string {
	return string(err)
}

func FromToken(token string) (JWT, error) {
	var jwt JWT

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwt, InvalidJWT
	}
	encodedHeader := parts[0]
	encodedPayload := parts[1]
	encodedSignature := parts[2]
	jwt.Input = []byte(encodedHeader + "." + encodedPayload)

	decodedHeader, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		return jwt, err
	}
	err = json.Unmarshal(decodedHeader, &jwt.Header)
	if err != nil {
		return jwt, err
	}

	jwt.Payload, err = base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return jwt, err
	}

	jwt.Signature, err = base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return jwt, err
	}

	return jwt, nil
}

func (jwt JWT) verifyRSA(jwk JWK) (bool, error) {
	// Construct RSA public key from (N, E) after base64 decoding them.
	N, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return false, err
	}
	E, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return false, err
	}
	pub := rsa.PublicKey{
		N: new(big.Int).SetBytes(N),
		E: int(new(big.Int).SetBytes(E).Int64()),
	}

	var hash crypto.Hash
	var hashed []byte 
	switch jwk.Alg {
	case RS256:
		hash = crypto.SHA256
		bytes := sha256.Sum256(jwt.Input)
		hashed = bytes[:]
	default:
		return false, UnsupportedJWT
	}

	// todo(jc): How does this work?
	err = rsa.VerifyPKCS1v15(&pub, hash, hashed, jwt.Signature)
	if err != nil {
		return false, InvalidJWT
	}

	return true, nil
}

func (jwt JWT) Verify(jwk JWK) (bool, error) {	
	switch jwk.Alg {
	case RS256: 
		return jwt.verifyRSA(jwk)
	}
	return false, UnsupportedJWT
}

func GetJWKS(path string) (JWKS, error) {
	var jwks JWKS

	jwksResponse, err := httpClient.Get(path)
	if err != nil {
		return jwks, err
	}
	defer jwksResponse.Body.Close()

	err = json.NewDecoder(jwksResponse.Body).Decode(&jwks)
	if err != nil {
		return jwks, err
	}

	return jwks, nil
}

func (jwks JWKS) GetJWK(kid string) (JWK, error) {
	// To verify, we use `kid` to grab the right public key.
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return key, nil
		}
	}
	return JWK{}, KidNotFound
}
