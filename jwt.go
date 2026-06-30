package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"strings"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type JWT struct {
	Header JWTHeader
	Claims map[string]string
	Payload string
	Signature []byte
}

// JSON Web Key Set.
type JWK struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	// Asymmetric RSA keys are made of (N, E), where N is pq and E is a random big exponent.
	N string `json:"n"`
	E string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func FromPayload(payload string) (JWT, error) {
	var jwt JWT

	parts := strings.Split(payload, ".")
	encodedHeader := parts[0]
	encodedClaims := parts[1]
	encodedSignature := parts[2]
	jwt.Payload = encodedHeader + "." + encodedClaims

	decodedHeader, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		return jwt, err
	}
	err = json.Unmarshal(decodedHeader, &jwt.Header)
	if err != nil {
		return jwt, err
	}

	decodedClaims, err := base64.RawURLEncoding.DecodeString(encodedClaims)
	if err != nil {
		return jwt, err
	}
	err = json.Unmarshal(decodedClaims, &jwt.Claims)

	jwt.Signature, err = base64.RawURLEncoding.DecodeString(encodedSignature)

	return jwt, nil
}

func (jwt JWT) Verify() bool {
	jwksResponse, err := http.Get("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		log.Panic(err)
		return false
	}
	defer jwksResponse.Body.Close()

	var jwks JWKS
	err = json.NewDecoder(jwksResponse.Body).Decode(&jwks)
	if err != nil {
		log.Panic(err)
		return false
	}

	// To verify, we use `kid` to grab the right public key.
	var jwk JWK
	for _, key := range jwks.Keys {
		if key.Kid == jwt.Header.Kid {
			jwk = key
			break
		}
	}
	// TODO: This entire function has to be more general purpose.
	if jwk.Alg != "RS256" {
		return false
	}

	// Construct public key from (N, E) after base64 decoding them.
	N, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		log.Panic(err)
		return false
	}
	E, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		log.Panic(err)
		return false
	}
	pub := rsa.PublicKey{
		N: new(big.Int).SetBytes(N),
		E: int(new(big.Int).SetBytes(E).Int64()),
	}

	// Hash the payload.
	hashed := sha256.Sum256([]byte(jwt.Payload))

	// How does this work?
	// Take RSA public key, which is (N, E), 
	// the hashing algorithm, in this case SHA-256 (returns 32 bytes, cast to pointer here),
	// result of hashing with the hashing algorithm,
	// and the signature.
	// 
	// TODO
	err = rsa.VerifyPKCS1v15(&pub, crypto.SHA256, hashed[:], jwt.Signature)
	if err != nil {
		return false
	}

	return true
}
