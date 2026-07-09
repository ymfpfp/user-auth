package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type CredentialPublicKey struct {
	Alg int `cbor:"3,keyasint"` // -7
	// The curve we're operating on, should be 1 for P-256.
	Crv int `cbor:"-1,keyasint"`
	// The key.
	X []byte `cbor:"-2,keyasint"` // 32 bytes
	Y []byte `cbor:"-3,keyasint"` // 32 bytes
}

type ClientData struct {
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
}

func (p *Passkey) UnmarshalCredential() (*ecdsa.PublicKey, error) {
	// The stored credential is the CBOR-encoded COSE key we saved at registration.
	var key CredentialPublicKey
	if err := cbor.Unmarshal(p.Credential, &key); err != nil {
		return nil, err
	}
	// We only ever store ES256 (alg -7) keys on the P-256 curve (crv 1).
	if key.Alg != -7 || key.Crv != 1 {
		return nil, errors.New("unsupported credential public key")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(key.X),
		Y:     new(big.Int).SetBytes(key.Y),
	}, nil
}

func (h *Handler) newPasskeyRoute(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Id string `json:"id"`
		// Both of these should be base64 encoded.
		ClientDataJSON        string `json:"clientDataJSON"`
		AttestationObjectCBOR string `json:"attestationObjectCBOR"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	clientDataJSON, err := base64.StdEncoding.DecodeString(request.ClientDataJSON)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var clientData ClientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// todo(jc): Verify challenge and origin.

	attestationObjectCBOR, err := base64.StdEncoding.DecodeString(request.AttestationObjectCBOR)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var attestationObject struct {
		AuthData []byte `cbor:"authData"`
	}
	if err := cbor.Unmarshal(attestationObjectCBOR, &attestationObject); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// The AT (Attested Credential Data) flag should be on for attested credential data.
	if attestationObject.AuthData[32]&0x40 == 0 {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	offset := 32 + 1 + 4 + 16 // Skip bytes for `rpIdHash`, `flags`, `signCount`, AAGUID

	// Skip credential id, same as `request.Id`.
	credentialIdLen := binary.BigEndian.Uint16(
		attestationObject.AuthData[offset : offset+2],
	)
	offset += 2 + int(credentialIdLen)

	// Grab public key, which is encoded as a COSE (CBOR Object Signing and Encryption) key.
	// In our case, we only accept keys of type alg -7, so we can directly encode that.
	// -7 maps to ES256, which is ECDSA (Elliptic Curve Digital Signing Algorithm).
	var credentialPublicKey CredentialPublicKey
	if _, err := cbor.UnmarshalFirst(attestationObject.AuthData[offset:], &credentialPublicKey); err != nil || credentialPublicKey.Alg != -7 || credentialPublicKey.Crv != 1 {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	session, ok := sessionFromContext(r.Context())
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	credential, err := cbor.Marshal(credentialPublicKey)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Now add this passkey to the db.
	if err = h.uploadPasskey(session.IdentityId, request.Id, credential); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := h.recordActivity(session.IdentityId, "Added a passkey"); err != nil {
		log.Print(err)
	}

	w.WriteHeader(http.StatusOK)
}

func passkeyMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("/new", h.authenticated(h.post(http.HandlerFunc(h.newPasskeyRoute))))

	mux.HandleFunc("/options", func(w http.ResponseWriter, r *http.Request) {
		// We're going to take advantage of the codes row's auto-incremented id
		// as the temp session id, and attach the challenge as the code.
		challenge, err := randomToken()
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		res, err := h.db.Exec(
			"INSERT INTO codes (purpose, code, expires_at) VALUES (?, ?, ?)",
			passkeyPurpose, hashToken(challenge), time.Now().Add(temporaryCodeTTL).Unix(),
		)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		id, err := res.LastInsertId()
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"passkeySession":   id,
			"passkeyChallenge": challenge,
		}); err != nil {
			log.Print(err)
		}
	})

	mux.Handle("/login", h.post(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// todo(jc): Flash message as needed.
		// Parse request.
		var request struct {
			Session int64  `json:"session"`
			Id      string `json:"id"`
			// All of these should be base64 encoded.
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Grab session.
		session, err := h.getTemporaryCodeFromId(request.Session)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Delete session.
		if err = h.deleteTemporaryCode(session.Id); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// challenge := session.Code

		// Attempt to find a matching credential.
		passkey, err := h.getPasskey(request.Id)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		publicKey, err := passkey.UnmarshalCredential()
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// todo(jc): Verify challenge and origin.

		clientDataJSON, err := base64.StdEncoding.DecodeString(request.ClientDataJSON)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		clientDataHash := sha256.Sum256(clientDataJSON)

		authenticatorData, err := base64.StdEncoding.DecodeString(request.AuthenticatorData)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// The authenticator signs authenticatorData || SHA-256(clientDataJSON).
		assertions := append(
			authenticatorData,
			clientDataHash[:]...,
		)

		signature, err := base64.StdEncoding.DecodeString(request.Signature)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// ES256 signs the SHA-256 digest of that concatenation; WebAuthn signatures
		// are ASN.1 DER encoded.
		digest := sha256.Sum256(assertions)
		if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Verified: mint a real session for the passkey's owner.
		device := r.UserAgent()
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		newSession, err := h.createSession(passkey.IdentityId, ip, device)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := h.recordActivity(passkey.IdentityId, "Logged in via passkey from "+ip); err != nil {
			log.Print(err)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    newSession,
			HttpOnly: true,
			Path:     "/",
		})
		w.WriteHeader(http.StatusOK)
	})))

	return mux
}

func (h *Handler) passkeyChallenge(identityId string) (string, error) {
	// Generate challenge if not already in db; otherwise use that one.
	var challenge string
	err := h.db.QueryRow(
		"SELECT code FROM codes WHERE identity_id = ? AND purpose = ?",
		identityId, passkeyPurpose,
	).Scan(&challenge)
	switch {
	case err == nil:
		return challenge, nil
	case errors.Is(err, sql.ErrNoRows):
		if challenge, err = randomToken(); err != nil {
			return "", err
		}
		_, err := h.db.Exec(
			"INSERT INTO codes (identity_id, purpose, code, expires_at) VALUES (?, ?, ?, ?)",
			identityId, passkeyPurpose, hashToken(challenge), time.Now().Add(temporaryCodeTTL).Unix(),
		)
		if err != nil {
			return "", err
		}
		return challenge, nil
	default:
		return "", err
	}
}

func (h *Handler) uploadPasskey(identityId, id string, credential []byte) error {
	_, err := h.db.Exec(
		"INSERT INTO passkeys (identity_id, id, credential, created_at) VALUES (?, ?, ?, ?)",
		identityId, id, credential, time.Now().Unix(),
	)
	return err
}

func (h *Handler) getPasskey(id string) (Passkey, error) {
	var passkey Passkey
	err := h.db.QueryRow(
		"SELECT identity_id, credential, created_at FROM passkeys WHERE id = ?",
		id,
	).Scan(&passkey.IdentityId, &passkey.Credential, &passkey.CreatedAt)
	if err != nil {
		return passkey, err
	}
	passkey.Id = id
	return passkey, nil
}

func (h *Handler) getPasskeys(identityId string) ([]Passkey, error) {
	var passkeys []Passkey

	rows, err := h.db.Query(
		"SELECT id, credential, created_at FROM passkeys WHERE identity_id = ?",
		identityId,
	)
	if err != nil {
		return passkeys, err
	}
	defer rows.Close()

	for rows.Next() {
		var passkey Passkey
		err := rows.Scan(
			&passkey.Id,
			&passkey.Credential,
			&passkey.CreatedAt,
		)
		if err != nil {
			return passkeys, err
		}
		passkeys = append(passkeys, passkey)
	}

	return passkeys, nil
}
