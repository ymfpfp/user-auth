package main

import (
	"database/sql"
	"errors"
	"net/http"
	"time"
)

// General utils for utilizing passkeys.

const (
	passkeyPurpose string = "passkey"
)

func (h *Handler) passkeyChallenge(identityId string) (string, error) {
	// Generate challenge if not already in db; otherwise use that one.
	var challenge string
	err := h.db.QueryRow(
		"SELECT code FROM temporary_codes WHERE identity_id = ? AND purpose = ?",
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
			"INSERT INTO temporary_codes (identity_id, purpose, code, expires_at) VALUES (?, ?, ?, ?)",
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

func (h *Handler) uploadPasskey(w http.ResponseWriter, r *http.Request) {
}
