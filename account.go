package main

import (
	"database/sql"
	"errors"

	"github.com/ymfpfp/user-auth/oauth"
	"github.com/ymfpfp/user-auth/utils"
)

func (h *Handler) createIdentity(name, email string) (string, error) {
	uuid, err := randomToken()
	if err != nil {
		return "", nil
	}
	_, err = h.db.Exec(
		"INSERT INTO identities (uuid, name, email) VALUES (?, ?, ?)",
		uuid, name, email,
	)
	if err != nil {
		return "", err
	}
	return uuid, nil
}

func (h *Handler) createIdentityWithProvider(issuer, subject, name, email string, accessToken *string) (string, error) {
	uuid, err := randomToken()
	if err != nil {
		return "", err
	}

	tx, err := h.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		"INSERT INTO identities (uuid, name, email) VALUES (?, ?, ?)", 
		uuid, name, email,
	)
	if err != nil {
		return "", err
	}

	if accessToken == nil {
		if _, err := tx.Exec(
			"INSERT INTO providers (identity_id, issuer, subject) VALUES (?, ?, ?)",
			uuid, issuer, subject,
		); err != nil {
			return "", err
		}
		return uuid, tx.Commit()
	}

	encryptedAccessToken, err := encryptToken(h.config.RootKey, []byte(*accessToken))
	if err != nil {
		return "", err
	}

	if _, err := tx.Exec(
		"INSERT INTO providers (identity_id, issuer, subject, access_token) VALUES (?, ?, ?, ?)",
		uuid, issuer, subject, encryptedAccessToken,
	); err != nil {
		return "", err
	}
	return uuid, tx.Commit()
}

// Attach the provider to the identity without triggering.
func (h *Handler) linkProvider(identityId string, issuer, subject, accessToken string) error {
	encryptedAccessToken, err := encryptToken(h.config.RootKey, []byte(accessToken))
	if err != nil {
		return err
	}
	_, err = h.db.Exec(
		`INSERT INTO providers (identity_id, issuer, subject, access_token) VALUES (?, ?, ?, ?)
		 ON CONFLICT (issuer, subject) DO UPDATE SET access_token = excluded.access_token`,
		identityId, issuer, subject, encryptedAccessToken,
	)
	return err
}

func (h *Handler) getProviderToken(identityId string, issuer string) (string, error) {
	var encryptedAccessToken []byte
	err := h.db.QueryRow(
		"SELECT access_token FROM providers WHERE identity_id = ? AND issuer = ?",
		identityId, issuer,
	).Scan(&encryptedAccessToken)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", err
	}

	if len(encryptedAccessToken) == 0 {
		return "", nil
	}

	accessToken, err := decryptToken(h.config.RootKey, encryptedAccessToken)
	if err != nil {
		return "", err
	}
	return string(accessToken), nil
}

func (h *Handler) upsertLogin(issuer, subject, name, email string) (string, bool, error) {
	var identityId string
	err := h.db.QueryRow(
		"SELECT identity_id FROM providers WHERE issuer = ? AND subject = ?",
		issuer, subject,
	).Scan(&identityId)

	switch {
	case err == nil:
		return identityId, false, nil // Existing user, simply just return the matching identity.
	case errors.Is(err, sql.ErrNoRows):
		id, err := h.createIdentityWithProvider(issuer, subject, name, email, nil)
		return id, true, err
	default:
		return "", false, err
	}
}

func (h *Handler) upsertLoginFromClaims(claims oauth.OIDCClaims) (string, bool, error) {
	// This expects `claims` to contain info about name and email.
	name, ok := utils.Get[string](claims.Raw, "name")
	if !ok {
		return "", false, errors.New("name not in claims")
	}

	email, ok := utils.Get[string](claims.Raw, "email")
	if !ok {
		return "", false, errors.New("email not in claims")
	}

	return h.upsertLogin(claims.Issuer, claims.Subject, name, email)
}

// todo(jc): How to connect accounts?
