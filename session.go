package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/ymfpfp/user-auth/data"
	"github.com/ymfpfp/user-auth/oauth"
	"github.com/ymfpfp/user-auth/utils"
)

// Tiny helper function to encode tokens at rest.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (h Handler) CreateIdentity(name, email string) (int64, error) {
	result, err := h.db.Exec(
		"INSERT INTO identities (name, email) VALUES (?, ?)",
		name, email,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// Attach the provider to the identity without triggering.
func (h Handler) LinkProvider(identityId int64, issuer, subject, accessToken string) error {
	encryptedAccessToken, err := data.EncryptToken(h.config.RootKey, []byte(accessToken))
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

func (h Handler) CreateIdentityWithProvider(issuer, subject, name, email string, accessToken *string) (int64, error) {
	tx, err := h.db.Begin()
	if err != nil {
		return -1, err
	}
	defer tx.Rollback()

	result, err := tx.Exec("INSERT INTO identities (name, email) VALUES (?, ?)", name, email)
	if err != nil {
		return -1, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return -1, err
	}

	if accessToken == nil {
		if _, err := tx.Exec(
			"INSERT INTO providers (identity_id, issuer, subject) VALUES (?, ?, ?)",
			id, issuer, subject,
		); err != nil {
			return 0, err
		}
		return id, tx.Commit()
	}

	encryptedAccessToken, err := data.EncryptToken(h.config.RootKey, []byte(*accessToken))
	if err != nil {
		return -1, err
	}

	if _, err := tx.Exec(
		"INSERT INTO providers (identity_id, issuer, subject, access_token) VALUES (?, ?, ?, ?)",
		id, issuer, subject, encryptedAccessToken,
	); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func (h Handler) GetProviderToken(identityId int64, issuer string) (string, error) {
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

	accessToken, err := data.DecryptToken(h.config.RootKey, encryptedAccessToken)
	if err != nil {
		return "", err
	}
	return string(accessToken), nil
}

func (h Handler) CreateSession(identityId int64, ip, device string, ttl time.Duration) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	now := time.Now().Unix()
	_, err := h.db.Exec(
		`INSERT INTO sessions (id, identity_id, ip_address, device, created, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		hashToken(token), identityId, ip, device, now, now + int64(ttl.Seconds()),
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (h Handler) GetSession(sessionId string) (data.Session, error) {
	var session data.Session
	err := h.db.QueryRow(
		`SELECT s.id, i.name, i.email, s.identity_id, s.ip_address, s.device, s.created, s.expires_at
		 FROM sessions s
		 JOIN identities i ON i.id = s.identity_id
		 WHERE s.id = ?`,
		hashToken(sessionId),
	).Scan(
		&session.Id,
		&session.Name,
		&session.Email,
		&session.IdentityId,
		&session.IpAddr,
		&session.Device,
		&session.Created,
		&session.ExpiresAt,
	)
	if err != nil {
		return session, err
	}
	session.Id = sessionId
	return session, nil
}

func (h Handler) RevokeSession(sessionId string) error {
	hashedSessionId := hashToken(sessionId)
	_, err := h.db.Exec("DELETE FROM sessions WHERE id = ?", hashedSessionId)
	return err
}

func (h Handler) GetActiveSessions(identityId int64) ([]data.Session, error) {
	var sessions []data.Session

	rows, err := h.db.Query("SELECT * FROM sessions WHERE identity_id = ?", identityId)
	if err != nil {
		return sessions, nil
	}
	defer rows.Close()

	for rows.Next() {
		var session data.Session
		err := rows.Scan(
			&session.Id, 
			&session.IdentityId, 
			&session.IpAddr, 
			&session.Device, 
			&session.Created, 
			&session.ExpiresAt,
		)
		if err != nil {
			return sessions, nil
		}
		sessions = append(sessions, session)
	}

	return sessions, rows.Err()
}

func (h Handler) RecordActivity(identityId int64, action string) error {
	_, err := h.db.Exec(
		"INSERT INTO activities (identity_id, action, created) VALUES (?, ?, ?)",
		identityId, action, time.Now().Unix(),
	)
	return err
}

func (h Handler) GetRecentActivities(identityId int64, limit int) ([]data.Activity, error) {
	var activities []data.Activity

	rows, err := h.db.Query(
		`SELECT id, identity_id, action, created
		 FROM activities
		 WHERE identity_id = ?
		 ORDER BY created DESC
		 LIMIT ?`,
		identityId, limit,
	)
	if err != nil {
		return activities, err
	}
	defer rows.Close()

	for rows.Next() {
		var activity data.Activity
		if err := rows.Scan(
			&activity.Id,
			&activity.IdentityId,
			&activity.Action,
			&activity.Created,
		); err != nil {
			return activities, err
		}
		activities = append(activities, activity)
	}

	return activities, rows.Err()
}

func (h Handler) UpsertLogin(issuer, subject, name, email string) (int64, bool, error) {
	var identityId int64
	err := h.db.QueryRow(
		"SELECT identity_id FROM providers WHERE issuer = ? AND subject = ?",
		issuer, subject,
	).Scan(&identityId)

	switch {
	case err == nil:
		return identityId, false, nil // Existing user, simply just return the matching identity.
	case errors.Is(err, sql.ErrNoRows):
		id, err := h.CreateIdentityWithProvider(issuer, subject, name, email, nil)
		return id, true, err
	default:
		return -1, false, err
	}
}

func (h Handler) UpsertLoginFromClaims(claims oauth.OIDCClaims) (int64, bool, error) {
	// This expects `claims` to contain info about name and email.
	name, ok := utils.Get[string](claims.Raw, "name")
	if !ok {
		return -1, false, errors.New("name not in claims")
	}

	email, ok := utils.Get[string](claims.Raw, "email")
	if !ok {
		return -1, false, errors.New("email not in claims")
	}

	return h.UpsertLogin(claims.Issuer, claims.Subject, name, email)
}

// todo(jc): How to connect accounts?
