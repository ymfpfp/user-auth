package main

import (
	"time"
)

func (h *Handler) createSession(identityId string, ip, device string, ttl time.Duration) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	_, err = h.db.Exec(
		`INSERT INTO sessions (id, identity_id, ip_address, device, created, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		hashToken(token), identityId, ip, device, now, now + int64(ttl.Seconds()),
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (h *Handler) getSession(sessionId string) (Session, error) {
	var session Session
	err := h.db.QueryRow(
		`SELECT s.id, i.name, i.email, s.identity_id, s.ip_address, s.device, s.created, s.expires_at
		 FROM sessions s
		 JOIN identities i ON i.uuid = s.identity_id
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

func (h *Handler) getActiveSessions(identityId string) ([]Session, error) {
	var sessions []Session

	rows, err := h.db.Query("SELECT * FROM sessions WHERE identity_id = ?", identityId)
	if err != nil {
		return sessions, nil
	}
	defer rows.Close()

	for rows.Next() {
		var session Session
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

func (h *Handler) revokeSession(sessionId string) error {
	hashedSessionId := hashToken(sessionId)
	_, err := h.db.Exec("DELETE FROM sessions WHERE id = ?", hashedSessionId)
	return err
}
