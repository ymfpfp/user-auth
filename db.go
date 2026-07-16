package main

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

const (
	INITIAL = `
	CREATE TABLE IF NOT EXISTS identities (
		uuid TEXT PRIMARY KEY,
		name TEXT,
		email TEXT UNIQUE,
		mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE
	);

	CREATE TABLE IF NOT EXISTS codes (
		id INTEGER PRIMARY KEY,
		-- Logging in with a passkey means we have to generate a temp session id,
		-- unattached to a user. 
		identity_id TEXT,
		purpose TEXT NOT NULL,
		code TEXT NOT NULL,
		-- Backup codes don't necessarily have these.
		expires_at INTEGER,
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);

	CREATE INDEX IF NOT EXISTS user_codes ON codes(identity_id, code);

	CREATE TABLE IF NOT EXISTS passkeys (
		id TEXT,
		identity_id TEXT NOT NULL,
		-- This is the public key.
		credential BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		FOREIGN KEY (identity_id) REFERENCES identities(id),
		PRIMARY KEY (identity_id, id)
	);

	CREATE INDEX IF NOT EXISTS user_passkeys ON passkeys(identity_id);

	CREATE TABLE IF NOT EXISTS providers (
		identity_id TEXT NOT NULL,
		issuer TEXT NOT NULL,
		subject TEXT NOT NULL,
		access_token BLOB,
		refresh_token BLOB,
		expires_at INTEGER,
		FOREIGN KEY (identity_id) REFERENCES identities(id),
		PRIMARY KEY (issuer, subject)
	);

	CREATE INDEX IF NOT EXISTS user_providers ON providers(identity_id);

	CREATE TABLE IF NOT EXISTS sessions (
		identity_id TEXT NOT NULL,
		id TEXT PRIMARY KEY,
		ip_address TEXT,
		device TEXT,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);

	CREATE INDEX IF NOT EXISTS user_sessions ON sessions(identity_id);

	CREATE TABLE IF NOT EXISTS activities (
		identity_id TEXT NOT NULL,
		id INTEGER PRIMARY KEY,
		action TEXT NOT NULL,
		created_at INTEGER NOT NULL, 
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);
	`
)

type Activity struct {
	Id         int64
	IdentityId string
	Action     string
	CreatedAt  int64
}

type Session struct {
	Id    string
	Name  string
	Email string

	IdentityId string
	IpAddr     string
	Device     string
	CreatedAt  int64
	ExpiresAt  int64
}

type TemporaryCode struct {
	Id         int64
	IdentityId string
	Purpose    string
	Code       string
	ExpiresAt  int64
}

type Passkey struct {
	Id         string
	IdentityId string
	Credential []byte
	CreatedAt  int64
}

func newDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "file:test.db")
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(INITIAL)
	if err != nil {
		return nil, err
	}
	return db, nil
}
