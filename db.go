package main

import (
	"database/sql"
	"log"

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
		identity_id TEXT NOT NULL,
		purpose TEXT NOT NULL,
		code TEXT NOT NULL,
		-- Backup codes don't necessarily have these.
		expires_at INTEGER,
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);

	CREATE INDEX IF NOT EXISTS user_codes ON codes(identity_id, code);

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
		created INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);

	CREATE INDEX IF NOT EXISTS user_sessions ON sessions(identity_id);

	CREATE TABLE IF NOT EXISTS activities (
		identity_id TEXT NOT NULL,
		id INTEGER PRIMARY KEY,
		action TEXT NOT NULL,
		created INTEGER NOT NULL, 
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);
	`
)

type Activity struct {
	Id         int64
	IdentityId string
	Action     string
	Created    int64
}

type Session struct {
	Id    string
	Name  string
	Email string

	IdentityId string
	IpAddr     string
	Device     string
	Created    int64
	ExpiresAt  int64
}

type TemporaryCode struct {
	Id         int64
	IdentityId string
	Purpose    string
	Code       string
	ExpiresAt  int64
}

func newDB() *sql.DB {
	db, err := sql.Open("sqlite3", "file:test.db")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(INITIAL)
	if err != nil {
		log.Fatal("Failed to set up db ", err)
	}
	return db
}
