package data

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

const (
	INITIAL = `
	CREATE TABLE IF NOT EXISTS identities (
		id INTEGER PRIMARY KEY,
		name TEXT,
		email TEXT
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		identity_id INTEGER NOT NULL,
		ip_address STRING,
		device STRING,
		created INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);

	CREATE INDEX IF NOT EXISTS user_sessions ON sessions(identity_id);

	CREATE TABLE IF NOT EXISTS providers (
		identity_id INTEGER,
		issuer TEXT NOT NULL,
		subject TEXT NOT NULL,
		FOREIGN KEY (identity_id) REFERENCES identities(id),
		PRIMARY KEY (issuer, subject)
	);

	CREATE INDEX IF NOT EXISTS user_providers ON providers(identity_id);

	CREATE TABLE IF NOT EXISTS activities (
		id INTEGER PRIMARY KEY,
		identity_id INTEGER NOT NULL,
		action STRING NOT NULL,
		created INTEGER NOT NULL, 
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);
	`
)

type Session struct {
	Id string
	Name string
	Email string

	IdentityId int64
	IpAddr string
	Device string
	Created int64
	ExpiresAt int64
}

func NewDb() *sql.DB {
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
