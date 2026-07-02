package data

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

const (
	INITIAL = `
	CREATE TABLE IF NOT EXISTS identities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		email TEXT
	);

	CREATE TABLE IF NOT EXISTS providers (
		id INTEGER,
		FOREIGN KEY (id) REFERENCES identities(id),
		issuer STRING,
		subject STRING,
		(issuer, subject) PRIMARY KEY
	);
	`
)

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
