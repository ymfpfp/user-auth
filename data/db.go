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
	`
)

func NewDb() *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(INITIAL)
	if err != nil {
		log.Fatal("Failed to set up db ", err)
	}
	return db
}
