package main

import (
	"database/sql"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	// Public identifier.
	ClientId string
	ClientSecret string
}

func main() {
	config := Config {
		ClientId: os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
	}

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	stmt := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		email TEXT
	);
	CREATE TABLE IF NOT EXISTS oauth (
		user_id INTEGER,
		provider TEXT,
		subject TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id),
		PRIMARY KEY (provider, subject)
	);
	`

	_, err = db.Exec(stmt)
	if err != nil {
		log.Fatal("Failed to set up db", err)
	}

	h := &Handler{
		db: db,
		config: &config,
		sessions: EmptySession(),
	}

	server := &http.Server{
		Addr: "127.0.0.1:9000",
		Handler: http.TimeoutHandler(
			h.Mux(),
			2 * time.Minute,
			"",
		),
		IdleTimeout: 5 * time.Minute,
		ReadHeaderTimeout: time.Minute,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Print("Listening on ", server.Addr)
	err = server.Serve(listener)
	if err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

