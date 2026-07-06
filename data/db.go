package data

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

const (
	INITIAL = `
	CREATE TABLE IF NOT EXISTS identities (
		id INTEGER PRIMARY KEY,
		name TEXT,
		email TEXT,

		-- For email-based login.
		temporary_code TEXT
		code_expires_at INTEGER
	);

	CREATE TABLE IF NOT EXISTS mfa_codes (
		identity_id INTEGER NOT NULL,
		code TEXT NOT NULL,
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);

	CREATE TABLE IF NOT EXISTS providers (
		identity_id INTEGER NOT NULL,
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
		identity_id INTEGER NOT NULL,
		id TEXT PRIMARY KEY,
		ip_address TEXT,
		device TEXT,
		created INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY (identity_id) REFERENCES identities(id)
	);

	CREATE INDEX IF NOT EXISTS user_sessions ON sessions(identity_id);

	CREATE TABLE IF NOT EXISTS activities (
		identity_id INTEGER NOT NULL,
		id INTEGER PRIMARY KEY,
		action TEXT NOT NULL,
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

type Activity struct {
	Id int64
	IdentityId int64
	Action string
	Created int64
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

func EncryptToken(key, plaintext []byte) ([]byte, error) {
	// AES is a block cipher, that is, it encrypts fixed size blocks, and will use CBC
	// for chaining together multiple blocks.
	//
	// Go's `aes.NewCipher` will determine the AES version to used baseed on the byte size
	// of the passed in key, in this case we'll say 32 bytes for AES-256.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// The most widely used AEAD with AES is with Galois/Counter Mode (GCM).
	// AES-GCM is pretty commonly used because it can be parallelized/hardware-accelerated.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Counter (CTR) Mode makes uses of a nonce. By default, the nonce is 12 bytes.
	// It turns a block cipher into a stream cipher. Here, we generate a random base.
	// The 12 bytes are taken and are todo(jc)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Seal prepends nothing; we prepend the nonce ourselves so it travels with the
	// ciphertext.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptToken(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	n := gcm.NonceSize()
	if len(blob) < n {
		return nil, errors.New("Ciphertext too short")
	}
	nonce, ciphertext := blob[:n], blob[n:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
