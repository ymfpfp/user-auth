package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func encryptToken(key, plaintext []byte) ([]byte, error) {
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

func decryptToken(key, blob []byte) ([]byte, error) {
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

const temporaryCodeTTL = 15 * time.Minute

const (
	backupPurpose  string = "backup"
	emailPurpose   string = "email"
	passkeyPurpose string = "passkey"
)

func (h *Handler) newTemporaryCode(identityId, purpose string) (string, error) {
	code, err := randomToken()
	if err != nil {
		return "", err
	}
	_, err = h.db.Exec(
		"INSERT INTO codes (identity_id, purpose, code, expires_at) VALUES (?, ?, ?, ?)",
		identityId, purpose, hashToken(code), time.Now().Add(temporaryCodeTTL).Unix(),
	)
	if err != nil {
		return "", err
	}
	return code, nil
}

func (h *Handler) getTemporaryCode(code, purpose string) (TemporaryCode, error) {
	var temporaryCode TemporaryCode
	err := h.db.QueryRow(
		"SELECT * FROM codes WHERE code = ? AND purpose = ?",
		code, purpose,
	).Scan(
		&temporaryCode.Id,
		&temporaryCode.IdentityId,
		&temporaryCode.Purpose,
		&temporaryCode.Code,
		&temporaryCode.ExpiresAt,
	)
	if err != nil {
		return temporaryCode, err
	}
	return temporaryCode, nil
}

func (h *Handler) getTemporaryCodeFromId(id int64) (TemporaryCode, error) {
	var temporaryCode TemporaryCode
	err := h.db.QueryRow("SELECT * FROM codes WHERE id = ?", id).Scan(
		&temporaryCode.Id,
		&temporaryCode.IdentityId,
		&temporaryCode.Purpose,
		&temporaryCode.Code,
		&temporaryCode.ExpiresAt,
	)
	if err != nil {
		return temporaryCode, nil
	}
	return temporaryCode, nil
}

func getTemporaryCodeWithTx(tx *sql.Tx, code, purpose string) (TemporaryCode, error) {
	var temporaryCode TemporaryCode
	err := tx.QueryRow(
		"SELECT * FROM codes WHERE code = ? AND purpose = ?",
		code, purpose,
	).Scan(
		&temporaryCode.Id,
		&temporaryCode.IdentityId,
		&temporaryCode.Purpose,
		&temporaryCode.Code,
		&temporaryCode.ExpiresAt,
	)
	if err != nil {
		return temporaryCode, err
	}
	return temporaryCode, nil
}

func (h *Handler) deleteTemporaryCode(id int64) error {
	_, err := h.db.Exec("DELETE FROM codes WHERE id = ?", id)
	return err
}

func deleteTemporaryCodeWithTx(tx *sql.Tx, id int64) error {
	_, err := tx.Exec("DELETE FROM codes WHERE id = ?", id)
	return err
}
