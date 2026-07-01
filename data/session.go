package data

import (
	"crypto/rand"
	"encoding/hex"
)

type Sessions struct {
	Sessions map[string]map[string]any
}

func EmptySession() Sessions {
	return Sessions{
		Sessions: make(map[string]map[string]any),
	}
}

func NewSessionId() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

