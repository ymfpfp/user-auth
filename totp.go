package main

func (h *Handler) enableTOTP(identityId string) (string, string, error) {
	// We are going to enable TOTP, which means generating a backup code.
	backupCode, err := randomToken()
	if err != nil {
		return "", "", err
	}

	_, err = h.db.Exec(
		"INSERT INTO codes (identity_id, purpose, code) VALUES (?, ?, ?)",
		identityId, backupPurpose, backupCode,
	)
	if err != nil {
		return "", "", err
	}

	return backupCode, "", nil
}
