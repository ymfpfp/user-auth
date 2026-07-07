package main

import (
	"time"
)

func (h *Handler) recordActivity(identityId string, action string) error {
	_, err := h.db.Exec(
		"INSERT INTO activities (identity_id, action, created) VALUES (?, ?, ?)",
		identityId, action, time.Now().Unix(),
	)
	return err
}

func (h *Handler) getRecentActivities(identityId string, limit int) ([]Activity, error) {
	var activities []Activity

	rows, err := h.db.Query(
		`SELECT id, identity_id, action, created
		 FROM activities
		 WHERE identity_id = ?
		 ORDER BY created DESC
		 LIMIT ?`,
		identityId, limit,
	)
	if err != nil {
		return activities, err
	}
	defer rows.Close()

	for rows.Next() {
		var activity Activity
		if err := rows.Scan(
			&activity.Id,
			&activity.IdentityId,
			&activity.Action,
			&activity.Created,
		); err != nil {
			return activities, err
		}
		activities = append(activities, activity)
	}

	return activities, rows.Err()
}
