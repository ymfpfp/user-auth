package main

import (
	"context"
	"time"

	"go.uber.org/zap"
)

func (h *Handler) recordActivity(ctx context.Context, identityId string, action string) {
	_, err := h.db.Exec(
		"INSERT INTO activities (identity_id, action, created_at) VALUES (?, ?, ?)",
		identityId, action, time.Now().Unix(),
	)
	if err != nil {
		logger := loggerFromContext(ctx)
		logger.Error(
			"record activity",
			zap.String("identityId", identityId),
			zap.String("activity", action),
			zap.Error(err),
		)
	}
}

func (h *Handler) getRecentActivities(identityId string, limit int) ([]Activity, error) {
	var activities []Activity

	rows, err := h.db.Query(
		`SELECT id, identity_id, action, created_at
		 FROM activities
		 WHERE identity_id = ?
		 ORDER BY created_at DESC
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
			&activity.CreatedAt,
		); err != nil {
			return activities, err
		}
		activities = append(activities, activity)
	}

	return activities, rows.Err()
}
