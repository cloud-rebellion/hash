// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"encoding/json"
	"errors"
	"time"
)

// Advance under the same transaction as token rotation, mail and audit.
func nextAutomaticReminder(raw []byte, remaining int, sentAt time.Time) (time.Time, error) {
	var schedule []struct {
		Days int `json:"days_after_send"`
	}
	if err := json.Unmarshal(raw, &schedule); err != nil {
		return time.Time{}, errors.New("invalid automatic reminder schedule")
	}
	if remaining <= 0 || remaining > len(schedule) {
		return time.Time{}, errors.New("invalid automatic reminder count")
	}
	previous := 0
	for _, entry := range schedule {
		if entry.Days <= previous || entry.Days > 365 {
			return time.Time{}, errors.New("automatic reminder offsets must increase within 365 days")
		}
		previous = entry.Days
	}
	idx := len(schedule) - remaining + 1
	if idx >= len(schedule) {
		return sentAt.Add(365 * 24 * time.Hour), nil
	}
	return sentAt.Add(time.Duration(schedule[idx].Days) * 24 * time.Hour), nil
}
