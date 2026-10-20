// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package remindercadence

import (
	"encoding/json"
	"errors"
	"time"
)

// Original unchanged reminder cadence policy, shared by native schedule
// mutation and the existing send policy tests. It grants no SQL authority.
func NextV1(raw []byte, remaining int, sentAt time.Time) (time.Time, error) {
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
