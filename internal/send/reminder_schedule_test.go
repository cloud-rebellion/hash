// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"testing"
	"time"
)

func TestAutomaticReminderCadenceAndValidation(t *testing.T) {
	sent := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	next, err := nextAutomaticReminder([]byte(`[{"days_after_send":3},{"days_after_send":7}]`), 2, sent)
	if err != nil || !next.Equal(sent.Add(7*24*time.Hour)) {
		t.Fatalf("day7 drifted %v %v", next, err)
	}
	for _, raw := range []string{`null`, `broken`, `[{"days_after_send":0}]`, `[{"days_after_send":366}]`, `[{"days_after_send":7},{"days_after_send":3}]`} {
		if _, err := nextAutomaticReminder([]byte(raw), 1, sent); err == nil {
			t.Fatalf("invalid schedule accepted: %s", raw)
		}
	}
}
