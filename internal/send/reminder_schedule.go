// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"github.com/bright-interaction/hash/internal/remindercadence"
	"time"
)

func nextAutomaticReminder(raw []byte, remaining int, sentAt time.Time) (time.Time, error) {
	return remindercadence.NextV1(raw, remaining, sentAt)
}
