// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/jackc/pgx/v5/pgtype"
)

type emailAttemptOutcome uint8

const (
	emailCheckpointFailed emailAttemptOutcome = iota
	emailSentAcknowledged
	emailRetryAcknowledged
	emailFailureAcknowledged
)

// Existing rows already owned by the original serial job are projected only to
// scalar ages. Invalid/infinite/future times are unknown, never a fabricated0.
func observeJobAge(tick *flarereport.JobTick, stamp pgtype.Timestamptz) {
	// Later leases can contain rows created after an earlier poll began. Observe
	// each actual selected row now, not relative to the start of a long SMTP pass.
	observeJobAgeAt(tick, time.Now(), stamp)
}

func observeJobAgeAt(tick *flarereport.JobTick, now time.Time, stamp pgtype.Timestamptz) {
	if !stamp.Valid || stamp.InfinityModifier != pgtype.Finite || stamp.Time.After(now) {
		tick.UnknownAges++
		return
	}
	age := now.Unix() - stamp.Time.Unix()
	if age > tick.OldestSelectedAgeSeconds {
		tick.OldestSelectedAgeSeconds = age
	}
}
