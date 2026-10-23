// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"time"
)

// Fresh per-attempt checks apply only to the reserved internal purpose header.
// The header selects this check; only immutable native queue/event references
// grant it. No ordinary email is reclassified by recipient/subject guessing.
func (w *worker) checkAmendmentOwnerAlertV1(ctx context.Context, id uuid.UUID) (bool, error) {
	if w == nil || w.pool == nil || id == uuid.Nil {
		return false, errors.New("amendment owner alert eligibility unavailable")
	}
	use, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var allowed bool
	e := w.pool.QueryRow(use, `SELECT hash_amendment_owner_alert_dispatch_eligible_v1($1)`, id).Scan(&allowed) //nolint:rawsql -- fixed native owner-alert function, no message or credentials accepted
	return allowed, e
}
