// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// SnapshotV1 returns a bounded numeric copy from this SAME actual process
// coordinator. Nil org observes global state without creating a tenant account.
// Counts are neither spare capacity, readiness nor retirement authority.
func (r *WorkRuntimeV1) SnapshotV1(org uuid.UUID) (workguard.SnapshotV1, error) {
	if r == nil || !r.MatchesPoolV1(r.pool) {
		return workguard.SnapshotV1{}, ErrWorkRuntimeV1
	}
	return r.coordinator.SnapshotV1(org), nil
}
