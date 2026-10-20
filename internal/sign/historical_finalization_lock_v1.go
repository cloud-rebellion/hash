// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"log/slog"
	"time"
)

func (e *Engine) acquireHistoricalFinalizationLockV1(ctx context.Context, org, document uuid.UUID) (*pdfadmission.ApplicationHistoricalFinalizationLockV1, error) {
	if e == nil || ctx == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	lock, err := e.WorkRuntime.SessionsV1().NewHistoricalFinalizationLockV1(ctx, org, document)
	if errors.Is(err, pdfadmission.ErrHistoricalFinalizationBusyV1) {
		return nil, ErrFinalizeInProgress
	}
	if err != nil {
		return nil, errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	return lock, nil
}
func closeHistoricalFinalizationLockV1(original context.Context, lock *pdfadmission.ApplicationHistoricalFinalizationLockV1, org, document uuid.UUID) {
	if original == nil || lock == nil {
		return
	}
	cleanup, stop := context.WithTimeout(context.WithoutCancel(original), 5*time.Second)
	defer stop()
	if err := lock.CloseV1(cleanup); err != nil {
		slog.Error("finalization serialization retirement unresolved", "org_id", org, "document_id", document, "err", err)
	}
}
