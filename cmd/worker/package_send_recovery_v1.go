// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
)

// The process-authorized batch retains the exact frozen members, then commits
// the original ceremony epoch, tokens, durable invitation queue and audit once.
// It never falls back to direct SMTP or activates nonempty package signing.
func (w *worker) runPackageSendRecoveryOnceV1(ctx context.Context) {
	started := time.Now()
	state := w.runPackageSendRecoveryOnceV1Observed(ctx)
	w.reportInvocation385(ctx, flarereport.JobPackageSendRecovery, started, state)
}
func (w *worker) runPackageSendRecoveryOnceV1Observed(ctx context.Context) flarereport.JobInvocationState {
	if w == nil || w.sendEngine == nil || w.sendEngine.WorkRuntime == nil || !w.sendEngine.WorkRuntime.MatchesPoolV1(w.pool) {
		return flarereport.InvocationUnavailable
	}
	client, ok := w.sendEngine.Storage.(*storage.Client)
	if !ok || client == nil {
		slog.Warn("package_send_recovery: original storage client unavailable")
		return flarereport.InvocationUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	batch, err := w.sendEngine.WorkRuntime.SessionsV1().ScanPendingPackageSendRecoveryV1(call, w.packageSendRecoveryCursor)
	if batch != nil {
		defer batch.CloseConsumerV1()
	}
	if err != nil {
		slog.Warn("package_send_recovery: discovery failed", "error_type", fmt.Sprintf("%T", err))
		return flarereport.InvocationUnavailable
	}
	state := flarereport.InvocationReturned
	processed := false
	for {
		more, err := batch.WithNextSendV1(client, pdfadmission.PackageSendCompletionConfigV1{PublicURL: w.sendEngine.PublicURL, OrgName: w.sendEngine.OrgName, Audit: w.sendEngine.Audit}, func(o pdfadmission.HTMLSendPackageSendObservationV1) error {
			state = mergeWorkerInvocation385(state, packageRecoveryState385(o.Attempt.Outcome, o.CompletionVerified, o.Status))
			slog.Debug("package_send_recovery: exact persisted attempt processed", "attempt_id", o.Attempt.AttemptID, "outcome", o.Attempt.Outcome, "retention_verified", o.RetentionVerified, "completion_verified", o.CompletionVerified, "status", o.Status)
			return nil
		})
		if more {
			processed = true
			w.packageSendRecoveryCursor = batch.CursorV1()
		}
		if err != nil {
			state = mergeWorkerInvocation385(state, flarereport.InvocationPartial)
			slog.Warn("package_send_recovery: inspection refused", "attempt_id", batch.CursorV1().AttemptID, "error_type", fmt.Sprintf("%T", err))
		}
		if !more || call.Err() != nil {
			if !more && err == nil && !processed {
				w.packageSendRecoveryCursor = pdfadmission.PackageSendRecoveryCursorV1{}
			}
			if call.Err() != nil {
				return flarereport.InvocationUnavailable
			}
			return state
		}
	}
}
