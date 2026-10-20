// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"context"
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// Called only after the actual original synchronous helper returned, including
// its own deferred cleanup. Cancellation and panic cannot emit healthy ticks.
func (w *worker) reportInvocation385(ctx context.Context, job flarereport.CriticalJob, started time.Time, state flarereport.JobInvocationState) {
	if w == nil {
		return
	}
	w.telemetry.RecordJobInvocation(ctx, flarereport.JobInvocation{Job: job, State: state, Duration: time.Since(started)})
}
func mergeWorkerInvocation385(a, b flarereport.JobInvocationState) flarereport.JobInvocationState {
	for _, state := range []flarereport.JobInvocationState{flarereport.InvocationUnobservable, flarereport.InvocationUnavailable, flarereport.InvocationPartial, flarereport.InvocationPending} {
		if a == state || b == state {
			return state
		}
	}
	if a == flarereport.InvocationReturned && b == flarereport.InvocationReturned {
		return flarereport.InvocationReturned
	}
	return flarereport.InvocationUnobservable
}

// Only already exposed fixed scalar observation fields are inspected within
// the original owned callback. No receipt, subject or private payload is kept.
func packageRecoveryState385(outcome pdfadmission.HTMLSendPackageAttemptOutcomeV1, completionVerified bool, status string) flarereport.JobInvocationState {
	if completionVerified {
		return flarereport.InvocationReturned
	}
	switch outcome {
	case pdfadmission.HTMLSendPackageAttemptActiveV1:
		if status == "draft" {
			return flarereport.InvocationReturned
		} // expired/aborted invocation, no completion claim
		return flarereport.InvocationPending
	case pdfadmission.HTMLSendPackageAttemptCompletedV1, pdfadmission.HTMLSendPackageAttemptAbortedV1:
		// Historical terminal state is not new completion/replay authority.
		return flarereport.InvocationReturned
	default:
		return flarereport.InvocationUnobservable
	}
}
