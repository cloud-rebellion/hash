// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"testing"
)

// These are scalar classification tests, not forged native/effect receipts.
func Test385PackageRecoveryStateNeverInventsCompletionOrHistoricalReplay(t *testing.T) {
	cases := []struct {
		name     string
		outcome  pdfadmission.HTMLSendPackageAttemptOutcomeV1
		verified bool
		status   string
		want     flarereport.JobInvocationState
	}{
		{"active", pdfadmission.HTMLSendPackageAttemptActiveV1, false, "sealing", flarereport.InvocationPending},
		{"verified returned", pdfadmission.HTMLSendPackageAttemptCompletedV1, true, "sent", flarereport.InvocationReturned},
		{"historical completed not replay", pdfadmission.HTMLSendPackageAttemptCompletedV1, false, "", flarereport.InvocationReturned},
		{"historical aborted", pdfadmission.HTMLSendPackageAttemptAbortedV1, false, "draft", flarereport.InvocationReturned},
		{"aborted in actual invocation", pdfadmission.HTMLSendPackageAttemptActiveV1, false, "draft", flarereport.InvocationReturned},
		{"missing", pdfadmission.HTMLSendPackageAttemptMissingV1, false, "", flarereport.InvocationUnobservable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := packageRecoveryState385(c.outcome, c.verified, c.status); got != c.want {
				t.Fatal("wrong invocation-only classification", got, c.want)
			}
		})
	}
}
func Test385PerItemFailureCannotBeClearedByLaterSuccessOrPending(t *testing.T) {
	state := flarereport.InvocationReturned
	for _, next := range []flarereport.JobInvocationState{flarereport.InvocationPending, flarereport.InvocationPartial, flarereport.InvocationReturned} {
		state = mergeWorkerInvocation385(state, next)
	}
	if state != flarereport.InvocationPartial {
		t.Fatal("later no-op/success cleared real per-item failure")
	}
	if got := mergeWorkerInvocation385(state, flarereport.InvocationUnavailable); got != flarereport.InvocationUnavailable {
		t.Fatal("dependency refusal was hidden")
	}
	if got := mergeWorkerInvocation385(flarereport.InvocationReturned, "unknown"); got != flarereport.InvocationUnobservable {
		t.Fatal("unknown observation fabricated healthy completion")
	}
}
