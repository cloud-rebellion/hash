// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"context"

	"github.com/bright-interaction/hash/internal/sanitize"
)

// PDFWorkerObserverV1 is installed only by the parent server/worker mains using
// their fixed boot context. It is synchronous and uses the existing bounded
// fixed-schema operation path. No error, request context, bytes, identities or
// worker diagnostics cross this interface. Probe traffic keeps its existing
// startup/readiness signals and is excluded from document-work attempt counts.
func PDFWorkerObserverV1(ctx context.Context) sanitize.PDFWorkerObserverV1 {
	if ctx == nil {
		ctx = context.Background()
	}
	return func(observation sanitize.PDFWorkerObservationV1) {
		switch observation.Operation {
		case sanitize.PDFWorkerOperationCleanV1, sanitize.PDFWorkerOperationPagesV1,
			sanitize.PDFWorkerOperationComposeV1, sanitize.PDFWorkerOperationProviderOverlayV1,
			sanitize.PDFWorkerOperationManualInspectV1, sanitize.PDFWorkerOperationManualOverlayV1,
			sanitize.PDFWorkerOperationManualLayersV1, sanitize.PDFWorkerOperationManualFragmentV1:
		default:
			return
		}
		var outcome Outcome
		switch observation.Outcome {
		case sanitize.PDFWorkerOutcomeSuccessV1:
			outcome = OutcomeSuccess
		case sanitize.PDFWorkerOutcomeRejectedV1, sanitize.PDFWorkerOutcomeCapacityV1:
			outcome = OutcomeRejected
		case sanitize.PDFWorkerOutcomeCanceledV1:
			outcome = OutcomeCanceled
		case sanitize.PDFWorkerOutcomeUnavailableV1:
			outcome = OutcomeUnavailable
		case sanitize.PDFWorkerOutcomeTimeoutV1:
			outcome = OutcomeTimeout
		case sanitize.PDFWorkerOutcomeInternalV1:
			outcome = OutcomeInternal
		default:
			return
		}
		ObserveOperation(ctx, OperationPDF, outcome, observation.Elapsed)
	}
}
