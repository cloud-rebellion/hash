// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// ErrPDFInvalid preserves the existing coherent child refusal's public text.
// It never wraps parser text, protocol failures or an arbitrary caller error.
var ErrPDFInvalid = errors.New("sanitize: invalid PDF")

type PDFWorkerOperationV1 uint8

const (
	PDFWorkerOperationUnknownV1 PDFWorkerOperationV1 = iota
	PDFWorkerOperationProbeV1
	PDFWorkerOperationCleanV1
	PDFWorkerOperationPagesV1
	PDFWorkerOperationComposeV1
	PDFWorkerOperationProviderOverlayV1
	PDFWorkerOperationManualInspectV1
	PDFWorkerOperationManualOverlayV1
	PDFWorkerOperationManualLayersV1
	PDFWorkerOperationManualFragmentV1
)

type PDFWorkerOutcomeV1 uint8

const (
	PDFWorkerOutcomeUnknownV1 PDFWorkerOutcomeV1 = iota
	PDFWorkerOutcomeSuccessV1
	PDFWorkerOutcomeRejectedV1
	PDFWorkerOutcomeCapacityV1
	PDFWorkerOutcomeCanceledV1
	PDFWorkerOutcomeUnavailableV1
	PDFWorkerOutcomeTimeoutV1
	PDFWorkerOutcomeInternalV1
)

// PDFWorkerObservationV1 describes the bounded runner attempt's return only.
// Preflight refusals may never start a process. Unavailable does not distinguish
// start failure, crash or bad protocol. No native consumer/grant retirement,
// stored-output durability or successful application operation is implied.
// Values contain no reference to PDF bytes, errors, caller context or identity.
type PDFWorkerObservationV1 struct {
	Operation PDFWorkerOperationV1
	Outcome   PDFWorkerOutcomeV1
	Elapsed   time.Duration
}

// PDFWorkerObserverV1 is fixed trusted parent-boot code, not a request-supplied
// callback. The instance retains it immutably. It must return promptly and may
// not grant admission, close native consumers or alter the processing result.
type PDFWorkerObserverV1 func(PDFWorkerObservationV1)

var pdfWorkerObserverPanicsV1 atomic.Uint64

// PDFWorkerObserverPanicsV1 counts fixed callback failures without exposing a
// panic value. It creates no queue or exported diagnostics acceptance claim.
func PDFWorkerObserverPanicsV1() uint64 { return pdfWorkerObserverPanicsV1.Load() }

func (w *pdfWorker) run(parent context.Context, request pdfWorkerRequest, raw []byte) (pdfWorkerResponse, []byte, error) {
	if w.observer == nil {
		return w.runBoundedV1(parent, request, raw)
	}
	started := time.Now()
	response, body, err := w.runBoundedV1(parent, request, raw)
	// Every original core defer (cancel and acquired worker slot) has returned.
	// This is not a receipt for outer callers' retained native work or buffers.
	observation := PDFWorkerObservationV1{
		Operation: pdfWorkerOperationV1(request.Operation),
		Outcome:   pdfWorkerOutcomeV1(parent, err),
		Elapsed:   time.Since(started),
	}
	w.observeV1(observation)
	return response, body, err
}

func (w *pdfWorker) observeV1(observation PDFWorkerObservationV1) {
	defer func() {
		if recover() != nil {
			pdfWorkerObserverPanicsV1.Add(1)
		}
	}()
	w.observer(observation)
}

func pdfWorkerOperationV1(operation string) PDFWorkerOperationV1 {
	switch operation {
	case "probe":
		return PDFWorkerOperationProbeV1
	case "clean":
		return PDFWorkerOperationCleanV1
	case "pages":
		return PDFWorkerOperationPagesV1
	case pdfComposeSigningPageOperation:
		return PDFWorkerOperationComposeV1
	case pdfProviderOverlayOperation:
		return PDFWorkerOperationProviderOverlayV1
	case pdfManualInspectOperation:
		return PDFWorkerOperationManualInspectV1
	case pdfManualOverlayOperation:
		return PDFWorkerOperationManualOverlayV1
	case pdfManualLayersOperation:
		return PDFWorkerOperationManualLayersV1
	case pdfManualFragmentOperation:
		return PDFWorkerOperationManualFragmentV1
	default:
		return PDFWorkerOperationUnknownV1
	}
}

func pdfWorkerOutcomeV1(parent context.Context, err error) PDFWorkerOutcomeV1 {
	if err == nil {
		return PDFWorkerOutcomeSuccessV1
	}
	if parent != nil && parent.Err() != nil {
		return PDFWorkerOutcomeCanceledV1
	}
	switch {
	case errors.Is(err, ErrPDFWorkerCapacity):
		return PDFWorkerOutcomeCapacityV1
	case errors.Is(err, ErrPDFTooLarge), errors.Is(err, ErrTooManyPages), errors.Is(err, ErrActivePDFContent), errors.Is(err, ErrPDFInvalid), errors.Is(err, ErrPDFProviderOverlay), errors.Is(err, ErrPDFSigningPageInvalid), errors.Is(err, ErrPDFManualOverlay), errors.Is(err, ErrPDFManualLayers), errors.Is(err, ErrPDFManualFragment):
		return PDFWorkerOutcomeRejectedV1
	case errors.Is(err, context.DeadlineExceeded):
		return PDFWorkerOutcomeTimeoutV1
	case errors.Is(err, context.Canceled):
		return PDFWorkerOutcomeCanceledV1
	case errors.Is(err, ErrPDFWorkerUnavailable):
		return PDFWorkerOutcomeUnavailableV1
	default:
		return PDFWorkerOutcomeInternalV1
	}
}
