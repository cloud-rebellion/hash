// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sanitize

import (
	"context"
	"unsafe"
)

// PageCountIsolatedParentWorkV1 prices the actual common worker's bounded
// request/stdout/parser overlap, including its full50MiB stdout ceiling even
// though a valid pages reply carries no PDF body. This is parent memory only;
// the caller separately reserves one worker and its2GiB address-space ceiling.
func PageCountIsolatedParentWorkV1(sourceBytes int64) (int64, error) {
	if sourceBytes < 1 || sourceBytes > MaxPDFBytes {
		return 0, ErrPDFTooLarge
	}
	fixed := 4*int64(unsafe.Sizeof(pdfWorkerRequest{})) + 4*int64(unsafe.Sizeof(pdfWorkerResponse{})) + 4*int64(unsafe.Sizeof(pdfWorkerOutput{})) + 8*pdfWorkerHeaderLimit
	return 4*sourceBytes + 4*(MaxPDFBytes+pdfWorkerHeaderLimit) + fixed, nil
}

// PageCountIsolatedWithContextV1 never falls back to parsing in the caller,
// including development. One atomic capture chooses the actual worker used;
// a separate readiness check cannot establish this boundary. Return follows
// that original worker's synchronous process/IPC join. Legacy PageCount remains
// unchanged for callers with its older explicit development behavior.
func PageCountIsolatedWithContextV1(ctx context.Context, raw []byte) (int, error) {
	if ctx == nil {
		return 0, ErrPDFWorkerUnavailable
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if _, ok := ctx.Deadline(); !ok {
		return 0, ErrPDFWorkerUnavailable
	}
	if len(raw) < 1 || len(raw) > MaxPDFBytes {
		return 0, ErrPDFTooLarge
	}
	worker := activePDFWorker.Load()
	if worker == nil || worker.path == "" {
		return 0, ErrPDFWorkerUnavailable
	}
	response, _, err := worker.run(ctx, pdfWorkerRequest{Operation: "pages", Length: len(raw)}, raw)
	if err != nil {
		return 0, err
	}
	return response.Pages, nil
}
