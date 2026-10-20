// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"

	"github.com/bright-interaction/hash/internal/workguard"
)

// Fixed numeric provenance for one actual source-parent refusal. The native
// body control recipe prepays this error frame before source construction.
// It contains no source, document, owner, context or coordinator reference.
// The cause preserves the existing public admission/cancellation classification.
type HTMLRevisionSourceParentErrorV1 struct {
	cause  error
	detail HTMLRevisionSourceParentDenialV1
}
type HTMLRevisionSourceParentDenialV1 struct {
	Branch, Stage                   uint8
	CumulativeBytes, RequestedBytes int64
	Capacity                        workguard.AdmissionDenialSnapshotV1
}

func (e *HTMLRevisionSourceParentErrorV1) Error() string { return e.cause.Error() }
func (e *HTMLRevisionSourceParentErrorV1) Unwrap() error { return e.cause }
func (e *HTMLRevisionSourceParentErrorV1) DetailsV1() HTMLRevisionSourceParentDenialV1 {
	return e.detail
}

func htmlRevisionSourceParentErrorV1(ctx context.Context, err error, branch uint8, g *applicationHTMLRevisionSourceGrantV1, cumulative int64, denial workguard.AdmissionDenialV1) error {
	d := HTMLRevisionSourceParentDenialV1{Branch: branch, CumulativeBytes: cumulative, Capacity: denial.SnapshotV1()}
	if g != nil {
		d.Stage = uint8(g.stage)
		d.RequestedBytes = g.parentBytes
	}
	return &HTMLRevisionSourceParentErrorV1{cause: applicationErrorV1(ctx, err), detail: d}
}
