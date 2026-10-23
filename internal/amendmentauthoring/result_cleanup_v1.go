// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package amendmentauthoring

import (
	"context"
	"log/slog"
	"time"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// Every amendment result binds only its actual original native admission.
// Notice alone can replace that binding after its first-pair retirement proof.
// Its value does not grant SQL or buffer credit. The original native fence is
// re-observed only after the result's actual serializer/pair/reader last use.
// Unknown/live owners remain reachable and charged in the native factory.
type resultAdmissionCleanupV1 struct {
	ctx       context.Context
	admission *pdfadmission.ApplicationAdmissionV1
}

func (r *ResultV1) bindAdmissionV1(ctx context.Context, admission *pdfadmission.ApplicationAdmissionV1) error {
	if r == nil || r.state == nil || ctx == nil || admission == nil {
		return amendments.ErrUnavailableV1
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.state.closed {
		return amendments.ErrUnavailableV1
	}
	r.state.admissionCleanup = &resultAdmissionCleanupV1{ctx: ctx, admission: admission}
	return nil
}
func (h *resultAdmissionCleanupV1) closeV1() {
	if h == nil || h.ctx == nil || h.admission == nil {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(h.ctx), 5*time.Second)
	defer cancel()
	pending, err := h.admission.ReconcileCleanupV1(cleanup)
	observed := h.admission.PendingV1()
	if err != nil || pending != 0 || observed.Loans != 0 || observed.RetainedPages != 0 || !observed.ClientCleaned || !observed.ServerRetired {
		// Deliberately closed diagnostic: no raw error/provider body, file URL,
		// notice capability, recipient, cookie, request body or private document.
		slog.WarnContext(cleanup, "later amendment result cleanup pending", "code", "HASH_AMENDMENT_RESULT_RETIREMENT_PENDING")
	}
}
