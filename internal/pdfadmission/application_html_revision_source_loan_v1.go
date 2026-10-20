// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"math"
	"sync"

	"github.com/bright-interaction/hash/internal/workguard"
)

// One continuous Parent-only loan belongs to one actual private source owner.
// The pointer is installed under owner.mu before its first grant. Its mutable
// loan/grant fields are protected by the SAME admission.mu as Pending/cleanup.
// No caller body, cost, context or independent grant can replace this identity.
type applicationHTMLRevisionSourceLoanV1 struct {
	self    *applicationHTMLRevisionSourceLoanV1
	owner   *applicationHTMLRevisionSourceOwnerV1
	binding *applicationHTMLRevisionSourceBindingV1
	loan    *applicationLoanV1
	grant   *workguard.GrantV1
}

func (a *ApplicationAdmissionV1) admitHTMLRevisionSourceParentV1(ctx context.Context, b ApplicationBudgetV1, r *applicationHTMLRevisionSourceLoanV1) (func(), error) {
	g := b.htmlRevisionSourceGrant
	if a == nil || r == nil || r.self != r || r.owner == nil || r.owner.self != r.owner || r.binding == nil ||
		r.owner.parentLoan != r || r.owner.binding != r.binding || r.binding.admission != a ||
		g == nil || g.owner != r.owner || g.binding != r.binding || !g.validV1(ctx, b.OrgID, b.DocumentID) {
		return nil, htmlRevisionSourceParentErrorV1(ctx, nil, 1, g, 0, workguard.AdmissionDenialV1{})
	}
	expected := ApplicationBudgetV1{Phase: "owned-html-revision-source", OrgID: r.binding.org, DocumentID: r.binding.document,
		WorkingBytes: g.parentBytes, htmlRevisionSourceGrant: g}
	work := r.binding.factory.work
	if b != expected || work == nil || work.coordinator == nil {
		return nil, htmlRevisionSourceParentErrorV1(ctx, nil, 2, g, 0, workguard.AdmissionDenialV1{})
	}
	// The source's caller retains factory->physical-session locks, exactly as
	// before. This method adds admission->coordinator only, with no I/O/callback.
	// A physically retired SQL session may still own source CPU; no new SQL,
	// provider/process-only vector or cleanup-context authority is created here.
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || !applicationContextV1(ctx) {
		return nil, htmlRevisionSourceParentErrorV1(ctx, nil, 3, g, 0, workguard.AdmissionDenialV1{})
	}
	if r.loan != nil {
		loan := r.loan
		_, retained := a.loans[loan]
		if !retained || loan.consumerClosed || loan.releasing || loan.release == nil || r.grant == nil ||
			b.WorkingBytes > math.MaxInt64-loan.budget.WorkingBytes {
			return nil, htmlRevisionSourceParentErrorV1(ctx, nil, 4, g, loan.budget.WorkingBytes, workguard.AdmissionDenialV1{})
		}
		if denial, err := r.grant.TryGrowParentWithDenialV1(ctx, b.WorkingBytes); err != nil {
			return nil, htmlRevisionSourceParentErrorV1(ctx, err, 5, g, loan.budget.WorkingBytes, denial)
		}
		// The original loan's numeric budget is cumulative accounting, not a
		// replacement dispatch receipt. Failed growth changes neither value.
		loan.budget.WorkingBytes += b.WorkingBytes
		if err := ctx.Err(); err != nil {
			return nil, applicationErrorV1(ctx, err)
		}
		return nil, nil
	}
	if r.grant != nil || len(a.loans) >= applicationMaxLoansV1 {
		return nil, htmlRevisionSourceParentErrorV1(ctx, nil, 6, g, 0, workguard.AdmissionDenialV1{})
	}
	// Register BEFORE first capacity acquisition, under the native admission.
	// Actual coordinator acquisition is bounded arithmetic and has no callback.
	loan := &applicationLoanV1{budget: b}
	a.loans[loan] = struct{}{}
	grant, denial, err := work.coordinator.TryAcquireWithDenialV1(ctx, b.OrgID, workguard.VectorV1{ParentBytes: b.WorkingBytes})
	if err != nil {
		delete(a.loans, loan)
		return nil, htmlRevisionSourceParentErrorV1(ctx, err, 7, g, 0, denial)
	}
	r.loan, r.grant = loan, grant
	loan.release = grant.Close
	var once sync.Once
	closeConsumer := func() {
		once.Do(func() {
			a.mu.Lock()
			loan.consumerClosed = true
			a.mu.Unlock()
			a.notify()
		})
	}
	if err := ctx.Err(); err != nil {
		return closeConsumer, applicationErrorV1(ctx, err)
	}
	return closeConsumer, nil
}
