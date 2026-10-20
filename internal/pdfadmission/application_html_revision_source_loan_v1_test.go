// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
)

// This uses the ACTUAL constructed input/source/candidate/Append owner and real
// coordinator. SQL rows/backend retirement remain the explicit synthetic witness
// of that fixture. Private fault inputs below prove bookkeeping refusal only;
// they do not establish source, SQL, physical-retirement or dispatch authority.
func TestHTMLRevisionContinuousSourceLoanAtomicRefusalV1(t *testing.T) {
	withHTMLRevisionConstructedWriterFixtureV1(t, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
		s := f.source.state
		if err := s.beginV1(); err != nil {
			t.Fatal(err)
		}
		defer s.finishV1()
		r, a := s.parentLoan, s.binding.admission
		if r == nil || r.loan == nil || r.grant == nil {
			t.Fatal("actual completed Append lacks its original source loan")
		}
		before, pending := f.coordinator.SnapshotV1(f.document.OrgID), a.PendingV1()
		// Every source stage already executed by this genuine constructed writer
		// shares ONE application loan and ONE actual coordinator grant. Other
		// header/actor/body/collection/statement loans remain distinct positives.
		a.mu.Lock()
		sourceCount := 0
		for loan := range a.loans {
			if loan.budget.Phase == "owned-html-revision-source" {
				sourceCount++
			}
		}
		budgetBefore := r.loan.budget.WorkingBytes
		a.mu.Unlock()
		if sourceCount != 1 || budgetBefore <= 0 || len(s.closes) != 1 {
			t.Fatal("actual source stages minted per-expression grant owners", sourceCount, budgetBefore, len(s.closes))
		}
		cost, err := htmlRevisionPreparedDocumentCloneV1(s.snapshot.document)
		if err != nil || cost <= 0 {
			t.Fatal("actual private retained source component unavailable", cost, err)
		}
		g := &applicationHTMLRevisionSourceGrantV1{owner: s, binding: s.binding, stage: htmlRevisionSourceCandidateV1, parentBytes: cost}
		g.self = g
		b := ApplicationBudgetV1{Phase: "owned-html-revision-source", OrgID: s.binding.org, DocumentID: s.binding.document, WorkingBytes: cost, htmlRevisionSourceGrant: g}
		for _, mode := range []string{"copied record", "foreign context", "consumer closed", "releasing", "deleted"} {
			t.Run(mode, func(t *testing.T) {
				record, ctx := r, s.binding.ctx
				var restore func()
				switch mode {
				case "copied record":
					copy := *r
					copy.self = &copy
					record = &copy
				case "foreign context":
					child, cancel := context.WithTimeout(ctx, time.Second)
					defer cancel()
					ctx = child
				case "consumer closed":
					a.mu.Lock()
					r.loan.consumerClosed = true
					a.mu.Unlock()
					restore = func() { a.mu.Lock(); r.loan.consumerClosed = false; a.mu.Unlock() }
				case "releasing":
					a.mu.Lock()
					r.loan.releasing = true
					a.mu.Unlock()
					restore = func() { a.mu.Lock(); r.loan.releasing = false; a.mu.Unlock() }
				case "deleted":
					a.mu.Lock()
					delete(a.loans, r.loan)
					a.mu.Unlock()
					restore = func() { a.mu.Lock(); a.loans[r.loan] = struct{}{}; a.mu.Unlock() }
				}
				if restore != nil {
					defer restore()
				}
				close, err := a.admitHTMLRevisionSourceParentV1(ctx, b, record)
				if close != nil || err == nil {
					t.Fatal("foreign/dead private loan minted or grew work", close != nil, err)
				}
				var detail *HTMLRevisionSourceParentErrorV1
				if !errors.As(err, &detail) || !errors.Is(err, ErrApplicationAdmissionV1) || detail.DetailsV1().Capacity.Reason != workguard.AdmissionNotDeniedV1 {
					t.Fatal("authority refusal lost provenance or became capacity", err)
				}
			})
		}
		if f.coordinator.SnapshotV1(f.document.OrgID) != before || a.PendingV1() != pending {
			t.Fatal("rejected private source growth changed resource ownership")
		}
		// Fill the ACTUAL fixture's declared1GiB Parent dimension. This blocker
		// is an independent test-owned accounting grant, not a backend witness.
		blocker, err := f.coordinator.TryAcquireV1(s.binding.ctx, f.document.OrgID, workguard.VectorV1{ParentBytes: (1 << 30) - before.Global.ParentBytes})
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Close()
		blocked := f.coordinator.SnapshotV1(f.document.OrgID)
		if err = s.holdV1(htmlRevisionSourceCandidateV1, s.maxScratch, cost); err == nil {
			t.Fatal("genuine coordinator capacity denial was bypassed")
		}
		var detail *HTMLRevisionSourceParentErrorV1
		if !errors.As(err, &detail) || !errors.Is(err, ErrApplicationAdmissionV1) {
			t.Fatal("source capacity lost existing classifier", err)
		}
		diagnostic := detail.DetailsV1()
		if diagnostic.Branch != 5 || diagnostic.Stage != uint8(htmlRevisionSourceCandidateV1) || diagnostic.CumulativeBytes != budgetBefore || diagnostic.RequestedBytes != cost || diagnostic.Capacity.Reason != workguard.AdmissionGlobalResourceV1 || diagnostic.Capacity.Dimension != workguard.AdmissionParentBytesV1 || diagnostic.Capacity.Before != blocked {
			t.Fatal("source parent decision differs from actual rejecting branch", diagnostic)
		}
		if f.coordinator.SnapshotV1(f.document.OrgID) != blocked || a.PendingV1() != pending || r.loan.budget.WorkingBytes != budgetBefore {
			t.Fatal("failed capacity growth partially changed native pending or coordinator debt")
		}
		blocker.Close()
		if f.coordinator.SnapshotV1(f.document.OrgID) != before {
			t.Fatal("test blocker changed original loan")
		}
		if detail.DetailsV1() != diagnostic {
			t.Fatal("source diagnostic aliased mutable accounting")
		}
		// Physical SQL retirement alone leaves this actual source owner alive.
		// Growth still derives from its ORIGINAL context and private retained body.
		close(f.native.done)
		if _, err = a.ReconcileCleanupV1(call); err != nil {
			t.Fatal(err)
		}
		if f.coordinator.SnapshotV1(f.document.OrgID) != before {
			t.Fatal("physical-only witness credited an active source")
		}
		if err = s.holdV1(htmlRevisionSourceCandidateV1, s.maxScratch, cost); err != nil {
			t.Fatal("original source could not grow after SQL retirement", err)
		}
		retainedClone := htmlRevisionCloneDocumentV1(s.snapshot.document)
		if retainedClone == nil || retainedClone.ID != f.document.ID {
			t.Fatal("actual source clone changed")
		}
		grown, grownPending := f.coordinator.SnapshotV1(f.document.OrgID), a.PendingV1()
		if grown.GlobalGrants != before.GlobalGrants || grown.OrganisationGrants != before.OrganisationGrants ||
			grown.Global.ParentBytes-before.Global.ParentBytes != cost || grown.Global.DBStagingBytes != before.Global.DBStagingBytes ||
			grownPending.Loans != pending.Loans || grownPending.WorkingBytes-pending.WorkingBytes != cost || r.loan.budget.WorkingBytes != budgetBefore+cost {
			t.Fatal("same original loan failed complete atomic Parent-only growth", before, grown, pending, grownPending)
		}
		retainedClone = nil // Last real test clone use; fixture closes original consumers later.
	})
}
