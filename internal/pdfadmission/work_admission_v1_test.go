// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ordinarypage"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func workAdmissionTestV1(t *testing.T) (*workguard.CoordinatorV1, *WorkAdmissionV1) {
	t.Helper()
	v := workguard.VectorV1{ParentBytes: 1 << 30, DBStagingBytes: 512 << 20, ChildAddressBytes: 2 << 30, PDFWorkers: 1, SQLSessions: 1, ProviderStreams: 1, RendererRequests: 1}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 64, MaxOrganisationGrants: 64})
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewWorkAdmissionV1(c)
	if err != nil {
		t.Fatal(err)
	}
	return c, a
}
func ordinaryInspectionTestWorkerGateV1(t *testing.T) OrdinaryInspectionWorkerAdmissionV1 {
	t.Helper()
	_, a := workAdmissionTestV1(t)
	return a.PDFWorkerV1
}

func TestWorkAdmissionV1FixedApplicationCosts(t *testing.T) {
	c, a := workAdmissionTestV1(t)
	ctx := ordinaryInspectionTestContextV1(t)
	base := ApplicationBudgetV1{OrgID: uuid.New(), DocumentID: uuid.New(), AdmissionID: uuid.New()}
	var budgets []ApplicationBudgetV1
	for _, phase := range []string{"locked-basis", "locked-ready", "locked-cold-ready"} {
		b := base
		b.Phase = phase
		b.StoredBasisBytes = 100
		b.ComponentBytes = 200
		b.WorkingBytes = 16*300 + (8 << 20)
		if phase == "locked-basis" {
			b.SourceBytes = 500
		}
		if phase == "locked-cold-ready" {
			b.OriginalPDFBytes = 10
			b.OriginalPlanBytes = 20
			b.WorkingBytes += 4 * 30
			b.DBStagingBytes = 16 * 300
		}
		budgets = append(budgets, b)
	}
	for _, phase := range []string{"locked-original-read", "locked-original-capture", "cold-fragment"} {
		b := base
		b.Phase = phase
		b.OriginalPDFBytes = 100
		b.OriginalPlanBytes = 20
		b.WorkingBytes = 4*120 + (8 << 20)
		if phase == "locked-original-capture" {
			b.DBStagingBytes = 120
		}
		budgets = append(budgets, b)
	}
	for _, phase := range []string{"generation-source", "cold-source"} {
		b := base
		b.Phase = phase
		b.SourceBytes = 100
		b.StoredBasisBytes = 200
		b.WorkingBytes = 4*100 + 16*200 + (8 << 20)
		budgets = append(budgets, b)
	}
	b := base
	b.Phase = "generation-page"
	b.OriginalPDFBytes = ordinarypage.MaxPDFBytesV1
	b.OriginalPlanBytes = ordinarypage.MaxPlanBytesV1
	b.WorkingBytes = 8*ordinarypage.MaxPackageBytesV1 + 8*ordinarypage.MaxPlanBytesV1 + (32 << 20)
	b.DBStagingBytes = b.OriginalPDFBytes + b.OriginalPlanBytes
	budgets = append(budgets, b)
	for _, b := range budgets {
		t.Run(b.Phase, func(t *testing.T) {
			release, err := a.ApplicationV1(ctx, b)
			if err != nil || release == nil {
				t.Fatal(err)
			}
			defer release()
			s := c.SnapshotV1(b.OrgID)
			if s.Global.ParentBytes != b.WorkingBytes || s.Global.DBStagingBytes != b.DBStagingBytes || s.Global.SQLSessions != 0 || s.Global.PDFWorkers != 0 {
				t.Fatal("incorrect phase costs", s)
			}
			before := s
			for _, mutate := range []func(*ApplicationBudgetV1){func(b *ApplicationBudgetV1) { b.WorkingBytes-- }, func(b *ApplicationBudgetV1) { b.WorkingBytes++ }, func(b *ApplicationBudgetV1) { b.DBStagingBytes++ }, func(b *ApplicationBudgetV1) { b.OrgID = uuid.Nil }, func(b *ApplicationBudgetV1) { b.Phase = "invented" }, func(b *ApplicationBudgetV1) { b.StoredBasisBytes = -1 }} {
				bad := b
				mutate(&bad)
				if r, err := a.ApplicationV1(ctx, bad); r != nil || err == nil {
					if r != nil {
						r()
					}
					t.Fatal("invalid phase admitted")
				}
				if c.SnapshotV1(b.OrgID) != before {
					t.Fatal("refusal changed counters")
				}
			}
			release()
			if c.SnapshotV1(b.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("loan not released")
			}
		})
	}
}

func TestWorkAdmissionV1FixedOrdinaryCostsAndPhysicalSeams(t *testing.T) {
	c, a := workAdmissionTestV1(t)
	ctx := ordinaryInspectionTestContextV1(t)
	org, doc := uuid.New(), uuid.New()
	for _, b := range []OrdinaryInspectionBudgetV1{
		{Phase: "source", OrgID: org, DocumentID: doc, SourceBytes: 100, CanonicalBytes: 200, MemoryBytes: 4*100 + 16*200 + (8 << 20)},
		{Phase: "fragment", OrgID: org, DocumentID: doc, PackageBytes: 100, MemoryBytes: 4*100 + 4*ordinarypage.MaxPDFBytesV1 + 4*ordinarypage.MaxPlanBytesV1 + (8 << 20)},
		{Phase: "cold-fragment", OrgID: org, DocumentID: doc, SourceBytes: 100, PlanBytes: 20, MemoryBytes: 4*120 + (8 << 20)},
	} {
		r, err := a.OrdinaryV1(ctx, b)
		if err != nil {
			t.Fatal(err)
		}
		r()
		for _, mutate := range []func(*OrdinaryInspectionBudgetV1){func(b *OrdinaryInspectionBudgetV1) { b.MemoryBytes++ }, func(b *OrdinaryInspectionBudgetV1) { b.CanonicalBytes = -1 }, func(b *OrdinaryInspectionBudgetV1) { b.PlanBytes = -1 }, func(b *OrdinaryInspectionBudgetV1) { b.Phase = "unknown" }} {
			bad := b
			mutate(&bad)
			if r, err := a.OrdinaryV1(ctx, bad); r != nil || err == nil {
				if r != nil {
					r()
				}
				t.Fatal("ordinary cost bypass")
			}
		}
	}
	for _, phase := range []string{"source", "fragment"} {
		r, err := a.PDFWorkerV1(ctx, OrdinaryInspectionWorkerBudgetV1{Phase: phase, OrgID: org, DocumentID: doc})
		if err != nil {
			t.Fatal(err)
		}
		if got := c.SnapshotV1(org).Global; got.PDFWorkers != 1 || got.ChildAddressBytes != 2<<30 || got.ParentBytes != 0 {
			t.Fatal(got)
		}
		r()
	}
	for _, acquire := range []func(context.Context, uuid.UUID) (func(), error){a.SQLSessionV1, a.ProviderStreamV1, a.RendererRequestV1} {
		r, err := acquire(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		if busy, err := acquire(ctx, org); busy != nil || err == nil {
			if busy != nil {
				busy()
			}
			t.Fatal("physical slot overspend")
		}
		r()
		r()
	}
	if c.SnapshotV1(org) != (workguard.SnapshotV1{}) {
		t.Fatal("physical seam leak")
	}
}

// The private worker oracles here prove resource lifetime/liveness, not genuine
// PDF semantics or OS isolation. The tagged suite separately runs the actual
// fixed Linux worker with a real single-worker coordinator grant.
func TestWorkAdmissionV1SingleWorkerRetainedSourceAndPage(t *testing.T) {
	c, a := workAdmissionTestV1(t)
	b, raw := ordinaryInspectionTestBasisV1(t)
	i, _, _ := ordinaryInspectionTestInspectorV1(t, b, &ordinaryInspectionTestAdmissionV1{})
	i.admission = a.OrdinaryV1
	i.workerAdmission = a.PDFWorkerV1
	ctx := ordinaryInspectionTestContextV1(t)
	s, err := i.InspectSourceV1(ctx, b, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := c.SnapshotV1(b.input.OrgID)
	if before.Global.ParentBytes < 1 || before.Global.PDFWorkers != 0 || before.Global.ChildAddressBytes != 0 {
		t.Fatal("source retained physical worker", before)
	}
	p, err := i.InspectPageV1(ctx, s, 2, ordinaryInspectionTestEnvelopeV1(t, b, 2, []byte("%PDF-synthetic-resource-lifetime")))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if now := c.SnapshotV1(b.input.OrgID); now.Global.ParentBytes <= before.Global.ParentBytes || now.Global.PDFWorkers != 0 {
		t.Fatal("page nested work failed", now)
	}
	s.Close()
	if c.SnapshotV1(b.input.OrgID).GlobalGrants != 2 {
		t.Fatal("source freed live borrower")
	}
	p.Close()
	if c.SnapshotV1(b.input.OrgID) != (workguard.SnapshotV1{}) {
		t.Fatal("last borrower did not retire")
	}
}

func TestWorkAdmissionV1CancelledWorkerRetainsUntilPhysicalReturn(t *testing.T) {
	c, a := workAdmissionTestV1(t)
	b, raw := ordinaryInspectionTestBasisV1(t)
	i, _, _ := ordinaryInspectionTestInspectorV1(t, b, &ordinaryInspectionTestAdmissionV1{})
	i.admission = a.OrdinaryV1
	i.workerAdmission = a.PDFWorkerV1
	started, observed, finish, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseFinish sync.Once
	var alias []byte
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	i.worker.source = func(ctx context.Context, body []byte) (sanitize.PDFManualGeometry, error) {
		alias = body
		close(started)
		<-ctx.Done()
		close(observed)
		<-finish
		return sanitize.PDFManualGeometry{}, ctx.Err()
	}
	go func() {
		defer close(joined)
		s, err := i.InspectSourceV1(ctx, b, raw)
		if s != nil {
			s.Close()
		}
		result <- err
	}()
	t.Cleanup(func() {
		cancel()
		releaseFinish.Do(func() { close(finish) })
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("worker actor did not join")
		}
	})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start")
	}
	cancel()
	select {
	case <-observed:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel not observed")
	}
	if got := c.SnapshotV1(b.input.OrgID); got.Global.PDFWorkers != 1 || got.Global.ParentBytes == 0 || ordinaryInspectionTestPrivateZeroV1(alias) {
		t.Fatal("cancel released live worker/buffer", got)
	}
	second, calls, _ := ordinaryInspectionTestInspectorV1(t, b, &ordinaryInspectionTestAdmissionV1{})
	second.admission = a.OrdinaryV1
	second.workerAdmission = a.PDFWorkerV1
	if s, err := second.InspectSourceV1(ordinaryInspectionTestContextV1(t), b, raw); s != nil || err == nil || calls.Load() != 0 {
		if s != nil {
			s.Close()
		}
		t.Fatal("busy physical worker dispatched")
	}
	releaseFinish.Do(func() { close(finish) })
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not return")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if c.SnapshotV1(b.input.OrgID) != (workguard.SnapshotV1{}) || !ordinaryInspectionTestPrivateZeroV1(alias) {
		t.Fatal("physical return did not clear owned work")
	}
}

func TestWorkAdmissionV1MandatoryWorkerGateBeforeDispatch(t *testing.T) {
	if i, err := NewOrdinaryInspectorV1(func(context.Context, OrdinaryInspectionBudgetV1) (func(), error) { return func() {}, nil }, nil); i != nil || err == nil {
		t.Fatal("missing worker gate admitted")
	}
	for _, mode := range []string{"refusal", "nil-release", "late-cancel"} {
		t.Run(mode, func(t *testing.T) {
			b, raw := ordinaryInspectionTestBasisV1(t)
			accounting := &ordinaryInspectionTestAdmissionV1{}
			i, calls, _ := ordinaryInspectionTestInspectorV1(t, b, accounting)
			ctx, cancel := context.WithCancel(ordinaryInspectionTestContextV1(t))
			defer cancel()
			var releases atomic.Int64
			i.workerAdmission = func(context.Context, OrdinaryInspectionWorkerBudgetV1) (func(), error) {
				if mode == "refusal" {
					return nil, errors.New("private gate error")
				}
				if mode == "nil-release" {
					return nil, nil
				}
				cancel()
				return func() { releases.Add(1) }, nil
			}
			if s, err := i.InspectSourceV1(ctx, b, raw); s != nil || err == nil || calls.Load() != 0 || accounting.count() != 0 {
				if s != nil {
					s.Close()
				}
				t.Fatal("unadmitted worker dispatched")
			}
			if (mode == "late-cancel" && releases.Load() != 1) || (mode != "late-cancel" && releases.Load() != 0) {
				t.Fatal("unstarted physical grant leaked")
			}
		})
	}
}
