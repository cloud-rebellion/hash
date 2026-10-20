// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"testing"
	"time"
)

// Actual coordinator/consumer lifetime, synthetic private state; no SQL or
// authentication claim. A closed shell cannot retire a still-borrowed report.
func TestDocumentPackageDraftBorrowRetainsActualOwnerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 4096}, Organisation: workguard.VectorV1{ParentBytes: 4096}, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	org := uuid.New()
	g, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	s := &applicationDocumentPackageSelectionStateV1{sourceContext: ctx, cancel: cancel, sourcesValidated: true, draft: &applicationDocumentPackageDraftSnapshotV1{}, closes: []func(){g.Close}}
	owner := &ApplicationDocumentPackageSelectionV1{state: s}
	draft, release, err := owner.borrowDraftV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	owner.CloseConsumerV1()
	if s.retired || s.draft != draft || c.SnapshotV1(org).Global.ParentBytes != 1024 {
		t.Fatal("closed shell refunded retained draft")
	}
	release()
	release()
	if !s.retired || s.draft != nil || c.SnapshotV1(org).Global.ParentBytes != 0 {
		t.Fatal("last real borrower failed to retire once")
	}
	if _, _, err = owner.borrowDraftV1(ctx); err == nil {
		t.Fatal("closed owner minted another borrower")
	}
}

func TestDocumentPackageDraftCostsBoundRealRowsV1(t *testing.T) {
	h := &generated.GetDocumentPackageDraftSizesV1Row{MemberCount: 16, RawTextBytes: 16 * 4096, ReportBytes: 16 * 65536, PdfBytes: 50 << 20, PdfPages: 500}
	raw, wire, err := documentPackageDraftBodyCostV1(h)
	if err != nil || raw < 4*(h.RawTextBytes+h.ReportBytes) || wire < 2*(h.RawTextBytes+h.ReportBytes) {
		t.Fatal("native/copy/wire overlap underpriced", raw, wire, err)
	}
	for name, change := range map[string]func(*generated.GetDocumentPackageDraftSizesV1Row){"count": func(h *generated.GetDocumentPackageDraftSizesV1Row) { h.MemberCount = 17 }, "raw": func(h *generated.GetDocumentPackageDraftSizesV1Row) { h.RawTextBytes++ }, "report": func(h *generated.GetDocumentPackageDraftSizesV1Row) { h.ReportBytes++ }, "legacy": func(h *generated.GetDocumentPackageDraftSizesV1Row) { h.MissingReports = 1 }, "bytes": func(h *generated.GetDocumentPackageDraftSizesV1Row) { h.PdfBytes++ }, "pages": func(h *generated.GetDocumentPackageDraftSizesV1Row) { h.PdfPages++ }} {
		t.Run(name, func(t *testing.T) {
			bad := *h
			change(&bad)
			if _, _, err := documentPackageDraftBodyCostV1(&bad); err == nil {
				t.Fatal("unbounded/missing scalar admitted")
			}
		})
	}
}
