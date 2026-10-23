// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func htmlAuditLoanBudget488V1(t *testing.T, ctx context.Context) ApplicationBudgetV1 {
	t.Helper()
	payload := map[string]any{"execution_id": uuid.New(), "execution_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "grant_id": uuid.New(), "grant_revision": int64(1), "use_number": int64(1), "request_id": uuid.New(), "command_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "executor_kind": "member", "executor_user_id": uuid.New(), "executor_credential_id": uuid.Nil}
	shape, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditPreSignCommittedV1, payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{HTMLAuditPreSignCommittedV1.KindV1(), "", ""} {
		if err = shape.text(text, false); err != nil {
			t.Fatal(err)
		}
	}
	if err = shape.add(192, 4096, 16); err != nil {
		t.Fatal(err)
	}
	resources, err := htmlAuditResourcesV1(shape.raw, shape.wire, shape.nodes)
	if err != nil {
		t.Fatal(err)
	}
	return ApplicationBudgetV1{Phase: "locked-html-fresh-event", OrgID: uuid.New(), DocumentID: uuid.New(), HTMLAuditRawBytes: shape.raw, HTMLAuditWireBytes: shape.wire, HTMLAuditNodes: shape.nodes, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes}
}

// This is an explicit synthetic coordinator/negative-registry arithmetic
// fixture, not a SQL/session/source authority or a production-capacity claim.
// Every tested attempt actually refuses; no fabricated native owner succeeds.
func TestPreSign488AuditLoanSameDecisionDenialsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	budget := htmlAuditLoanBudget488V1(t, ctx)
	for _, tc := range []struct {
		name, stage string
		reason      workguard.AdmissionDenialReasonV1
		dimension   workguard.AdmissionDimensionV1
	}{
		{"global_parent", "prepare_loan_global_parent", workguard.AdmissionGlobalResourceV1, workguard.AdmissionParentBytesV1},
		{"org_parent", "prepare_loan_org_parent", workguard.AdmissionOrganisationResourceV1, workguard.AdmissionParentBytesV1},
		{"global_db", "prepare_loan_global_db", workguard.AdmissionGlobalResourceV1, workguard.AdmissionDBStagingBytesV1},
		{"org_db", "prepare_loan_org_db", workguard.AdmissionOrganisationResourceV1, workguard.AdmissionDBStagingBytesV1},
		{"global_count", "prepare_loan_global_count", workguard.AdmissionGlobalGrantCountV1, workguard.AdmissionNoDimensionV1},
		{"org_count", "prepare_loan_org_count", workguard.AdmissionOrganisationGrantCountV1, workguard.AdmissionNoDimensionV1},
		{"budget", "prepare_loan_budget", workguard.AdmissionNotDeniedV1, workguard.AdmissionNoDimensionV1},
		{"context", "prepare_loan_context", workguard.AdmissionContextV1, workguard.AdmissionNoDimensionV1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit := workguard.VectorV1{ParentBytes: 2 * budget.WorkingBytes, DBStagingBytes: 2 * budget.DBStagingBytes}
			limits := workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: 2, MaxOrganisationGrants: 2}
			b := budget
			switch tc.name {
			case "global_parent":
				limits.Global.ParentBytes = b.WorkingBytes - 1
				limits.Organisation.ParentBytes = limits.Global.ParentBytes
			case "org_parent":
				limits.Organisation.ParentBytes = b.WorkingBytes - 1
			case "global_db":
				limits.Global.DBStagingBytes = b.DBStagingBytes - 1
				limits.Organisation.DBStagingBytes = limits.Global.DBStagingBytes
			case "org_db":
				limits.Organisation.DBStagingBytes = b.DBStagingBytes - 1
			case "global_count":
				limits.MaxGrants = 1
				limits.MaxOrganisationGrants = 1
			case "org_count":
				limits.MaxOrganisationGrants = 1
			case "budget":
				b.WorkingBytes++
			}
			coordinator, err := workguard.NewV1(limits)
			if err != nil {
				t.Fatal(err)
			}
			work, err := NewWorkAdmissionV1(coordinator)
			if err != nil {
				t.Fatal(err)
			}
			var held *workguard.GrantV1
			if tc.name == "global_count" || tc.name == "org_count" {
				held, err = coordinator.TryAcquireV1(ctx, b.OrgID, workguard.VectorV1{ParentBytes: 1})
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
			}
			before := coordinator.SnapshotV1(b.OrgID) // test-only nonmutation assertion
			call := ctx
			if tc.name == "context" {
				c, stop := context.WithCancel(ctx)
				stop()
				call = c
			}
			admission := &ApplicationAdmissionV1{loans: make(map[*applicationLoanV1]struct{}), changed: make(chan struct{}, 1)}
			var observed htmlAuditLoanObservationV1
			closeConsumer, err := admission.admitHTMLAuditObservedV1(call, b, work, &observed)
			if closeConsumer != nil || !errors.Is(err, ErrApplicationAdmissionV1) || observed.stageV1() != tc.stage {
				t.Fatal("actual refusal lost original application sentinel or exact branch", observed.stageV1())
			}
			exact := observed.denial.SnapshotV1()
			if exact.Reason != tc.reason || exact.Dimension != tc.dimension {
				t.Fatal("projection differs from original immutable atomic denial")
			}
			if tc.reason == workguard.AdmissionGlobalResourceV1 || tc.reason == workguard.AdmissionOrganisationResourceV1 {
				if exact.Requested.ParentBytes != b.WorkingBytes || exact.Requested.DBStagingBytes != b.DBStagingBytes || exact.Before != before || exact.GlobalLimit != limits.Global || exact.OrganisationLimit != limits.Organisation {
					t.Fatal("denial was reconstructed from another decision or changed vector")
				}
			}
			if len(admission.loans) != 0 || coordinator.SnapshotV1(b.OrgID) != before {
				t.Fatal("refused observation changed actual registry or coordinator accounting")
			}
			wrapped := htmlAuditFailureV1(HTMLAuditPreSignCommittedV1, observed.stageV1(), err)
			if HTMLPreSignAuditFailureStageV1(wrapped) != tc.stage || len(tc.stage) > 48 {
				t.Fatal("same-decision branch escaped closed diagnostic")
			}
			if tc.name == "context" && !errors.Is(wrapped, context.Canceled) {
				t.Fatal("context cause was changed by diagnostic")
			}
			if held != nil {
				held.Close()
			}
			if coordinator.SnapshotV1(b.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("synthetic holder did not retire")
			}
		})
	}
}

func TestPreSign488AuditLoanRegistryRefusalIsOriginalLockedBranchV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	budget := htmlAuditLoanBudget488V1(t, ctx)
	limit := workguard.VectorV1{ParentBytes: 2 * budget.WorkingBytes, DBStagingBytes: 2 * budget.DBStagingBytes}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: 2, MaxOrganisationGrants: 2})
	if err != nil {
		t.Fatal(err)
	}
	work, err := NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	for _, closed := range []bool{false, true} {
		admission := &ApplicationAdmissionV1{closed: closed, loans: make(map[*applicationLoanV1]struct{}), acquire: func(context.Context, ApplicationBudgetV1) (func(), error) {
			t.Fatal("original registry refusal reached acquisition")
			return nil, nil
		}}
		expected := "prepare_loan_registry_closed"
		if !closed {
			expected = "prepare_loan_registry_limit"
			for i := 0; i < applicationMaxLoansV1; i++ {
				admission.loans[&applicationLoanV1{}] = struct{}{}
			}
		}
		count := len(admission.loans)
		var observed htmlAuditLoanObservationV1
		closeConsumer, err := admission.admitHTMLAuditObservedV1(ctx, budget, work, &observed)
		if closeConsumer != nil || !errors.Is(err, ErrApplicationAdmissionV1) || observed.stageV1() != expected || observed.denial != (workguard.AdmissionDenialV1{}) {
			t.Fatal("registry diagnostic did not come from original locked predicate")
		}
		if len(admission.loans) != count || coordinator.SnapshotV1(budget.OrgID) != (workguard.SnapshotV1{}) {
			t.Fatal("registry refusal mutated loans or coordinator")
		}
	}
}
