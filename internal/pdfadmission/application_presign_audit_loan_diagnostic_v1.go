// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/workguard"
)

const (
	htmlAuditLoanUnobservedV1 uint8 = iota
	htmlAuditLoanClosedV1
	htmlAuditLoanRegistryLimitV1
	htmlAuditLoanDecisionV1
	htmlAuditLoanConsumerV1
)

// Fixed stack observation of the original admission attempt. Registry labels
// are assigned under its original mutex; denial is from the ONE coordinator
// decision. No live Snapshot, second admission or available-credit claim.
type htmlAuditLoanObservationV1 struct {
	branch uint8
	denial workguard.AdmissionDenialV1
}

func (a *ApplicationAdmissionV1) admitHTMLAuditObservedV1(ctx context.Context, b ApplicationBudgetV1, work *WorkAdmissionV1, observed *htmlAuditLoanObservationV1) (func(), error) {
	if observed == nil {
		return nil, applicationErrorV1(ctx, nil)
	}
	*observed = htmlAuditLoanObservationV1{}
	if b.Phase != "locked-html-fresh-event" || work == nil {
		observed.branch = htmlAuditLoanDecisionV1
		return nil, applicationErrorV1(ctx, nil)
	}
	return a.admitCoreObservedV1(ctx, b, work, &observed.denial, observed)
}
func (o htmlAuditLoanObservationV1) stageV1() string {
	switch o.branch {
	case htmlAuditLoanClosedV1:
		return "prepare_loan_registry_closed"
	case htmlAuditLoanRegistryLimitV1:
		return "prepare_loan_registry_limit"
	case htmlAuditLoanConsumerV1:
		return "prepare_loan_after_grant"
	case htmlAuditLoanDecisionV1:
		d := o.denial.SnapshotV1() // immutable output from the same original decision
		switch d.Reason {
		case workguard.AdmissionNotDeniedV1:
			return "prepare_loan_budget"
		case workguard.AdmissionInvalidV1:
			return "prepare_loan_invalid"
		case workguard.AdmissionContextV1:
			return "prepare_loan_context"
		case workguard.AdmissionCoordinatorUnavailableV1:
			return "prepare_loan_unavailable"
		case workguard.AdmissionGlobalGrantCountV1:
			return "prepare_loan_global_count"
		case workguard.AdmissionOrganisationGrantCountV1:
			return "prepare_loan_org_count"
		case workguard.AdmissionGlobalResourceV1:
			if d.Dimension == workguard.AdmissionParentBytesV1 {
				return "prepare_loan_global_parent"
			}
			if d.Dimension == workguard.AdmissionDBStagingBytesV1 {
				return "prepare_loan_global_db"
			}
			return "prepare_loan_dimension"
		case workguard.AdmissionOrganisationResourceV1:
			if d.Dimension == workguard.AdmissionParentBytesV1 {
				return "prepare_loan_org_parent"
			}
			if d.Dimension == workguard.AdmissionDBStagingBytesV1 {
				return "prepare_loan_org_db"
			}
			return "prepare_loan_dimension"
		}
	}
	return "prepare_loan_unknown"
}
