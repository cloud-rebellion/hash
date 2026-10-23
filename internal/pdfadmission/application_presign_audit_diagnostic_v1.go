// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import "errors"

// Diagnostic labels describe only fixed control flow in the existing native
// audit operation. They confer no admission, SQL, payload or publication right.
type htmlAuditFailure488V1 struct {
	stage string
	cause error
}

func (e *htmlAuditFailure488V1) Error() string { return "pre-sign audit failed at " + e.stage }
func (e *htmlAuditFailure488V1) Unwrap() error { return e.cause }
func htmlAuditFailureStageKnownV1(stage string) bool {
	switch stage {
	case "prepare_scope", "prepare_shape", "prepare_resources", "prepare_session", "prepare_loan", "prepare_clone", "prepare_marshal", "append_scope", "append_document", "append_chain", "append_head", "append_callback", "append_identity", "append_insert", "append_cache", "append_return":
		return true
	case "prepare_loan_registry_closed", "prepare_loan_registry_limit", "prepare_loan_budget", "prepare_loan_invalid", "prepare_loan_context", "prepare_loan_unavailable", "prepare_loan_global_count", "prepare_loan_org_count", "prepare_loan_global_parent", "prepare_loan_global_db", "prepare_loan_org_parent", "prepare_loan_org_db", "prepare_loan_dimension", "prepare_loan_after_grant", "prepare_loan_unknown":
		return true
	}
	return false
}
func htmlAuditFailureV1(purpose HTMLAuditPurposeV1, stage string, cause error) error {
	if cause == nil || purpose != HTMLAuditPreSignCommittedV1 {
		return cause
	}
	if !htmlAuditFailureStageKnownV1(stage) {
		stage = "prepare_scope"
	}
	return &htmlAuditFailure488V1{stage: stage, cause: cause}
}

// Only the private native wrapper can supply an audit substage. Cause strings,
// filenames, row values, IDs, headers and SQL are never projected.
func HTMLPreSignAuditFailureStageV1(err error) string {
	var failure *htmlAuditFailure488V1
	if errors.As(err, &failure) && failure != nil && htmlAuditFailureStageKnownV1(failure.stage) {
		return failure.stage
	}
	return ""
}
