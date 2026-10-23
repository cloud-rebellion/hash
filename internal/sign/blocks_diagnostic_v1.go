// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"errors"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// Only this private wrapper can project one closed source stage. Original
// client error text, sentinel/status mapping and cleanup errors are retained.
type blockSignatureStageFailureV1 struct {
	stage string
	cause error
}

func (e *blockSignatureStageFailureV1) Error() string { return e.cause.Error() }
func (e *blockSignatureStageFailureV1) Unwrap() error { return e.cause }
func blockSignatureStageKnownV1(stage string) bool {
	switch stage {
	case "ordinary_certificate_body", "ordinary_certificate_capture", "ordinary_certificate_claims", "ordinary_certificate_freeze", "ordinary_certificate_prepare", "ordinary_certificate_render", "ordinary_certificate_snapshot", "ordinary_final_ack", "ordinary_final_blocks", "ordinary_final_capture", "ordinary_final_hash", "ordinary_final_manual", "ordinary_output_checkpoint", "ordinary_output_join", "ordinary_output_read", "ordinary_output_store", "ordinary_read", "ordinary_refresh", "ordinary_scope", "ordinary_snapshot_close", "ordinary_source_close", "ordinary_stage_intent":
		return true
	case "finalize_admission", "finalize_branding", "finalize_certificate_state", "finalize_children", "finalize_claim", "finalize_claim_retire", "finalize_connection", "finalize_document", "finalize_frozen_family", "finalize_intent", "finalize_lock", "finalize_manifest", "finalize_ordinary_prepare", "finalize_reference", "finalize_resume_intent", "finalize_resume_stage", "finalize_retention", "finalize_signature_policy", "finalize_source":
		return true
	case "finalization_source_commit", "finalization_source_models", "finalization_source_new", "finalization_source_owner", "finalization_source_phase", "finalization_source_reference", "finalization_source_signatures", "finalization_source_state", "finalization_source_storage", "finalization_source_versions":
		return true
	case "audit", "audit_package", "audit_publish", "credential", "credential_recheck", "declined", "deferred_close", "document", "eligibility", "envelope", "finalize", "fitted", "historical", "insert_signature", "mark_signed", "mutation", "mutation_begin", "mutation_commit", "mutation_fields", "mutation_historical", "mutation_models", "mutation_notice", "mutation_state", "mutation_status", "mutation_tier", "notice", "notice_payload", "operation", "operation_close", "original", "package_begin", "package_register", "package_request", "package_validate", "preparation", "preparation_commit", "preparation_envelope", "preparation_fields", "preparation_members", "preparation_models", "preparation_pdf", "preparation_standalone", "preparation_state", "prepared_view", "recipient", "recipient_recheck", "record_response", "remaining", "report_admit", "report_prepare", "required_role", "retain_publication", "retry", "roles", "scope", "signature_register", "signature_request", "signature_targets", "storage", "store_evidence", "tier", "unfilled":
		return true
	}
	return false
}
func blockSignatureDiagnosticV1(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	if !blockSignatureStageKnownV1(stage) {
		stage = "scope"
	}
	return &blockSignatureStageFailureV1{stage: stage, cause: cause}
}

// One outer owned-sign wrapper and at most one private deferred-close wrapper.
// No caller-controlled text or foreign error label is read by this accessor.
func BlockSignatureFailureStageV1(err error) string {
	var failure *blockSignatureStageFailureV1
	if !errors.As(err, &failure) || failure == nil || !blockSignatureStageKnownV1(failure.stage) {
		return pdfadmission.HistoricalFinalizationSourceFailureStageV1(err)
	}
	if native := pdfadmission.HistoricalFinalizationSourceFailureStageV1(failure.cause); native != "" {
		return native
	}
	var inner *blockSignatureStageFailureV1
	if errors.As(failure.cause, &inner) && inner != nil && blockSignatureStageKnownV1(inner.stage) {
		return inner.stage
	}
	return failure.stage
}
