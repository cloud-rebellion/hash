// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"errors"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// A closed operation label for the existing error/log seam. No source IDs,
// provider values, SQL arguments, cause text or dynamically supplied label is
// projected. Unwrap preserves the original status/recovery/sentinel authority.
type preSignStageFailureV1 struct {
	stage string
	cause error
}

func (e *preSignStageFailureV1) Error() string { return "pre-sign operation failed at " + e.stage }
func (e *preSignStageFailureV1) Unwrap() error { return e.cause }
func preSignStageKnownV1(stage string) bool {
	switch stage {
	case "operation", "confirm", "original_recovery", "confirm_receipt", "preparation_read", "freeze_data", "reserve_preparation", "prepare_artifacts", "reserve_objects", "upload_artifacts", "commit_read", "commit_source", "commit_data", "commit_document", "commit_quota", "confirm_lawful_basis", "create_intent", "read_intent", "new_execution", "fresh_execution", "new_command", "audit_payload", "commit_audit", "new_record", "resolve_objects", "append_record", "pin_base", "commit_actor", "commit_deadline", "commit_transaction", "publication", "result_recovery":
		return true
	}
	return preSignPublicationStageKnownV1(stage)
}
func preSignPublicationStageKnownV1(stage string) bool {
	switch stage {
	case "publication_commit", "publication_expired_audit", "publication_invited_audit", "publication_mark", "publication_model_identity", "publication_native", "publication_open", "publication_published_audit", "publication_read_evidence", "publication_read_fields", "publication_read_intent", "publication_read_models", "publication_read_recipients", "publication_read_retained", "publication_read_state", "publication_recovery_commit", "publication_recovery_open", "publication_resume_scope", "publication_retention_complete", "publication_retention_complete_commit", "publication_retention_complete_open", "publication_retention_io", "publication_retention_start", "publication_retention_start_commit", "publication_retention_start_open", "publication_sent_audit", "publication_sent_document", "publication_sent_entry":
		return true
	}
	return false
}
func preSignFailureV1(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	if !preSignStageKnownV1(stage) {
		stage = "operation"
	}
	return &preSignStageFailureV1{stage: stage, cause: cause}
}

// Only this package's private error can supply a label, and it must still
// belong to the closed constant set before reaching a handler's safe log.
func PreSignFailureStageV1(err error) string {
	var failure *preSignStageFailureV1
	if errors.As(err, &failure) && failure != nil && preSignStageKnownV1(failure.stage) {
		if failure.stage == "commit_audit" {
			if substage := pdfadmission.HTMLPreSignAuditFailureStageV1(failure.cause); substage != "" {
				return "commit_audit_" + substage
			}
		}
		// Capture the closed resume phase before following the same bounded
		// Confirm -> resume -> read error chain.
		if failure.stage == "publication" || preSignPublicationStageKnownV1(failure.stage) {
			phase := ""
			for depth := 0; depth < 2; depth++ {
				switch failure.stage {
				case "publication_recovery_open", "publication_retention_start_open", "publication_retention_complete_open", "publication_open":
					phase = failure.stage
				}
				var inner *preSignStageFailureV1
				if !errors.As(failure.cause, &inner) || inner == nil || !preSignPublicationStageKnownV1(inner.stage) {
					break
				}
				failure = inner
			}
			if native := pdfadmission.HTMLPreSignPublicationFailureStageV1(failure.cause); native != "" {
				if qualified := preSignPublicationReadStageV1(phase, native); qualified != "" {
					return qualified
				}
				return native
			}
			if qualified := preSignPublicationReadStageV1(phase, failure.stage); qualified != "" {
				return qualified
			}
		}
		return failure.stage
	}
	return ""
}

// Every result is a literal from this finite phase/read table, never input text.
func preSignPublicationReadStageV1(phase, stage string) string {
	switch phase {
	case "publication_recovery_open":
		switch stage {
		case "publication_read_state":
			return "publication_recovery_read_state"
		case "publication_read_models":
			return "publication_recovery_read_models"
		case "publication_read_recipients":
			return "publication_recovery_read_recipients"
		case "publication_read_fields":
			return "publication_recovery_read_fields"
		case "publication_read_intent":
			return "publication_recovery_read_intent"
		case "publication_read_evidence":
			return "publication_recovery_read_evidence"
		case "publication_read_retained":
			return "publication_recovery_read_retained"
		case "publication_fields_count":
			return "publication_recovery_fields_count"
		case "publication_fields_fresh":
			return "publication_recovery_fields_fresh"
		case "publication_fields_header":
			return "publication_recovery_fields_header"
		case "publication_fields_header_cache":
			return "publication_recovery_fields_header_cache"
		case "publication_fields_header_query":
			return "publication_recovery_fields_header_query"
		case "publication_fields_header_scope":
			return "publication_recovery_fields_header_scope"
		case "publication_fields_header_shape":
			return "publication_recovery_fields_header_shape"
		case "publication_fields_loan":
			return "publication_recovery_fields_loan"
		case "publication_fields_lockpins":
			return "publication_recovery_fields_lockpins"
		case "publication_fields_raw_shape":
			return "publication_recovery_fields_raw_shape"
		case "publication_fields_repeat":
			return "publication_recovery_fields_repeat"
		case "publication_fields_rows":
			return "publication_recovery_fields_rows"
		case "publication_fields_scope":
			return "publication_recovery_fields_scope"
		case "publication_fields_verify":
			return "publication_recovery_fields_verify"
		case "publication_retained_scope":
			return "publication_recovery_retained_scope"
		case "publication_retained_repeat":
			return "publication_recovery_retained_repeat"
		case "publication_retained_borrow":
			return "publication_recovery_retained_borrow"
		case "publication_retained_load":
			return "publication_recovery_retained_load"
		case "publication_retained_postread":
			return "publication_recovery_retained_postread"
		}
	case "publication_retention_start_open":
		switch stage {
		case "publication_read_state":
			return "publication_retention_start_read_state"
		case "publication_read_models":
			return "publication_retention_start_read_models"
		case "publication_read_recipients":
			return "publication_retention_start_read_recipients"
		case "publication_read_fields":
			return "publication_retention_start_read_fields"
		case "publication_read_intent":
			return "publication_retention_start_read_intent"
		case "publication_read_evidence":
			return "publication_retention_start_read_evidence"
		case "publication_read_retained":
			return "publication_retention_start_read_retained"
		case "publication_fields_count":
			return "publication_retention_start_fields_count"
		case "publication_fields_fresh":
			return "publication_retention_start_fields_fresh"
		case "publication_fields_header":
			return "publication_retention_start_fields_header"
		case "publication_fields_header_cache":
			return "publication_retention_start_fields_header_cache"
		case "publication_fields_header_query":
			return "publication_retention_start_fields_header_query"
		case "publication_fields_header_scope":
			return "publication_retention_start_fields_header_scope"
		case "publication_fields_header_shape":
			return "publication_retention_start_fields_header_shape"
		case "publication_fields_loan":
			return "publication_retention_start_fields_loan"
		case "publication_fields_lockpins":
			return "publication_retention_start_fields_lockpins"
		case "publication_fields_raw_shape":
			return "publication_retention_start_fields_raw_shape"
		case "publication_fields_repeat":
			return "publication_retention_start_fields_repeat"
		case "publication_fields_rows":
			return "publication_retention_start_fields_rows"
		case "publication_fields_scope":
			return "publication_retention_start_fields_scope"
		case "publication_fields_verify":
			return "publication_retention_start_fields_verify"
		case "publication_retained_scope":
			return "publication_retention_start_retained_scope"
		case "publication_retained_repeat":
			return "publication_retention_start_retained_repeat"
		case "publication_retained_borrow":
			return "publication_retention_start_retained_borrow"
		case "publication_retained_load":
			return "publication_retention_start_retained_load"
		case "publication_retained_postread":
			return "publication_retention_start_retained_postread"
		}
	case "publication_retention_complete_open":
		switch stage {
		case "publication_read_state":
			return "publication_retention_complete_read_state"
		case "publication_read_models":
			return "publication_retention_complete_read_models"
		case "publication_read_recipients":
			return "publication_retention_complete_read_recipients"
		case "publication_read_fields":
			return "publication_retention_complete_read_fields"
		case "publication_read_intent":
			return "publication_retention_complete_read_intent"
		case "publication_read_evidence":
			return "publication_retention_complete_read_evidence"
		case "publication_read_retained":
			return "publication_retention_complete_read_retained"
		case "publication_fields_count":
			return "publication_retention_complete_fields_count"
		case "publication_fields_fresh":
			return "publication_retention_complete_fields_fresh"
		case "publication_fields_header":
			return "publication_retention_complete_fields_header"
		case "publication_fields_header_cache":
			return "publication_retention_complete_fields_header_cache"
		case "publication_fields_header_query":
			return "publication_retention_complete_fields_header_query"
		case "publication_fields_header_scope":
			return "publication_retention_complete_fields_header_scope"
		case "publication_fields_header_shape":
			return "publication_retention_complete_fields_header_shape"
		case "publication_fields_loan":
			return "publication_retention_complete_fields_loan"
		case "publication_fields_lockpins":
			return "publication_retention_complete_fields_lockpins"
		case "publication_fields_raw_shape":
			return "publication_retention_complete_fields_raw_shape"
		case "publication_fields_repeat":
			return "publication_retention_complete_fields_repeat"
		case "publication_fields_rows":
			return "publication_retention_complete_fields_rows"
		case "publication_fields_scope":
			return "publication_retention_complete_fields_scope"
		case "publication_fields_verify":
			return "publication_retention_complete_fields_verify"
		case "publication_retained_scope":
			return "publication_retention_complete_retained_scope"
		case "publication_retained_repeat":
			return "publication_retention_complete_retained_repeat"
		case "publication_retained_borrow":
			return "publication_retention_complete_retained_borrow"
		case "publication_retained_load":
			return "publication_retention_complete_retained_load"
		case "publication_retained_postread":
			return "publication_retention_complete_retained_postread"
		}
	case "publication_open":
		switch stage {
		case "publication_read_state":
			return "publication_publish_read_state"
		case "publication_read_models":
			return "publication_publish_read_models"
		case "publication_read_recipients":
			return "publication_publish_read_recipients"
		case "publication_read_fields":
			return "publication_publish_read_fields"
		case "publication_read_intent":
			return "publication_publish_read_intent"
		case "publication_read_evidence":
			return "publication_publish_read_evidence"
		case "publication_read_retained":
			return "publication_publish_read_retained"
		case "publication_fields_count":
			return "publication_publish_fields_count"
		case "publication_fields_fresh":
			return "publication_publish_fields_fresh"
		case "publication_fields_header":
			return "publication_publish_fields_header"
		case "publication_fields_header_cache":
			return "publication_publish_fields_header_cache"
		case "publication_fields_header_query":
			return "publication_publish_fields_header_query"
		case "publication_fields_header_scope":
			return "publication_publish_fields_header_scope"
		case "publication_fields_header_shape":
			return "publication_publish_fields_header_shape"
		case "publication_fields_loan":
			return "publication_publish_fields_loan"
		case "publication_fields_lockpins":
			return "publication_publish_fields_lockpins"
		case "publication_fields_raw_shape":
			return "publication_publish_fields_raw_shape"
		case "publication_fields_repeat":
			return "publication_publish_fields_repeat"
		case "publication_fields_rows":
			return "publication_publish_fields_rows"
		case "publication_fields_scope":
			return "publication_publish_fields_scope"
		case "publication_fields_verify":
			return "publication_publish_fields_verify"
		case "publication_retained_scope":
			return "publication_publish_retained_scope"
		case "publication_retained_repeat":
			return "publication_publish_retained_repeat"
		case "publication_retained_borrow":
			return "publication_publish_retained_borrow"
		case "publication_retained_load":
			return "publication_publish_retained_load"
		case "publication_retained_postread":
			return "publication_publish_retained_postread"
		}
	}
	return ""
}
