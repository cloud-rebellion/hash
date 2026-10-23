// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import "errors"

type htmlPreSignPublicationFailure488V1 struct {
	stage string
	cause error
}

func (e *htmlPreSignPublicationFailure488V1) Error() string {
	return "pre-sign publication failed at " + e.stage
}
func (e *htmlPreSignPublicationFailure488V1) Unwrap() error { return e.cause }
func htmlPreSignPublicationStageKnownV1(stage string) bool {
	switch stage {
	case "publication_fields_count", "publication_fields_fresh", "publication_fields_header", "publication_fields_header_cache", "publication_fields_header_query", "publication_fields_header_scope", "publication_fields_header_shape", "publication_fields_loan", "publication_fields_lockpins", "publication_fields_raw_shape", "publication_fields_repeat", "publication_fields_rows", "publication_fields_scope", "publication_fields_verify":
		return true
	case "publication_retained_scope", "publication_retained_repeat", "publication_retained_borrow", "publication_retained_load", "publication_retained_postread":
		return true
	case "publication_current", "publication_current_document", "publication_current_document_loan", "publication_current_intent", "publication_current_outbox", "publication_current_recipients", "publication_current_scope", "publication_document_exact", "publication_document_loan", "publication_document_sent", "publication_expired_loan", "publication_expired_read", "publication_expired_sql", "publication_expired_token", "publication_input_loan", "publication_input_size", "publication_invite_render", "publication_mark_canonical", "publication_mark_current", "publication_mark_hash", "publication_mark_loan", "publication_mark_measure", "publication_mark_payload", "publication_mark_read", "publication_mark_row", "publication_mark_scope", "publication_mark_shape", "publication_mark_size", "publication_mark_update", "publication_outbox", "publication_output_loan", "publication_output_size", "publication_policy_freeze", "publication_proof_shape", "publication_proof_sql", "publication_recipient_read", "publication_recipient_sent", "publication_reminder_cancel", "publication_reminder_upsert", "publication_retained_read", "publication_scope", "publication_source", "publication_source_field_validation", "publication_source_fields", "publication_source_parties", "publication_source_party_validation", "publication_source_repeat", "publication_source_scope", "publication_source_validate", "publication_state_loan", "publication_token", "publication_token_sql":
		return true
	}
	return false
}
func htmlPreSignPublicationFailureV1(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	if !htmlPreSignPublicationStageKnownV1(stage) {
		stage = "publication_scope"
	}
	return &htmlPreSignPublicationFailure488V1{stage: stage, cause: cause}
}

// Only one fixed native source/current wrapper can lie below this publisher.
// No cause text, row values, headers, IDs, SQL or arbitrary labels are read.
func HTMLPreSignPublicationFailureStageV1(err error) string {
	var failure *htmlPreSignPublicationFailure488V1
	if !errors.As(err, &failure) || failure == nil || !htmlPreSignPublicationStageKnownV1(failure.stage) {
		return ""
	}
	switch failure.stage {
	case "publication_source", "publication_source_repeat", "publication_current", "publication_mark_current", "publication_retained_read", "publication_fields_header":
		var inner *htmlPreSignPublicationFailure488V1
		if errors.As(failure.cause, &inner) && inner != nil && htmlPreSignPublicationStageKnownV1(inner.stage) {
			return inner.stage
		}
	}
	return failure.stage
}

// Only immutable private Work/Stage identity and the three pre-sign purposes
// select this observation. Other collection users retain the original error.
func htmlPreSignFieldsFailureV1(w *ApplicationHTMLSendWorkV1, purpose htmlSendCollectionPurposeV1, stage string, cause error) error {
	if cause == nil || purpose != htmlSendFieldCollectionV1 || w == nil || w.self != w || w.stage == nil || w.stage.self != w.stage {
		return cause
	}
	switch w.stage.purpose {
	case HTMLPreSignRecoveryV1, HTMLPreSignRetentionV1, HTMLPreSignPublicationV1:
		return htmlPreSignPublicationFailureV1(stage, cause)
	}
	return cause
}
