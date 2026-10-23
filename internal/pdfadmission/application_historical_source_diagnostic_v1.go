// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import "errors"

type historicalSourceStageFailureV1 struct {
	stage string
	cause error
}

func (e *historicalSourceStageFailureV1) Error() string { return e.cause.Error() }
func (e *historicalSourceStageFailureV1) Unwrap() error { return e.cause }
func historicalSourceStageKnownV1(stage string) bool {
	switch stage {
	case "delegated_asset_read", "delegated_asset_shape", "delegated_assets", "delegated_document", "delegated_load", "signature_activity", "signature_attempt", "signature_body", "signature_legacy_body", "signature_loan", "signature_pin", "signature_pin_shape", "signature_pin_tuple", "signature_pinned_body", "signature_quote", "signature_read", "signature_row_shape", "signature_rows", "signature_scope", "signature_state", "signature_version_shape", "source_activity", "source_attempt", "source_delegated", "source_new_limits", "source_new_loan", "source_new_quote", "source_new_scope", "source_new_work", "source_pdf", "source_pin_quote", "source_pin_shape", "source_pin_sql", "source_pin_tuple", "source_rendered", "source_scope", "source_work":
		return true
	}
	return false
}
func historicalSourceDiagnosticV1(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	if !historicalSourceStageKnownV1(stage) {
		stage = "source_scope"
	}
	return &historicalSourceStageFailureV1{stage: stage, cause: cause}
}

// Only original private Source24 wrappers supply fixed labels. At most an
// EnsureSource wrapper surrounds its original delegated-capture wrapper.
func HistoricalFinalizationSourceFailureStageV1(err error) string {
	var failure *historicalSourceStageFailureV1
	if !errors.As(err, &failure) || failure == nil || !historicalSourceStageKnownV1(failure.stage) {
		return ""
	}
	var inner *historicalSourceStageFailureV1
	if errors.As(failure.cause, &inner) && inner != nil && historicalSourceStageKnownV1(inner.stage) {
		return inner.stage
	}
	return failure.stage
}
