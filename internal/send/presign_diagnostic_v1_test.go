// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"context"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type preSignPrivateDiagnosticCause488 struct{}

func (*preSignPrivateDiagnosticCause488) Error() string {
	return "PRIVATE_PROVIDER_BODY_URL_SQL_ARGUMENT"
}
func TestPreSign488ClosedFailureStagePreservesCauseAndPrivacyV1(t *testing.T) {
	original := &preSignPrivateDiagnosticCause488{}
	cause := errors.Join(original, fmt.Errorf("PRIVATE_NESTED_VALUE: %w", presignexecute.ErrConflict))
	for _, stage := range []string{"confirm", "original_recovery", "reserve_preparation", "prepare_artifacts", "reserve_objects", "upload_artifacts", "commit_read", "commit_source", "commit_data", "commit_document", "commit_quota", "confirm_lawful_basis", "create_intent", "read_intent", "new_execution", "fresh_execution", "new_command", "audit_payload", "commit_audit", "new_record", "resolve_objects", "append_record", "pin_base", "commit_actor", "commit_deadline", "commit_transaction", "publication", "result_recovery"} {
		err := preSignFailureV1(stage, cause)
		if !errors.Is(err, presignexecute.ErrConflict) || PreSignFailureStageV1(err) != stage {
			t.Fatal("closed diagnostic changed original sentinel or stage")
		}
		var actual *preSignPrivateDiagnosticCause488
		if !errors.As(err, &actual) || actual != original {
			t.Fatal("diagnostic replaced original typed error identity")
		}
		if strings.Contains(err.Error(), "PRIVATE") || len(err.Error()) > 80 {
			t.Fatal("diagnostic projected private cause or unbounded output")
		}
		if PreSignFailureStageV1(fmt.Errorf("outer: %w", err)) != stage {
			t.Fatal("bounded diagnostic lost through original error wrapping")
		}
	}
	if preSignFailureV1("new_record", nil) != nil {
		t.Fatal("successful result became a failure")
	}
	if PreSignFailureStageV1(errors.New("new_record PRIVATE_PROVIDER_BODY_URL_SQL_ARGUMENT")) != "" {
		t.Fatal("foreign plaintext error forged a closed stage")
	}
	unknown := preSignFailureV1("PRIVATE_DYNAMIC_STAGE_PATH", cause)
	if PreSignFailureStageV1(unknown) != "operation" || strings.Contains(unknown.Error(), "PRIVATE") {
		t.Fatal("unknown stage escaped fixed fallback")
	}
}

func TestPreSign488ActualNativeAuditSubstageReachesClosedSendDiagnosticV1(t *testing.T) {
	var session *pdfadmission.ApplicationSessionV1
	_, native := session.NewHTMLAuditEventV1(context.Background(), pdfadmission.HTMLAuditPreSignCommittedV1, uuid.New(), uuid.New(), pgtype.UUID{}, pgtype.UUID{}, pdfadmission.HTMLAuditPreSignCommittedV1.KindV1(), "", "", nil)
	err := preSignFailureV1("commit_audit", native)
	if !errors.Is(err, pdfadmission.ErrHTMLAuditEventV1) || PreSignFailureStageV1(err) != "commit_audit_prepare_scope" {
		t.Fatal("actual native audit substage did not reach existing safe log extractor")
	}
	if PreSignFailureStageV1(preSignFailureV1("publication", native)) != "publication" {
		t.Fatal("audit substage replaced an unrelated operation label")
	}
	if PreSignFailureStageV1(preSignFailureV1("commit_audit", errors.New("append_cache PRIVATE_HEADER"))) != "commit_audit" {
		t.Fatal("foreign error forged an audit substage")
	}
	if len(PreSignFailureStageV1(err)) > 64 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("send diagnostic projection became unbounded or private")
	}
}

func TestPreSign488PublicationDiagnosticTraversesActualPrivateDepthV1(t *testing.T) {
	private := &preSignPrivateDiagnosticCause488{}
	cause := errors.Join(private, presignexecute.ErrConflict)
	deepest := preSignFailureV1("publication_read_evidence", cause)
	wrapped := preSignFailureV1("publication", preSignFailureV1("publication_recovery_open", deepest))
	var actual *preSignPrivateDiagnosticCause488
	if PreSignFailureStageV1(wrapped) != "publication_recovery_read_evidence" || !errors.Is(wrapped, presignexecute.ErrConflict) || !errors.As(wrapped, &actual) || actual != private {
		t.Fatal("actual three-level wrapping lost branch or original cause")
	}
	if strings.Contains(wrapped.Error(), "PRIVATE") || len(PreSignFailureStageV1(wrapped)) > 80 {
		t.Fatal("private or unbounded publication diagnostic")
	}
	var native *pdfadmission.ApplicationHTMLSendWorkV1
	_, nativeErr := native.PublishPreSignCustomerV1(context.Background(), "PRIVATE_URL", "PRIVATE_ORG")
	nestedNative := preSignFailureV1("publication", preSignFailureV1("publication_native", nativeErr))
	if PreSignFailureStageV1(nestedNative) != "publication_scope" || !errors.Is(nestedNative, pdfadmission.ErrHTMLSendWorkV1) {
		t.Fatal("actual native scope did not cross safe accessor")
	}
	_, readerErr := native.ReadRetainedPreSignV1(context.Background())
	readerDepth := preSignFailureV1("publication", preSignFailureV1("publication_recovery_open", preSignFailureV1("publication_read_retained", readerErr)))
	if PreSignFailureStageV1(readerDepth) != "publication_recovery_retained_scope" || !errors.Is(readerDepth, pdfadmission.ErrHTMLSendWorkV1) {
		t.Fatal("actual retained reader lost branch through all three Send layers")
	}
	if PreSignFailureStageV1(preSignFailureV1("publication", errors.New("publication_read_evidence PRIVATE"))) != "publication" {
		t.Fatal("foreign text forged inner stage")
	}
	forged := &preSignStageFailureV1{stage: "PRIVATE_DYNAMIC", cause: cause}
	if PreSignFailureStageV1(preSignFailureV1("publication", forged)) != "publication" {
		t.Fatal("unknown private stage escaped closed set")
	}
	for _, row := range []struct{ phase, expected, nativeExpected string }{
		{"publication_recovery_open", "publication_recovery_read_fields", "publication_recovery_fields_loan"},
		{"publication_retention_start_open", "publication_retention_start_read_fields", "publication_retention_start_fields_loan"},
		{"publication_retention_complete_open", "publication_retention_complete_read_fields", "publication_retention_complete_fields_loan"},
		{"publication_open", "publication_publish_read_fields", "publication_publish_fields_loan"},
	} {
		full := preSignFailureV1("publication", preSignFailureV1(row.phase, preSignFailureV1("publication_read_fields", cause)))
		var typed *preSignPrivateDiagnosticCause488
		if PreSignFailureStageV1(full) != row.expected || !errors.Is(full, presignexecute.ErrConflict) || !errors.As(full, &typed) || typed != private {
			t.Fatal("phase-qualified actual wrapper chain changed cause or phase")
		}
		if preSignPublicationReadStageV1(row.phase, "publication_fields_loan") != row.nativeExpected {
			t.Fatal("closed native field loan mapping lost phase")
		}
		if len(PreSignFailureStageV1(full)) > 80 || strings.Contains(full.Error(), "PRIVATE") {
			t.Fatal("phase qualification leaked private or unbounded text")
		}
	}
	if preSignPublicationReadStageV1("PRIVATE_PHASE", "publication_fields_loan") != "" || preSignPublicationReadStageV1("publication_open", "PRIVATE_STAGE") != "" {
		t.Fatal("unknown phase or field stage forged mapping")
	}
	if preSignFailureV1("publication_read_evidence", nil) != nil {
		t.Fatal("nil publication became failure")
	}
}
