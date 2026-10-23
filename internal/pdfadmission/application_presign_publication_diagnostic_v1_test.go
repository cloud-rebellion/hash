// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type preSignPublicationPrivateCause488 struct{}

func (*preSignPublicationPrivateCause488) Error() string { return "PRIVATE_ROW_PROVIDER_HEADER_SQL" }
func TestPreSignPublication488DiagnosticPreservesActualScopeCauseAndPrivacyV1(t *testing.T) {
	var work *ApplicationHTMLSendWorkV1
	_, actual := work.PublishPreSignCustomerV1(context.Background(), "PRIVATE_URL", "PRIVATE_ORG")
	if !errors.Is(actual, ErrHTMLSendWorkV1) || HTMLPreSignPublicationFailureStageV1(actual) != "publication_scope" {
		t.Fatal("actual nil native scope lost original sentinel")
	}
	_, reader := work.ReadRetainedPreSignV1(context.Background())
	if !errors.Is(reader, ErrHTMLSendWorkV1) || HTMLPreSignPublicationFailureStageV1(reader) != "publication_retained_scope" {
		t.Fatal("actual nil retained reader lost original scope sentinel")
	}
	publisherReader := htmlPreSignPublicationFailureV1("publication_retained_read", reader)
	if HTMLPreSignPublicationFailureStageV1(publisherReader) != "publication_retained_scope" || !errors.Is(publisherReader, ErrHTMLSendWorkV1) {
		t.Fatal("publisher retained read hid inner reader branch")
	}
	for _, purpose := range []HTMLSendSQLPurposeV1{HTMLPreSignRecoveryV1, HTMLPreSignRetentionV1, HTMLPreSignPublicationV1, HTMLSendPreparationV1} {
		stage := &ApplicationHTMLSendSQLStageV1{purpose: purpose}
		stage.self = stage
		scoped := &ApplicationHTMLSendWorkV1{stage: stage}
		scoped.self = scoped
		_, scopeErr := scoped.ReadFieldsV1(context.Background())
		if !errors.Is(scopeErr, ErrHTMLSendWorkV1) {
			t.Fatal("actual fields scope changed original sentinel")
		}
		if purpose == HTMLSendPreparationV1 {
			if scopeErr != ErrHTMLSendWorkV1 || HTMLPreSignPublicationFailureStageV1(scopeErr) != "" {
				t.Fatal("ordinary collection gained pre-sign diagnostics")
			}
		} else if HTMLPreSignPublicationFailureStageV1(scopeErr) != "publication_fields_scope" {
			t.Fatal("trusted pre-sign fields scope was not observed")
		}
		original := errors.New("PRIVATE_COLLECTION_BODY")
		if htmlPreSignFieldsFailureV1(scoped, htmlSendRecipientCollectionV1, "publication_fields_loan", original) != original {
			t.Fatal("recipient purpose error identity changed")
		}
		if purpose == HTMLSendPreparationV1 && htmlPreSignFieldsFailureV1(scoped, htmlSendFieldCollectionV1, "publication_fields_loan", original) != original {
			t.Fatal("ordinary field error identity changed")
		}
	}
	fieldCause := errors.Join(ErrHTMLSendWorkV1, errors.New("PRIVATE_COLLECTION_BODY"))
	headerLoan := htmlPreSignPublicationFailureV1("publication_fields_header", htmlPreSignPublicationFailureV1("publication_fields_loan", fieldCause))
	if HTMLPreSignPublicationFailureStageV1(headerLoan) != "publication_fields_loan" || !errors.Is(headerLoan, ErrHTMLSendWorkV1) || strings.Contains(headerLoan.Error(), "PRIVATE") {
		t.Fatal("field/header private nesting lost loan branch or original sentinel")
	}
	private := &preSignPublicationPrivateCause488{}
	cause := errors.Join(private, ErrHTMLSendWorkV1)
	nested := htmlPreSignPublicationFailureV1("publication_source", htmlPreSignPublicationFailureV1("publication_source_fields", cause))
	var recovered *preSignPublicationPrivateCause488
	if !errors.Is(nested, ErrHTMLSendWorkV1) || !errors.As(nested, &recovered) || recovered != private || HTMLPreSignPublicationFailureStageV1(nested) != "publication_source_fields" {
		t.Fatal("native source nesting replaced cause or lost branch")
	}
	if strings.Contains(nested.Error(), "PRIVATE") || len(nested.Error()) > 128 {
		t.Fatal("native diagnostic leaked private or unbounded cause")
	}
	if htmlPreSignPublicationFailureV1("publication_scope", nil) != nil {
		t.Fatal("nil became failure")
	}
	if HTMLPreSignPublicationFailureStageV1(errors.New("publication_source_fields PRIVATE")) != "" {
		t.Fatal("foreign plaintext forged stage")
	}
	if HTMLPreSignPublicationFailureStageV1(&htmlPreSignPublicationFailure488V1{stage: "PRIVATE_DYNAMIC", cause: cause}) != "" {
		t.Fatal("unknown forged private label projected")
	}
	unknown := htmlPreSignPublicationFailureV1("PRIVATE_DYNAMIC", cause)
	if HTMLPreSignPublicationFailureStageV1(unknown) != "publication_scope" || strings.Contains(unknown.Error(), "PRIVATE") {
		t.Fatal("unknown constructor label escaped fixed fallback")
	}
}
