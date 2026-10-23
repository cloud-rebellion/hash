// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
)

func TestDelegatedSignerPublicDisclosureIsClosedAndCannotMutatePrivateBindingV1(t *testing.T) {
	rc := &RecipientContext{delegated: &delegatedSignerEvidenceV1{public: PreSignContextV1{SchemaVersion: 1, DocumentID: uuid.New(), ExecutionID: uuid.New(), ExecutionSHA256: strings.Repeat("a", 64), VisiblePDFSHA256: strings.Repeat("b", 64), DisclosureVersion: 1, DisclosureSHA256: strings.Repeat("c", 64), DisclosureText: "retained disclosure", ProviderName: "declared provider", ExecutedAt: "2026-10-20T12:00:00Z"}, visible: presign.ArtifactPin{StorageKey: "PRIVATE-KEY", VersionID: "PRIVATE-VERSION"}, assetsSHA256: "PRIVATE-ASSET"}}
	copy := rc.PreSignContextV1()
	raw, err := json.Marshal(copy)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != 10 {
		t.Fatal("public shape changed")
	}
	for _, key := range []string{"schema_version", "document_id", "execution_id", "execution_sha256", "visible_pdf_sha256", "disclosure_version", "disclosure_sha256", "disclosure_text", "provider_name", "executed_at"} {
		if _, ok := object[key]; !ok {
			t.Fatal("missing public field", key)
		}
	}
	if strings.Contains(string(raw), "PRIVATE-") || strings.Contains(string(raw), "storage_key") || strings.Contains(string(raw), "version_id") {
		t.Fatal("private storage capability disclosed")
	}
	copy.VisiblePDFSHA256 = strings.Repeat("f", 64)
	if rc.PreSignContextV1().VisiblePDFSHA256 == copy.VisiblePDFSHA256 {
		t.Fatal("public copy changed original binding")
	}
	original := cloneDelegatedSignerEvidenceV1(rc.delegated)
	rc.delegated.visible.VersionID += "-changed"
	if sameDelegatedSignerEvidenceV1(original, rc.delegated) {
		t.Fatal("same public PDF hid changed immutable version")
	}
	if (*RecipientContext)(nil).PreSignContextV1() != nil || (&RecipientContext{}).PreSignContextV1() != nil {
		t.Fatal("ordinary context invented delegation")
	}
}

func TestDelegatedFittedRequestRefusesBeforeAnyPreparationOrSQLV1(t *testing.T) {
	rc := &RecipientContext{delegated: &delegatedSignerEvidenceV1{}}
	if _, err := (*Engine)(nil).validateFittedRequestV1(context.Background(), rc, SignInput{}); !errors.Is(err, ErrDelegatedFittedUnsupportedV1) {
		t.Fatal("fitted request did not explicitly refuse", err)
	}
	// A nil journal/factory would panic if the original native Open happened.
	// This test qualifies refusal ordering only, not a native transaction.
	if _, _, err := (*applicationRequestJournalV1)(nil).prepareV1(context.Background(), nil, rc, SignInput{}, pdfadmission.ApplicationRequestJournalCaptureV1); !errors.Is(err, ErrDelegatedFittedUnsupportedV1) {
		t.Fatal("fitted preparation began before refusal", err)
	}
}
