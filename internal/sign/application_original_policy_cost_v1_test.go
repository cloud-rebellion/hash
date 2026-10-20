// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5/pgtype"
)

// Test retained data pricing and the real private issuer separately. Pricing
// never validates, decodes or authorizes caller-mutated HTML. The actual owned
// journal acquires the combined ORIGINAL+CURRENT policy loan before issuance.
func TestApplicationOriginalPolicyCostV1PricesMutableRetainedHTMLBeforeDecode(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	base, err := applicationOriginalPolicyBytesV1(rc)
	if err != nil {
		t.Fatal(err)
	}
	rc.Document.HtmlSourceJson = []byte("retained original malformed HTML source")
	rc.Document.HtmlCurrentSourceJson = []byte("separate retained current malformed HTML source")
	rc.Document.VariablesJson = []byte("retained original values")
	rc.Document.PdfStorageKey = pgtype.Text{String: "retained/source/key", Valid: true}
	rc.Document.PdfStorageVersionID = pgtype.Text{String: "retained-source-version", Valid: true}
	rc.Document.HtmlEffectiveSourceCommitment = pgtype.Text{String: "retained-source-commitment", Valid: true}
	growth := int64(len(rc.Document.HtmlSourceJson) + len(rc.Document.HtmlCurrentSourceJson) + len(rc.Document.VariablesJson) + len(rc.Document.PdfStorageKey.String) + len(rc.Document.PdfStorageVersionID.String) + len(rc.Document.HtmlEffectiveSourceCommitment.String))
	got, err := applicationOriginalPolicyBytesV1(rc)
	if err != nil || got != base+growth {
		t.Fatal("retained byte pricing omitted body/text", got, err)
	}
	// The real issuer still validates the original source after pricing; length
	// metadata is no semantic permission, and malformed retained source refuses.
	if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, presentedCredentialTestInputV1(t, rc)); err == nil {
		t.Fatal("retained lengths authorized malformed source")
	}
	currentBytes := int64(9000)
	combined, err := requestPayloadAddV1(currentBytes, got)
	if err != nil {
		t.Fatal(err)
	}
	cost := pdfadmission.ApplicationRequestJournalCostV1{Kind: pdfadmission.ApplicationRequestJournalCaptureV1, OriginBytes: 2000, IntentBytes: 7000, AuthorityBytes: 11000, SpanBytes: 13000, CurrentContextBytes: 17000, OriginalRawContextBytes: 19000, PolicyBytes: combined}
	actual, err := pdfadmission.ApplicationRequestJournalResourcesForV1(cost)
	if err != nil {
		t.Fatal(err)
	}
	onlyCurrent := cost
	onlyCurrent.PolicyBytes = currentBytes
	earlier, err := pdfadmission.ApplicationRequestJournalResourcesForV1(onlyCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if actual.WorkingBytes-earlier.WorkingBytes != 16*got || actual.DBStagingBytes-earlier.DBStagingBytes != 16*got {
		t.Fatal("fixed resource costs omitted retained original policy")
	}
	for _, bad := range []*RecipientContext{nil, {}} {
		if _, err := applicationOriginalPolicyBytesV1(bad); !errors.Is(err, errApplicationBoundRequestV1) {
			t.Fatal("missing retained context got a policy budget")
		}
	}
}
