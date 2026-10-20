// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"testing"
)

func TestSendCompletionWitnessKeepsPrivateBodiesAndParentDebtV1(t *testing.T) {
	fixture, _, coordinator := applicationRequestLoanFixtureV1(t)
	ctx := applicationTestContextV1(t)
	// Predicate/copy/lifetime test uses the real shared coordinator, not a fake
	// Tx or a claim that a synthetic class passed the public capture constructor.
	doc := &generated.Document{ID: fixture.scope.DocumentID, OrgID: fixture.scope.OrgID, Name: "original", Metadata: []byte("{\"value\":1}"), BlocksJson: []byte("{}"), VariablesJson: []byte("{}")}
	raw, err := htmlSendCompletionDocumentResourcesV1(doc)
	if err != nil || raw <= 0 {
		t.Fatal("real full body has no concrete price", err)
	}
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	grant, err := coordinator.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ParentBytes: 8 * raw})
	if err != nil {
		t.Fatal(err)
	}
	op := &ApplicationHTMLSendOperationV1{}
	op.self = op
	owner := &applicationHTMLSendCompletionReferenceV1{operation: op, grant: grant, document: htmlSendCloneDocumentV1(doc)}
	owner.self = owner
	owner.reference.owner = owner
	op.completionReference = owner
	reference := &owner.reference
	if !reference.MatchesOperationV1(op) {
		t.Fatal("registered independent witness refused")
	}
	if (&ApplicationHTMLSendCompletionReferenceV1{owner: owner}).MatchesOperationV1(op) {
		t.Fatal("copied shell adopted native comparison authority")
	}
	charged := coordinator.SnapshotV1(fixture.scope.OrgID)
	if charged.Global.DBStagingBytes != before.Global.DBStagingBytes || charged.Global.ParentBytes <= before.Global.ParentBytes {
		t.Fatal("native memory copy did not retain only its actual Parent debt")
	}
	original := bytes.Clone(owner.document.Metadata)
	doc.Metadata = []byte("changed")
	doc.Name = "changed"
	if !bytes.Equal(owner.document.Metadata, original) || owner.document.Name == doc.Name {
		t.Fatal("old view changed private completion witness")
	}
	if coordinator.SnapshotV1(fixture.scope.OrgID) != charged {
		t.Fatal("comparison released source witness while consumer remains live")
	}
	owner.closeV1()
	if reference.MatchesOperationV1(op) {
		t.Fatal("closed native witness accepted")
	}
	if coordinator.SnapshotV1(fixture.scope.OrgID) != before {
		t.Fatal("actual completed witness left retained Parent debt")
	}
	if _, err := (*ApplicationHTMLSendEvidenceV1)(nil).CaptureCompletionReferenceV1(); err == nil {
		t.Fatal("absent source created completion comparison authority")
	}
}
