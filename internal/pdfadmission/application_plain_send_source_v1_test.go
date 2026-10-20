// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/workguard"
	"testing"
)

// The ordinary uploaded-PDF tuple genuinely has no HTML origin/current. The
// same actual source constructor/body loan handles that input; no fabricated
// HTML record or reviewed sentinel is introduced to gain source authority.
func TestOwnedPlainPDFSourceRetainsActualAbsentHTMLV1(t *testing.T) {
	work, source, _, fixture, coordinator, _ := htmlSendEvidenceFixtureV1(t, HTMLSendPreparationV1, true)
	doc := work.models.Document
	if err := htmlsource.Validate(doc, true); err != nil {
		t.Fatal("original plain source oracle refused tuple", err)
	}
	if _, artifact, err := htmlsource.SigningPage(doc); err != nil || artifact != nil {
		t.Fatal("original plain Send oracle unexpectedly requires HTML artifact", err)
	}
	if _, err := htmlsource.Commitment(doc); err == nil {
		t.Fatal("plain success fabricated an HTML commitment")
	}
	if len(doc.HtmlSourceJson) != 0 || len(doc.HtmlCurrentSourceJson) != 0 || doc.HtmlCurrentMaterializationID.Valid || !work.currentRead || work.sourceCurrent != nil {
		t.Fatal("ordinary PDF was replaced by HTML/current authority")
	}
	if !source.MatchesDocumentV1(doc) {
		t.Fatal("actual ordinary PDF source did not validate")
	}
	changed := *doc
	changed.VariablesJson = []byte("{\"changed\":\"value\"}")
	if source.MatchesDocumentV1(&changed) {
		t.Fatal("mutable caller PDF variables replaced actual source")
	}
	var absent *generated.Document
	if source.MatchesDocumentV1(absent) {
		t.Fatal("absent caller view acquired actual source")
	}
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	if before.Global.ParentBytes <= 0 || before.Global.DBStagingBytes <= 0 {
		t.Fatal("plain PDF body/source missing actual credit", before)
	}
	work.CloseConsumerV1()
	after := coordinator.SnapshotV1(fixture.scope.OrgID)
	if after == (workguard.SnapshotV1{}) {
		t.Fatal("source consumer alone retired synthetic physical debt")
	}
}
