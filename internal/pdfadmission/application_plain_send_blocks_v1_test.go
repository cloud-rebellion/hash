// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"errors"
	"github.com/bright-interaction/hash/internal/workguard"
	"reflect"
	"testing"
)

// Native tests deliberately reuse the existing synthetic SQL/body receipt. They
// prove actual immutable source/admission methods, not real PG creation or Send.
func TestOwnedBlockSourceUsesActualCanonicalEvidenceV1(t *testing.T) {
	raw := []byte("{\"version\":1,\"blocks\":[{\"id\":\"p\",\"type\":\"paragraph\",\"text\":\"Price {{amount}}\"},{\"id\":\"sig\",\"type\":\"signature_field\",\"attrs\":{\"recipient_role\":\"buyer\"}}]}")
	work, source, evidence, fixture, coordinator, _ := htmlSendEvidenceFixtureDocumentV1(t, HTMLSendPreparationV1, &htmlSendEvidenceSourceFixtureV1{sourceKind: "blocks", blocks: raw, variables: []byte("{\"amount\":\"20\"}")})
	if err := source.ValidateResolvedBlocksV1(); err != nil {
		t.Fatal(err)
	}
	roles, err := source.RequiredBlockRolesV1()
	if err != nil || !reflect.DeepEqual(roles, []string{"buyer"}) {
		t.Fatalf("actual block roles: %v %v", roles, err)
	}
	if pages, err := evidence.InspectPDFV1(); err != nil || pages != 0 {
		t.Fatalf("original blocks do not require a pre-send PDF: pages=%d err=%v", pages, err)
	}
	changed := *work.models.Document
	changed.BlocksJson = []byte("{\"version\":1,\"blocks\":[]}")
	if source.MatchesDocumentV1(&changed) {
		t.Fatal("caller tree replaced actual immutable blocks")
	}
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	if before.Global.ParentBytes <= 0 || before.Global.DBStagingBytes <= 0 {
		t.Fatal("missing real native source/body credit", before)
	}
	work.CloseConsumerV1()
	if coordinator.SnapshotV1(fixture.scope.OrgID) == (workguard.SnapshotV1{}) {
		t.Fatal("consumer closure retired still-open synthetic physical debt")
	}
}
func TestOwnedBlockSourcePreservesCanonicalRefusalsV1(t *testing.T) {
	cases := []struct {
		name, tree, vars string
		kind             error
	}{
		{"missing ID", "{\"version\":1,\"blocks\":[{\"type\":\"paragraph\",\"text\":\"body\"}]}", "{}", ErrPlainSendBlockTreeV1},
		{"unresolved frozen token", "{\"version\":1,\"blocks\":[{\"id\":\"p\",\"type\":\"paragraph\",\"text\":\"{{missing}}\"}]}", "{}", ErrPlainSendBlockVariablesV1},
		{"withdrawn legal draft", "{\"version\":1,\"blocks\":[{\"id\":\"p\",\"type\":\"paragraph\",\"text\":\"DRAFT KIT v1 (auto-seeded by Hash\"}]}", "{}", ErrPlainSendBlockLegalV1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, source, _, _, _, _ := htmlSendEvidenceFixtureDocumentV1(t, HTMLSendPreparationV1, &htmlSendEvidenceSourceFixtureV1{sourceKind: "blocks", blocks: []byte(tc.tree), variables: []byte(tc.vars)})
			if err := source.ValidateResolvedBlocksV1(); !errors.Is(err, tc.kind) {
				t.Fatalf("original policy refusal lost: %v", err)
			}
		})
	}
}
func TestOwnedBlockDecimalAdmissionRefusesBeforeLargeRatV1(t *testing.T) {
	raw := []byte("{\"version\":1,\"blocks\":[{\"id\":\"condition\",\"type\":\"conditional\",\"attrs\":{\"expression\":\"1e1000000 > 0\"},\"content\":[{\"id\":\"p\",\"type\":\"paragraph\",\"text\":\"body\"}]}]}")
	_, source, _, fixture, coordinator, ctx := htmlSendEvidenceFixtureDocumentV1(t, HTMLSendPreparationV1, &htmlSendEvidenceSourceFixtureV1{sourceKind: "blocks", blocks: raw, variables: []byte("{}")})
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	// Existing workAdmissionTestV1 has a declared1GiB parent limit. Occupy that
	// SAME actual coordinator, leaving enough for small lexical/parser staging,
	// while the accepted million-exponent decimal must fail its additional grant.
	occupy, err := coordinator.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ParentBytes: (1 << 30) - before.Global.ParentBytes - (256 << 10)})
	if err != nil {
		t.Fatal(err)
	}
	defer occupy.Close()
	err = source.ValidateResolvedBlocksV1()
	if err == nil {
		t.Fatal("large decimal ran without actual shared capacity")
	}
	if source.state.blockDecimalPeak <= 256<<10 || source.state.blockAdmissionFailure == nil {
		t.Fatalf("refusal did not occur at actual decimal admission: peak=%d failure=%v", source.state.blockDecimalPeak, source.state.blockAdmissionFailure)
	}
	if errors.Is(err, ErrPlainSendBlockTreeV1) {
		t.Fatalf("native capacity was misreported as malformed original grammar: %v", err)
	}
}
