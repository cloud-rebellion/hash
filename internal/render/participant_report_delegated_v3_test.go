// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	stdhtml "html"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Public projection/formatter tests only: synthetic row commitments do not
// qualify a native execution, storage version, visible PDF or legal authority.
func delegatedReportFixtureV3(t *testing.T) (ParticipantNarrativeScopeDraft402, []*generated.Event, ParticipantReportV1, ParticipantDelegatedExecutionV1) {
	t.Helper()
	org, doc := uuid.New(), uuid.New()
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	e := &generated.Event{ID: uuid.New(), OrgID: org, DocumentID: pgtype.UUID{Bytes: doc, Valid: true}, Kind: "presign.execution.committed", CreatedAt: pgtype.Timestamptz{Time: at, Valid: true}, PayloadHashed: []byte(`{"private":"DO-NOT-PROJECT-ORIGINAL"}`)}
	var err error
	e.RowHash, err = audit.RecomputeEventRowHash(e)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := ParticipantReportEventsV1([]*generated.Event{e}, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	old := ParticipantReportV1{Schema: ParticipantReportSchemaV1, DocumentID: doc.String(), Cutoff: at.Add(time.Second).Format(time.RFC3339Nano), Events: metadata}
	hash := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte("hash:presign-disclosure:v1\x00" + delegatedDisclosureTextV1))
	d := ParticipantDelegatedExecutionV1{SchemaVersion: 1, EventID: e.ID.String(), EventRowSHA256: hex.EncodeToString(e.RowHash), EventAt: at.Format(time.RFC3339Nano), ExecutionID: uuid.NewString(), ExecutionSHA256: hash,
		PolicyID: uuid.NewString(), PolicyRevision: 1, PolicySHA256: hash, GrantID: uuid.NewString(), GrantRevision: 1, GrantSHA256: hash, UseNumber: 1,
		ProviderRecipientID: uuid.NewString(), ProviderSignatureID: uuid.NewString(), ProviderName: `Provider <&> Å`, ExecutedAt: at.Format(time.RFC3339Nano), BasePDFSHA256: hash, VisiblePDFSHA256: strings.Repeat("b", 64), AssetsSHA256: hash, OverlayProofSHA256: hash,
		DisclosureVersion: 1, DisclosureSHA256: hex.EncodeToString(sum[:]), DisclosureText: delegatedDisclosureTextV1}
	return ParticipantNarrativeScopeDraft402{Org: org, Root: doc, Documents: []uuid.UUID{doc}}, []*generated.Event{e}, old, d
}

func TestDelegatedReportV3ClosedCanonicalReadableAndLegacyUnchanged(t *testing.T) {
	scope, rows, old, d := delegatedReportFixtureV3(t)
	v2, err := NewParticipantReportV2(scope, rows, old)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := v2.CanonicalV2()
	if err != nil {
		t.Fatal(err)
	}
	beforeHTML, _, err := v2.HTMLV3()
	if err != nil {
		t.Fatal(err)
	}
	v3, err := NewParticipantReportV3(scope, rows, old, d)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := v3.CanonicalV2()
	if err != nil {
		t.Fatal(err)
	}
	standard, err := json.Marshal(v3)
	if err != nil || !bytes.Equal(raw, standard) || v3.SourceRowsV2() != v2.SourceRowsV2()+1 {
		t.Fatal("closed canonical/count differs", err)
	}
	html, digest, err := v3.HTMLV3()
	if err != nil || !strings.HasPrefix(html, ParticipantReportHTMLV4Start) || strings.Contains(html, "DO-NOT-PROJECT-ORIGINAL") || strings.Contains(html, d.ProviderName) {
		t.Fatal("privacy/escaping/version", err)
	}
	carrier := strings.Index(html, ParticipantReportCanonicalCarrierV3)
	if carrier < 0 {
		t.Fatal("exact canonical carrier missing")
	}
	readable := html[:carrier]
	for _, value := range []string{d.ExecutionID, d.ExecutionSHA256, d.AssetsSHA256, d.VisiblePDFSHA256, d.DisclosureSHA256, d.ProviderName, d.DisclosureText} {
		if !strings.Contains(readable, stdhtml.EscapeString(value)) {
			t.Fatal("readable delegated evidence missing", value)
		}
	}
	if !strings.Contains(readable, "customer's later manual signature") {
		t.Fatal("readable delegated/manual distinction missing")
	}
	parsed, actual, err := ParseParticipantReportHTMLV3(html)
	if err != nil || actual != digest || parsed.Schema != ParticipantReportSchemaV3 || VerifyParticipantReportOriginalEventsV2(scope, rows, parsed) != nil {
		t.Fatal("exact V3 roundtrip", err)
	}
	after, _, err := v2.CanonicalV2()
	again, _, htmlErr := v2.HTMLV3()
	if err != nil || htmlErr != nil || !bytes.Equal(before, after) || beforeHTML != again || bytes.Contains(after, []byte("delegated_execution")) {
		t.Fatal("V2 changed", err, htmlErr)
	}
}

func TestDelegatedReportV3RejectsCrossVersionTamperScopeAndDisclosure(t *testing.T) {
	scope, rows, old, d := delegatedReportFixtureV3(t)
	for name, change := range map[string]func(*ParticipantDelegatedExecutionV1){
		"foreign event":      func(v *ParticipantDelegatedExecutionV1) { v.EventID = uuid.NewString() },
		"row hash":           func(v *ParticipantDelegatedExecutionV1) { v.EventRowSHA256 = strings.Repeat("f", 64) },
		"unknown disclosure": func(v *ParticipantDelegatedExecutionV1) { v.DisclosureVersion = 2 },
		"changed disclosure": func(v *ParticipantDelegatedExecutionV1) { v.DisclosureText += " forged" },
		"late execution":     func(v *ParticipantDelegatedExecutionV1) { v.ExecutedAt = "2026-10-21T12:00:00Z" },
		"oversized provider": func(v *ParticipantDelegatedExecutionV1) { v.ProviderName = strings.Repeat("x", 801) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := d
			change(&copy)
			if _, err := NewParticipantReportV3(scope, rows, old, copy); err == nil {
				t.Fatal("invalid V3 accepted")
			}
		})
	}
	v3, err := NewParticipantReportV3(scope, rows, old, d)
	if err != nil {
		t.Fatal(err)
	}
	v3.Schema = ParticipantReportSchemaV2
	if _, _, err := v3.CanonicalV2(); err == nil {
		t.Fatal("V3 relabelled V2")
	}
	v3.Schema = ParticipantReportSchemaV3
	v3.DelegatedExecution = nil
	if _, _, err := v3.CanonicalV2(); err == nil {
		t.Fatal("V3 missing delegation")
	}
	rows[0].PayloadHashed = []byte(`{"changed":"raw forensic input"}`)
	if _, err := NewParticipantReportV3(scope, rows, old, d); err == nil {
		t.Fatal("unverified original payload accepted")
	}
}
