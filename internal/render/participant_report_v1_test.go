// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func reportCommentFixtureV1(t *testing.T) (*generated.DocumentComment, *generated.Event) {
	t.Helper()
	at := pgtype.Timestamptz{Time: time.Date(2026, 10, 18, 12, 0, 0, 123456000, time.UTC), Valid: true}
	c := &generated.DocumentComment{ID: uuid.New(), DocumentID: uuid.New(), RecipientID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, AuthorName: "Participant <name>", AuthorSide: "signer", Body: "Shared <terms> and Å text", CreatedAt: at}
	sum := sha256.Sum256([]byte(c.Body))
	p, _ := json.Marshal(map[string]string{"side": c.AuthorSide, "comment_evidence_schema": "hash-comment-evidence-v1", "comment_id": c.ID.String(), "comment_body_sha256": hex.EncodeToString(sum[:]), "comment_created_at": at.Time.UTC().Format(time.RFC3339Nano)})
	e := &generated.Event{ID: uuid.New(), OrgID: uuid.New(), DocumentID: pgtype.UUID{Bytes: c.DocumentID, Valid: true}, RecipientID: c.RecipientID, Kind: audit.KindCommentPosted, CreatedAt: at, PayloadHashed: p, PayloadJson: []byte(`{"redacted":true}`), PrevHash: bytes.Repeat([]byte{1}, 32)}
	var err error
	e.RowHash, err = audit.RecomputeEventRowHash(e)
	if err != nil {
		t.Fatal(err)
	}
	return c, e
}

func TestParticipantReportCommentBindsOriginalForensicBodyAndActorV1(t *testing.T) {
	c, e := reportCommentFixtureV1(t)
	v, err := ParticipantReportCommentV1FromRow(c, []*generated.Event{e})
	if err != nil || v.Evidence != "body-and-actor-associated" || v.Body != c.Body || v.EventID != e.ID.String() {
		t.Fatalf("original body/actor association failed: %#v %v", v, err)
	}
	for _, name := range []string{"body", "actor", "side", "document", "timestamp", "row-hash", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			copy := *c
			event := *e
			events := []*generated.Event{&event}
			switch name {
			case "body":
				copy.Body += " changed"
			case "actor":
				copy.RecipientID.Bytes = uuid.New()
			case "side":
				copy.AuthorSide = "internal"
			case "document":
				copy.DocumentID = uuid.New()
			case "timestamp":
				copy.CreatedAt.Time = copy.CreatedAt.Time.Add(time.Microsecond)
			case "row-hash":
				event.RowHash = bytes.Repeat([]byte{2}, 32)
			case "duplicate":
				events = append(events, &event)
			}
			if _, err := ParticipantReportCommentV1FromRow(&copy, events); err == nil {
				t.Fatal("changed evidence adopted")
			}
		})
	}
}

func TestParticipantReportLegacyCommentIsExplicitlyUnverifiedV1(t *testing.T) {
	c, e := reportCommentFixtureV1(t)
	e.PayloadHashed = []byte(`{"side":"signer"}`)
	e.RowHash, _ = audit.RecomputeEventRowHash(e)
	v, err := ParticipantReportCommentV1FromRow(c, []*generated.Event{e})
	if err != nil || v.Evidence != "legacy-text-not-verified" || v.EventID != "" {
		t.Fatal("legacy text was retrospectively certified", v, err)
	}
}

func TestParticipantReportFiltersPrivateEventsWithoutRehashingRedactedRowsV1(t *testing.T) {
	_, e := reportCommentFixtureV1(t)
	private := *e
	private.ID = uuid.New()
	private.Kind = "billing.subscription_updated"
	private.PayloadHashed = []byte(`{"secret":"internal"}`)
	private.RowHash, _ = audit.RecomputeEventRowHash(&private)
	before := bytes.Clone(e.PayloadHashed)
	rows, err := ParticipantReportEventsV1([]*generated.Event{e, &private}, e.CreatedAt.Time)
	if err != nil || len(rows) != 1 || rows[0].RowSHA256 != hex.EncodeToString(e.RowHash) || !bytes.Equal(before, e.PayloadHashed) {
		t.Fatal("public projection rewrote or leaked forensic rows", rows, err)
	}
	if _, err := ParticipantReportEventsV1([]*generated.Event{e}, e.CreatedAt.Time.Add(-time.Microsecond)); err == nil {
		t.Fatal("event beyond frozen cutoff admitted")
	}
}

func TestParticipantReportPreservesStaffActorAndRecipientSubjectV1(t *testing.T) {
	_, event := reportCommentFixtureV1(t)
	event.Kind = audit.KindRecipientCreated
	event.ActorUserID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	event.PayloadHashed = []byte(`{"role":"signer"}`)
	var err error
	event.RowHash, err = audit.RecomputeEventRowHash(event)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParticipantReportEventsV1([]*generated.Event{event}, event.CreatedAt.Time)
	if err != nil || len(rows) != 1 {
		t.Fatal("valid staff recipient operation refused", err)
	}
	row := rows[0]
	if row.ActorID != uuid.UUID(event.ActorUserID.Bytes).String() || row.RecipientID != uuid.UUID(event.RecipientID.Bytes).String() || row.RowSHA256 != hex.EncodeToString(event.RowHash) {
		t.Fatal("staff actor and recipient subject were conflated", row)
	}
	changed := *event
	changed.ActorUserID.Bytes = uuid.New()
	if _, err := ParticipantReportEventsV1([]*generated.Event{&changed}, event.CreatedAt.Time); err == nil {
		t.Fatal("changed actor accepted under original row commitment")
	}
	changed = *event
	changed.RecipientID.Bytes = uuid.New()
	if _, err := ParticipantReportEventsV1([]*generated.Event{&changed}, event.CreatedAt.Time); err == nil {
		t.Fatal("changed recipient accepted under original row commitment")
	}
}

func TestParticipantReportRejectsOversizeHistoryInsteadOfTruncatingV1(t *testing.T) {
	r := ParticipantReportV1{Schema: ParticipantReportSchemaV1, DocumentID: uuid.NewString(), Cutoff: "2026-10-18T12:00:00Z", Comments: make([]ParticipantReportCommentV1, MaxParticipantReportRowsV1+1)}
	if _, _, err := r.CanonicalV1(); err == nil {
		t.Fatal("oversize row history accepted")
	}
	r.Comments = []ParticipantReportCommentV1{{Body: strings.Repeat("x", int(MaxParticipantReportRawBytesV1))}}
	if _, _, err := r.CanonicalV1(); err == nil {
		t.Fatal("oversize canonical history accepted")
	}
}

func TestParticipantReportAndReceiptCommitmentsAreInsideDetachedSignatureV1(t *testing.T) {
	c, e := reportCommentFixtureV1(t)
	comment, err := ParticipantReportCommentV1FromRow(c, []*generated.Event{e})
	if err != nil {
		t.Fatal(err)
	}
	r := ParticipantReportV1{Schema: ParticipantReportSchemaV1, DocumentID: c.DocumentID.String(), Cutoff: c.CreatedAt.Time.UTC().Format(time.RFC3339Nano), Comments: []ParticipantReportCommentV1{comment}, Responses: []ParticipantReportResponseV1{{RecipientID: uuid.UUID(c.RecipientID.Bytes).String(), ManifestSHA256: strings.Repeat("a", 64), LegalCommitmentSHA256: strings.Repeat("b", 64), Kind: "signed"}}}
	section, sum, err := r.HTMLV1()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(section, "Shared <terms>") || !strings.Contains(section, "Shared &lt;terms&gt;") {
		t.Fatal("shared text was not escaped")
	}
	key := NewAuditCertificateKeyV1(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)))
	doc := &generated.Document{ID: c.DocumentID, OrgID: e.OrgID}
	claims := CertificateEvidenceClaimsV1{ParticipantReportSchema: ParticipantReportSchemaV1, ParticipantReportSHA256: sum, ParticipantReportCutoff: r.Cutoff, ParticipantReportRows: 1, ParticipantReportHTML: section}
	_, payload, sig, err := CertificateFinishV1("prefix", doc, nil, claims, nil, key, "Org", "https://hash.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, section) || !strings.Contains(payload, sum) || sig == "" {
		t.Fatal("mandatory report omitted from signed payload")
	}
	claims.ParticipantReportHTML = strings.Replace(section, "body-and-actor-associated", "changed", 1)
	_, changed, changedSig, err := CertificateFinishV1("prefix", doc, nil, claims, nil, key, "Org", "https://hash.example")
	if err != nil || payload == changed || sig == changedSig {
		t.Fatal("report change did not change detached signature")
	}
	legacy := CertificateEvidenceClaimsV1{}
	if strings.Contains(legacy.HTML(), "participant-report") {
		t.Fatal("optional additive claims changed legacy claim bytes")
	}
}
