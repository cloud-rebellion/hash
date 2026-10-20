// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func commentEvidenceFixture242(t *testing.T, side string) (*generated.DocumentComment, *generated.Event) {
	t.Helper()
	row := &generated.DocumentComment{ID: uuid.New(), DocumentID: uuid.New(), AuthorName: "Synthetic author", AuthorSide: side, Body: "Exact Unicode Å and <tag> body", CreatedAt: pgtype.Timestamptz{Time: time.Date(2026, 10, 18, 12, 0, 0, 123456000, time.UTC), Valid: true}}
	if side == "signer" {
		row.RecipientID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	} else {
		row.UserID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	}
	payload := commentAuditPayloadV1(pdfadmission.CommentAuditEvidenceV1{CommentID: row.ID, BodySHA256: sha256.Sum256([]byte(row.Body)), CreatedAt: row.CreatedAt, Side: side})
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event := &generated.Event{ID: uuid.New(), OrgID: uuid.New(), DocumentID: pgtype.UUID{Bytes: row.DocumentID, Valid: true}, ActorUserID: row.UserID, RecipientID: row.RecipientID, Kind: audit.KindCommentPosted, PayloadJson: raw, PayloadHashed: bytes.Clone(raw), CreatedAt: pgtype.Timestamptz{Time: row.CreatedAt.Time.Add(time.Microsecond), Valid: true}}
	event.RowHash, err = audit.RecomputeEventRowHash(event)
	if err != nil {
		t.Fatal(err)
	}
	return row, event
}
func TestCommentEvidenceMatchesExactPersistedContentV1(t *testing.T) {
	for _, side := range []string{"sender", "signer"} {
		t.Run(side, func(t *testing.T) {
			row, event := commentEvidenceFixture242(t, side)
			if ok, err := CommentAuditEvidenceMatchesV1(event, row); !ok || err != nil {
				t.Fatal("valid persisted evidence refused", err)
			}
			original := bytes.Clone(event.PayloadJson)
			for _, change := range []string{"id", "body", "time", "side", "actor"} {
				copy := *row
				switch change {
				case "id":
					copy.ID = uuid.New()
				case "body":
					copy.Body = "X" + copy.Body[1:]
				case "time":
					copy.CreatedAt.Time = copy.CreatedAt.Time.Add(time.Microsecond)
				case "side":
					copy.AuthorSide = "other"
				case "actor":
					if side == "signer" {
						copy.RecipientID.Bytes = uuid.New()
					} else {
						copy.UserID.Bytes = uuid.New()
					}
				}
				if ok, err := CommentAuditEvidenceMatchesV1(event, &copy); ok || err == nil {
					t.Fatal("different persisted comment matched original event", change)
				}
			}
			tampered := *event
			tampered.RowHash = make([]byte, 32)
			if ok, err := CommentAuditEvidenceMatchesV1(&tampered, row); ok || err == nil {
				t.Fatal("invalid event hash accepted")
			}
			if !bytes.Equal(event.PayloadJson, original) || bytes.Contains(event.PayloadJson, []byte(row.Body)) {
				t.Fatal("evidence rewrote history or exposed body plaintext")
			}
		})
	}
}
func TestLegacyCommentEventNeverAcquiresContentProofV1(t *testing.T) {
	for _, raw := range []string{`{"side":"sender"}`, `{"side":"signer","notice_schema":"legacy"}`} {
		event := &generated.Event{PayloadJson: []byte(raw)}
		before := bytes.Clone(event.PayloadJson)
		if ok, err := CommentAuditEvidenceMatchesV1(event, nil); ok || err != nil || !bytes.Equal(before, event.PayloadJson) {
			t.Fatal("legacy comment was rewritten or relabeled as content proof", err)
		}
	}
}

func TestCommentEvidenceJSONBRepresentationAndStrictKeysV1(t *testing.T) {
	row, event := commentEvidenceFixture242(t, "sender")
	var payload map[string]any
	if json.Unmarshal(event.PayloadJson, &payload) != nil {
		t.Fatal("fixture payload")
	}
	pretty, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	event.PayloadJson = pretty
	if ok, err := CommentAuditEvidenceMatchesV1(event, row); !ok || err != nil {
		t.Fatal("JSONB formatting invalidated exact original preimage", err)
	}
	for _, raw := range []string{string(event.PayloadJson[:len(event.PayloadJson)-1]) + `,"comment_id":"other"}`, string(event.PayloadJson[:len(event.PayloadJson)-1]) + `,"unexpected":"value"}`, string(event.PayloadJson) + " {}"} {
		copy := *event
		copy.PayloadJson = []byte(raw)
		if ok, err := CommentAuditEvidenceMatchesV1(&copy, row); ok || err == nil {
			t.Fatal("ambiguous/unknown evidence fields accepted")
		}
	}
	payload["comment_body_sha256"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	changed, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	copy := *event
	copy.PayloadJson = changed
	if ok, err := CommentAuditEvidenceMatchesV1(&copy, row); ok || err == nil {
		t.Fatal("different JSONB evidence replaced signed original payload")
	}
}
