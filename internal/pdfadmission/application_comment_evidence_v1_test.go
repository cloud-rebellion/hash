// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

// Pure returned-row and fixed-payload guards, not simulated native authority.
func TestCommentPersistedEvidenceRequiresOriginalStatementV1(t *testing.T) {
	intended := generated.CreateCommentParams{DocumentID: uuid.New(), UserID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, AuthorName: "Actual author", AuthorSide: "sender", Body: "same length Å body"}
	row := generated.DocumentComment{ID: uuid.New(), DocumentID: intended.DocumentID, UserID: intended.UserID, AuthorName: intended.AuthorName, AuthorSide: intended.AuthorSide, Body: intended.Body, CreatedAt: pgtype.Timestamptz{Time: time.Date(2026, 10, 18, 12, 0, 0, 123456000, time.UTC), Valid: true}}
	if !commentPersistedRowMatchesV1(&row, intended) {
		t.Fatal("actual statement tuple refused")
	}
	for _, name := range []string{"body", "id", "document", "actor", "side", "timestamp", "submicrosecond"} {
		t.Run(name, func(t *testing.T) {
			copy := row
			switch name {
			case "body":
				copy.Body = "X" + copy.Body[1:]
			case "id":
				copy.ID = uuid.Nil
			case "document":
				copy.DocumentID = uuid.New()
			case "actor":
				copy.UserID.Bytes = uuid.New()
			case "side":
				copy.AuthorSide = "signer"
			case "timestamp":
				copy.CreatedAt.Valid = false
			case "submicrosecond":
				copy.CreatedAt.Time = copy.CreatedAt.Time.Add(time.Nanosecond)
			}
			if commentPersistedRowMatchesV1(&copy, intended) {
				t.Fatal("divergent persisted comment adopted")
			}
		})
	}
}
func TestCommentEvidenceAuditSchemaPreservesLegacyV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, purpose := range []HTMLAuditPurposeV1{HTMLAuditStaffCommentV1, HTMLAuditSignerCommentV1} {
		for _, payload := range []map[string]any{{"side": "sender"}, {"side": "signer", "comment_evidence_schema": CommentAuditEvidenceSchemaV1, "comment_id": uuid.NewString(), "comment_body_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "comment_created_at": "2026-10-18T12:00:00.123456Z"}} {
			if _, err := htmlAuditPayloadShapeV1(ctx, purpose, payload); err != nil {
				t.Fatal("additive evidence schema broke old or new fixed producer", err)
			}
		}
		if _, err := htmlAuditPayloadShapeV1(ctx, purpose, map[string]any{"side": "signer", "body": "private plaintext"}); err == nil {
			t.Fatal("plaintext body entered the fixed comment audit schema")
		}
	}
}
