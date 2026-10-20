// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestSignerAICapabilityRefusesSyntheticOwnersV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f := &ApplicationSessionFactoryV1{}
	if h, err := f.NewSignerAIRequestV1(ctx, &ApplicationSignerReaderV1{}, article13.Evidence{}, "", ""); err == nil || h != nil {
		t.Fatal("synthetic reader issued recipient processing authority")
	}
	h := &ApplicationSignerAIRequestV1{state: &applicationSignerAIRequestV1{}}
	if _, _, err := h.ScopeV1(ctx, f); err == nil {
		t.Fatal("copied/zero request issued actual scope")
	}
	if err := h.CaptureInputV1(ctx, "body", "en", "selection", "question"); err == nil {
		t.Fatal("unowned decoded input was adopted")
	}
	if w, err := (&ApplicationSessionV1{}).NewSignerAIWorkV1(ctx, h); err == nil || w != nil {
		t.Fatal("synthetic session became recipient dispatch")
	}
	if w, err := (&ApplicationSessionV1{}).NewDocumentAIWorkV1(ctx, uuid.Nil, "signer", "clarify_clause"); err == nil || w != nil {
		t.Fatal("signer was promoted to a staff actor")
	}
	h.CloseConsumerV1()
	h.CloseConsumerV1()
}

// Pure original-policy regression witnesses only. No native request/measurement,
// backend, audit receipt or successful producer is fabricated by these models.
func TestSignerAIOriginalCredentialPinsRejectExtensionsRotationAndNoticeV1(t *testing.T) {
	now := time.Now().UTC()
	org, doc, recipient := uuid.New(), uuid.New(), uuid.New()
	stamp := pgtype.Timestamptz{Time: now.Add(-time.Minute), Valid: true}
	expiry := pgtype.Timestamptz{Time: now.Add(time.Second), Valid: true}
	var hash [32]byte
	hash[0] = 7
	h := &applicationSignerAIRequestV1{org: org, document: doc, recipient: recipient, hash: hash, recipientExpiry: expiry, sentAt: stamp, noticeEpoch: stamp, noticeCommitted: true, name: "Original", basis: "contract", schema: article13.Schema, role: "signer", notice: article13.Evidence{Snapshot: article13.Snapshot{OrgID: org, DocumentID: doc, RecipientID: recipient, Schema: article13.Schema, SentAt: stamp.Time.UTC().Format(time.RFC3339Nano)}}}
	d := generated.Document{ID: doc, OrgID: org, Name: h.name, LawfulBasis: h.basis, SentAt: stamp, Article13NoticeEpochAt: stamp, Article13NoticeSchema: h.schema, Article13NoticeEpochV61Committed: true}
	r := generated.Recipient{ID: recipient, DocumentID: doc, Role: "signer", MagicTokenHash: append([]byte(nil), hash[:]...), MagicTokenExpiresAt: expiry}
	if err := h.checkDocumentV1(&d, &r, now); err != nil {
		t.Fatal("pure matching policy", err)
	}
	for _, change := range []string{"extended live expiry", "rotated token", "role", "notice epoch", "notice name", "notice basis", "moved member"} {
		t.Run(change, func(t *testing.T) {
			copyD, copyR := d, r
			at := now
			want := ErrSignerAIExpiredV1
			switch change {
			case "extended live expiry":
				copyR.MagicTokenExpiresAt.Time = now.Add(time.Hour)
				at = expiry.Time.Add(time.Nanosecond)
			case "rotated token":
				copyR.MagicTokenHash = make([]byte, 32)
			case "role":
				copyR.Role = "cc"
			case "notice epoch":
				copyD.Article13NoticeEpochAt.Time = stamp.Time.Add(time.Second)
				want = ErrSignerAINoticeV1
			case "notice name":
				copyD.Name = "Changed"
				want = ErrSignerAINoticeV1
			case "notice basis":
				copyD.LawfulBasis = "consent"
				want = ErrSignerAINoticeV1
			case "moved member":
				copyD.ParentEnvelopeID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
			}
			if err := h.checkDocumentV1(&copyD, &copyR, at); !errors.Is(err, want) {
				t.Fatal("original policy was extended or rebound", change, err)
			}
		})
	}
}
func TestSignerAIPurposesPreserveRecipientAndPrivatePayloadBoundaryV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if HTMLAuditSignerClarifierRequestedV1 != HTMLAuditAIRiskAnalyzedV1+1 {
		t.Fatal("historical purpose enum reordered")
	}
	h := &applicationSignerAIRequestV1{recipient: uuid.New(), block: "body", locale: "en", notice: article13.Evidence{Schema: "schema", Digest: "digest"}}
	scope := &applicationDocumentAIAuditScopeV1{signer: h, purpose: HTMLAuditSignerAIRequestedV1}
	rec, actor := scope.attributionV1()
	if !rec.Valid || rec.Bytes != h.recipient || actor.Valid {
		t.Fatal("recipient evidence acquired a staff identity")
	}
	payload := map[string]any{"via": "signer", "tool": "clarify_clause", "block_id": "body", "locale": "en", "notice_schema": "schema", "notice_digest": "digest", "notice_snapshot": h.notice.Snapshot}
	if !scope.signerPayloadMatchesV1(HTMLAuditSignerAIRequestedV1, payload) {
		t.Fatal("original concrete metadata schema refused")
	}
	if scope.signerPayloadMatchesV1(HTMLAuditAIRequestedV1, payload) {
		t.Fatal("signer payload borrowed staff request purpose")
	}
	payload["answer"] = "private answer"
	if scope.signerPayloadMatchesV1(HTMLAuditSignerAIRequestedV1, payload) {
		t.Fatal("private generated text became evidence payload")
	}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditSignerAIRequestedV1, payload); err == nil {
		t.Fatal("arbitrary payload shape admitted")
	}
}
