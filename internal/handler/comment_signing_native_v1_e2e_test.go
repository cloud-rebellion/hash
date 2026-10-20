//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	evidencepkg "github.com/bright-interaction/hash/internal/evidence"
	"net/http"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestOwnedPublicCommentSigningAndArtifactsE2E(t *testing.T) {
	testOwnedCommentSigningAndArtifactsV1(t, "signer")
}
func TestOwnedStaffCommentSigningAndArtifactsE2E(t *testing.T) {
	testOwnedCommentSigningAndArtifactsV1(t, "sender")
}
func testOwnedCommentSigningAndArtifactsV1(t *testing.T, side string) {
	t.Helper()
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	f.s.Sign.Storage = f.s.Storage
	doc, parties := q.createSentV1(t)
	bootstrap := q.requestV1(parties[0].Token, "")
	var page signerContextResponse
	if bootstrap.Code != http.StatusOK || json.Unmarshal(bootstrap.Body.Bytes(), &page) != nil {
		t.Fatal("actual notice bootstrap failed")
	}
	if ownedRevisionCommentProbeV1(t, q, doc, parties[0].Token, page.Privacy.NoticeDigest, side) {
		t.Fatal("native comment unmeasured")
	}
	for index, party := range parties {
		rc := q.lookupV1(t, party.Token)
		notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := signerArticle13NoticeEvidence(rc, notice)
		if err != nil {
			t.Fatal(err)
		}
		result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic native comment completion"})
		if closeErr := rc.CloseReadV1(); closeErr != nil {
			t.Fatal(closeErr)
		}
		q.assertObserversOnlyV1(t)
		if err != nil || result == nil || result.Completed != (index == len(parties)-1) {
			t.Fatal("commented contract did not preserve all-party completion", err)
		}
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != "completed" || !sameSignerDocumentSource(doc, current) {
		t.Fatal("viewed completion changed approved source or remained incomplete")
	}
	type pin struct {
		key, version pgtype.Text
		digest       []byte
	}
	var artifacts [][]byte
	for _, p := range []pin{{current.FinalPdfKey, current.FinalPdfVersionID, current.FinalPdfSha}, {current.AuditCertKey, current.AuditCertVersionID, current.AuditCertSha256}, {current.AuditPayloadKey, current.AuditPayloadVersionID, current.AuditPayloadSha256}, {current.AuditSignatureKey, current.AuditSignatureVersionID, current.AuditSignatureSha256}} {
		if !p.key.Valid || !p.version.Valid || p.version.String == "" || len(p.digest) != sha256.Size {
			t.Fatal("viewed completion omitted exact artifact pins")
		}
		b, err := readDocumentArtifact(f.ctx, f.s.Storage, current, p.key.String, p.digest, p.version)
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, b)
	}
	if !bytes.HasPrefix(artifacts[0], []byte("%PDF-")) || !bytes.HasPrefix(artifacts[1], []byte("%PDF-")) || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(artifacts[2]), string(artifacts[3])) {
		t.Fatal("viewed completion artifact verification failed")
	}

	claims, err := evidencepkg.ParseCertificateCommitments(artifacts[2])
	if err != nil || claims.DocumentID != current.ID.String() || claims.OrgID != current.OrgID.String() || claims.FinalPDFSHA256 != hex.EncodeToString(current.FinalPdfSha) || claims.CompletionEffectiveAt != current.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano) {
		t.Fatal("comment completion certificate claims mismatch", err)
	}

	// The signed certificate commits the chronological PRE-FINAL event prefix.
	// Completion itself is appended after that capture. Verify the actual full
	// prefix hash, including the comment, rather than looking for raw kind text
	// in a human-readable certificate or equating it with later live row count.
	rows, err := f.q.ListEventsByDocumentChronological(f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, Limit: int32(claims.DocumentEventsCount)})
	if err != nil {
		t.Fatal(err)
	}
	_, commitment, count, err := evidencepkg.BuildCeremonyEventsJSON(doc.ID, rows)
	comments := 0
	for _, row := range rows {
		if row.Kind == "document.comment_posted" {
			comments++
		}
	}
	if err != nil || count != claims.DocumentEventsCount || commitment != claims.DocumentEventsSHA256 || comments != 1 {
		t.Fatalf("signed pre-final history differs: count%d/signed%d comments%d commitmentMatch%t err=%v", count, claims.DocumentEventsCount, comments, commitment == claims.DocumentEventsSHA256, err)
	}
	var total, completed int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::integer,count(*) FILTER(WHERE kind='document.completed')::integer FROM events WHERE document_id=$1 AND org_id=$2", doc.ID, f.org).Scan(&total, &completed); err != nil || completed != 1 || total != count+completed {
		t.Fatalf("unexpected post-capture event set total%d prefix%d completed%d err=%v", total, count, completed, err)
	} //nolint:rawsql -- complete exact synthetic event-set oracle only
	t.Logf("actual %s comment direct signing: both parties complete, four exact artifact pins/digests/signatures and full signed pre-final event prefix including one comment verified", side)
	ownedRevisionConsumedV1(t, q)

}
