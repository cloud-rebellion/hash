//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func amendmentAbsenceSnapshot700(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) string {
	t.Helper()
	var state string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object('document',to_jsonb(d),
 'policy',(SELECT to_jsonb(p) FROM document_signing_policy_sizes_v1 p WHERE p.document_id=d.id),
 'response',(SELECT to_jsonb(p) FROM html_creation_response_sizes_v1 p WHERE p.document_id=d.id),
 'report',(SELECT to_jsonb(p) FROM document_read_report_sizes_v1 p WHERE p.document_id=d.id),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e WHERE e.document_id=d.id))::text
 FROM documents d WHERE d.id=$1 AND d.org_id=$2`, id, q.f.org).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestLaterAmendmentOrdinaryUncachedBlockDraftReturnsGenuineAbsence700E2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	// Deliberately reproduce the old draft's real missing measurements. This
	// scalar relation read must not fill a cache, adopt an unmeasured body or
	// claim that the legacy-shaped document is otherwise ready for Send.
	doc, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Synthetic unlinked legacy block draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	before := amendmentAbsenceSnapshot700(t, q, doc.ID)
	w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+doc.ID.String()+"/amendment", "", cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("ordinary no-relation response=%d want404 %s", w.Code, w.Body.String())
	}
	if amendmentAbsenceSnapshot700(t, q, doc.ID) != before {
		t.Fatal("negative relation lookup changed source, caches or event history")
	}
	ownedPlainAssertDrainedV1(t, q)
}

func TestLaterAmendmentAbsenceRetainsNativeActorAndPrivacyRefusal700E2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	doc, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Synthetic private ordinary draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/documents/" + doc.ID.String() + "/amendment"
	for _, role := range []string{"viewer", "sender"} {
		member, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@amendment.test", Name: "Synthetic reader", Role: role})
		if err != nil {
			t.Fatal(err)
		}
		cookie := dsrSessionCookieE2E(t, f.s, member.ID, member.SessionGeneration, time.Hour)
		if w := submitSessionOperationE2E(f.s, http.MethodGet, path, "", cookie); w.Code != http.StatusForbidden {
			t.Fatalf("%s foreign-sender relation response=%d", role, w.Code)
		}
	}
	_, err = f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, SubjectEmail: "subject@example.test", SubjectName: "Synthetic subject", Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	if w := submitSessionOperationE2E(f.s, http.MethodGet, path, "", cookie); w.Code != http.StatusConflict {
		t.Fatalf("pending privacy response=%d want409", w.Code)
	}
	ownedPlainAssertDrainedV1(t, q)
}

func TestLaterAmendmentLinkedNoticeStillUsesFullNativeSource700E2E(t *testing.T) {
	f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
	path := "/api/v1/documents/" + f.candidate.ID.String() + "/amendment"
	if w := submitSessionOperationE2E(f.q.f.s, http.MethodGet, path, "", f.q.cookie); w.Code != 200 {
		t.Fatalf("linked notice response=%d", w.Code)
	}
	// An actual linked record cannot use scalar absence to skip the native
	// source proof. This fixture-only cache fault must remain unavailable.
	if _, err := f.q.f.pool.Exec(f.q.f.ctx, `DELETE FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2`, f.candidate.ID, f.q.f.org); err != nil {
		t.Fatal(err)
	}
	if w := submitSessionOperationE2E(f.q.f.s, http.MethodGet, path, "", f.q.cookie); w.Code != 503 {
		t.Fatalf("linked missing source proof response=%d want503", w.Code)
	}
	if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
		t.Fatal("read refusal changed original accepted evidence")
	}
}
