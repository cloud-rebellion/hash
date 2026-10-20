//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

// This is controlled missing-cache maintenance in the isolated real fixture.
// It never repairs or invents a cache. Actual original stale CAS must still
// refuse before body sizing, while unchanged CAS truthfully remains503.
func TestOwnedHTMLRevisionStaleCASPrecedesMissingCacheE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc := createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	before, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, q.f.org)
	if err != nil || removed.RowsAffected() != 1 {
		t.Fatal("controlled genuine cache removal failed", err)
	}
	//nolint:rawsql -- isolated maintenance refusal fixture, never runtime repair
	base := "/api/v1/documents/" + doc.ID.String() + "/html/revisions"
	for _, tc := range []struct {
		name  string
		clock time.Time
		want  int
	}{
		{"stale", doc.UpdatedAt.Time.Add(-time.Second), http.StatusConflict},
		{"current", doc.UpdatedAt.Time, http.StatusServiceUnavailable},
	} {
		body, e := json.Marshal(htmlDocumentRevisionInput{ExpectedUpdatedAt: tc.clock.Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: commitment, Values: htmlStringMap{"scope": "Changed declared scope"}, Summary: "Original CAS refusal"})
		if e != nil {
			t.Fatal(e)
		}
		w := submitSessionOperationE2E(q.f.s, http.MethodPost, base, string(body), q.cookie)
		if w.Code != tc.want {
			t.Fatalf("%s CAS with missing cache=%d %s", tc.name, w.Code, w.Body.String())
		}
		if tc.want == http.StatusServiceUnavailable && w.Header().Get("Retry-After") != "1" {
			t.Fatal("missing cache refused without bounded retry hint")
		}
		after, e := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
		if e != nil || !sameSignerDocumentSource(before, after) || after.UpdatedAt != before.UpdatedAt || !bytes.Equal(after.HtmlReviewedPdfSha256, before.HtmlReviewedPdfSha256) {
			t.Fatal("refused request changed original source or PDF", e)
		}
		var caches int
		if e = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, q.f.org).Scan(&caches); e != nil || caches != 0 {
			t.Fatal("refusal repaired missing old policy cache", e)
		}
		//nolint:rawsql -- exact isolated absence witness only
		q.reconcileV1(t)
		pending := q.runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.HTMLAdmissions != 0 || pending.HTMLInputProducers != 0 {
			t.Fatalf("actual refused request consumers retained work: %+v", pending)
		}
	}
}
