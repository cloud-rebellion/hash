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

// This positive route deliberately starts with a genuine fresh draft whose
// creator event/cache is owned119. It does not bypass or repair the separately
// pending legacy Send/negotiation/ceremony events from unchanged full116.
// Rendering/S3/retention retain the explicit synthetic113 fixture boundaries.
func TestOwnedFreshHTMLDraftRevisionsDeriveAllFreshCachesE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc := createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)
	origin := bytes.Clone(doc.HtmlSourceJson)
	for index, text := range []string{"First genuinely owned revised scope", "Second genuinely owned revised scope"} {
		before := doc
		cacheBefore := ownedDetailsCachesReadV1(t, q, before)
		fields, err := q.f.q.ListFieldsByDocument(q.f.ctx, before.ID)
		if err != nil || len(fields) != 2 {
			t.Fatal("genuine original managed fields missing", err)
		}
		oldIDs := map[string]bool{}
		for _, field := range fields {
			oldIDs[field.ID.String()] = true
		}
		var source, fieldJSON, parties, notice, events string
		err = q.f.pool.QueryRow(q.f.ctx, "SELECT coalesce(d.html_current_source_json,d.html_source_json)::text,c.fields_json::text,c.recipients_json::text,c.notice_context_json::text,c.ceremony_events_json::text FROM documents d CROSS JOIN LATERAL hash_html_materialization_snapshot_context(d.id)c WHERE d.id=$1 AND d.org_id=$2", before.ID, q.f.org).Scan(&source, &fieldJSON, &parties, &notice, &events)
		//nolint:rawsql -- complete original fixture oracle only, never runtime grant
		if err != nil {
			t.Fatal(err)
		}
		commitment, err := htmlsource.Commitment(before)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(htmlDocumentRevisionInput{ExpectedUpdatedAt: before.UpdatedAt.Time.Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: commitment, Values: htmlStringMap{"scope": text}, Summary: "Actual native fresh draft revision"})
		if err != nil {
			t.Fatal(err)
		}
		w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+before.ID.String()+"/html/revisions", string(raw), q.cookie)
		if w.Code != http.StatusCreated {
			t.Fatalf("actual native draft revision%d=%d %s", index, w.Code, w.Body.String())
		}
		doc = ownedDetailsDocumentV1(t, q, before)
		if doc.Status != "draft" || !bytes.Equal(doc.HtmlSourceJson, origin) || doc.HtmlCurrentMaterializationSequence.Int32 != before.HtmlCurrentMaterializationSequence.Int32+1 ||
			doc.HtmlCurrentMaterializationID == before.HtmlCurrentMaterializationID || doc.PdfStorageKey == before.PdfStorageKey || !doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" ||
			!doc.PdfStorageVersionID.Valid || doc.PdfStorageVersionID.String == "" || len(doc.PdfSha256) != 32 ||
			doc.HtmlReviewedAt.Valid || doc.HtmlReviewedBy.Valid || len(doc.HtmlReviewedPdfSha256) != 0 {
			t.Fatal("fresh revision lost immutable origin/new PDF tuple/review reset")
		}
		// Version IDs identify versions within a key; this protocol peer returns
		// the same version label for distinct keys. Verify both complete immutable
		// tuples, rather than requiring globally unique version strings.
		for _, artifact := range []*generated.Document{before, doc} {
			stored, err := q.f.s.Storage.GetVerifiedVersion(q.f.ctx, artifact.PdfStorageKey.String, artifact.PdfStorageVersionID.String, artifact.PdfSha256)
			if err != nil || len(stored) == 0 {
				t.Fatal("old or revised exact-version PDF tuple was not retrievable", err)
			}
		}
		cacheAfter := ownedDetailsCachesReadV1(t, q, doc)
		if cacheAfter.policy == cacheBefore.policy || cacheAfter.report == cacheBefore.report || cacheAfter.response != cacheBefore.response {
			t.Fatal("fresh91/93 were not derived or unchanged blocks/metadata cache was replaced")
		}
		currentFields, err := q.f.q.ListFieldsByDocument(q.f.ctx, doc.ID)
		if err != nil || len(currentFields) != 2 {
			t.Fatal("fresh managed fields absent", err)
		}
		for _, field := range currentFields {
			if oldIDs[field.ID.String()] {
				t.Fatal("old field identity reused")
			}
		}
		if err = htmlsource.ValidateSigningPageState(q.f.ctx, q.f.q, doc, 0); err != nil {
			t.Fatal("unchanged original signing-state oracle refused actual new source/fields/branding", err)
		}
		var gotSource, gotFields, gotParties, gotNotice, gotEvents string
		err = q.f.pool.QueryRow(q.f.ctx, "SELECT source_json::text,fields_json::text,recipients_json::text,notice_context_json::text,ceremony_events_json::text FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND kind='draft_superseded' AND captured_updated_at=$3", doc.ID, q.f.org, before.UpdatedAt).Scan(&gotSource, &gotFields, &gotParties, &gotNotice, &gotEvents)
		//nolint:rawsql -- compare complete retained history, never truncate
		if err != nil || gotSource != source || gotFields != fieldJSON || gotParties != parties || gotNotice != notice || gotEvents != events {
			t.Fatal("actual snapshot lost a complete original collection", err)
		}
		var snapshots, measuredSnapshots, measuredFields, documentEvents, measuredEvents int
		err = q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*)::integer FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2),(SELECT count(*)::integer FROM html_revision_snapshot_sizes_v1 WHERE document_id=$1 AND org_id=$2),(SELECT count(*)::integer FROM field_signing_policy_sizes_v1 s JOIN document_fields f ON f.id=s.field_id WHERE f.document_id=$1 AND s.org_id=$2),(SELECT count(*)::integer FROM events WHERE document_id=$1 AND org_id=$2),(SELECT count(*)::integer FROM html_snapshot_event_payload_sizes_v1 WHERE document_id=$1 AND org_id=$2)", doc.ID, q.f.org).Scan(&snapshots, &measuredSnapshots, &measuredFields, &documentEvents, &measuredEvents)
		//nolint:rawsql -- all actual fresh rows, no cache insertion or repair
		if err != nil || snapshots != index+1 || measuredSnapshots != snapshots || measuredFields != 2 || documentEvents != index+2 || measuredEvents != documentEvents {
			t.Fatal("genuine complete fresh history/field/event producers absent", snapshots, measuredSnapshots, measuredFields, documentEvents, measuredEvents, err)
		}
		ownedDetailsResponseReadV1(t, q, doc, true)
		ownedDetailsConsumedV1(t, q)
		if pending := q.runtime.SessionsV1().PendingV1(); pending.HTMLInputProducers != 0 || pending.HTMLCanonicalConsumers != 0 {
			t.Fatalf("actual revision producer retained work: %+v", pending)
		}
	}
}
