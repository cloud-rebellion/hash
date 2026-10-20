//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	evidencepkg "github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/htmlsource"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Genuine existing negotiation/revision journey. No cache insertion/repair,
// fabricated sent/completed state, source bypass or history truncation.
// The reused fixture explicitly has synthetic renderer/S3/retention boundaries.
func TestOwnedHTMLNegotiationRevisionResendAndCompleteE2E(t *testing.T) {
	testOwnedHTMLNegotiationRevisionResendAndCompleteV1(t, "")
}

func TestOwnedPublicCommentRevisionResendAndCompleteE2E(t *testing.T) {
	testOwnedHTMLNegotiationRevisionResendAndCompleteV1(t, "signer")
}

func TestOwnedStaffCommentRevisionResendAndCompleteE2E(t *testing.T) {
	testOwnedHTMLNegotiationRevisionResendAndCompleteV1(t, "sender")
}

func testOwnedHTMLNegotiationRevisionResendAndCompleteV1(t *testing.T, commentSide string) {
	t.Helper()
	q := newOwnedPublicReadFixtureV1(t)
	original, parties := q.createSentV1(t)
	fields, err := q.f.q.ListFieldsByDocument(q.f.ctx, original.ID)
	if err != nil || len(fields) != 2 {
		t.Fatal("actual original managed fields absent", err)
	}
	oldFieldIDs := map[string]bool{}
	for _, field := range fields {
		oldFieldIDs[field.ID.String()] = true
	}
	bootstrap := q.requestV1(parties[0].Token, "")
	var page signerContextResponse
	if bootstrap.Code != http.StatusOK || json.Unmarshal(bootstrap.Body.Bytes(), &page) != nil || page.DocumentID != original.ID || page.Privacy.NoticeDigest == "" || page.PDFObservation == nil {
		t.Fatal("genuine public context/notice unavailable")
	}
	commentUnmeasured := false
	if commentSide != "" {
		commentUnmeasured = ownedRevisionCommentProbeV1(t, q, original, parties[0].Token, page.Privacy.NoticeDigest, commentSide)
	}
	var beforeOwnerMail int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE to_email=$1", q.f.user.Email).Scan(&beforeOwnerMail); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- exact synthetic owner outbox witness only
	requestBody, err := json.Marshal(signerRequestChangesInput{Message: "Please revise the declared service scope", Proposed: "Human-approved revised synthetic service scope"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/sign/"+parties[0].Token+"/request-changes", bytes.NewReader(requestBody)).WithContext(q.f.ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", q.f.s.PublicURL)
	request.Header.Set(signerNoticeDigestHeader, page.Privacy.NoticeDigest)
	response := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, request)
	var changed map[string]string
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &changed) != nil || changed["status"] != "changes_requested" {
		t.Fatalf("genuine notice-bound public change request=%d %s", response.Code, response.Body.String())
	}
	var afterOwnerMail, noticeEvents int
	var noticeBound bool
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE to_email=$1", q.f.user.Email).Scan(&afterOwnerMail); err != nil || afterOwnerMail != beforeOwnerMail+1 {
		t.Fatal("actual negotiation owner notification not enqueued exactly once", err)
	} //nolint:rawsql -- actual queueing, not SMTP delivery claim
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer,coalesce(bool_and(payload_json->>$4=$5),false) FROM events WHERE org_id=$1 AND document_id=$2 AND recipient_id=$3 AND kind='document.changes_requested'", q.f.org, original.ID, parties[0].RecipientID, article13.AuditNoticeDigestKey, page.Privacy.NoticeDigest).Scan(&noticeEvents, &noticeBound); err != nil || noticeEvents != 1 || !noticeBound {
		t.Fatal("actual change response did not bind original server notice", err)
	} //nolint:rawsql -- exact fresh response evidence oracle
	ownedRevisionConsumedV1(t, q)
	requests, err := q.f.q.ListChangeRequests(q.f.ctx, original.ID)
	if err != nil || len(requests) != 1 {
		t.Fatal("actual change request missing", err)
	}
	base := "/api/v1/documents/" + original.ID.String()
	if w := submitSessionOperationE2E(q.f.s, http.MethodPost, base+"/change-requests/"+requests[0].ID.String()+"/approve", "", q.cookie); w.Code != http.StatusOK {
		t.Fatalf("genuine sender approval=%d %s", w.Code, w.Body.String())
	}
	paused, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: q.f.org})
	if err != nil || paused.Status != "changes_requested" || !sameSignerDocumentSource(original, paused) {
		t.Fatal("HTML approval auto-applied unreviewed prose or lost paused state", err)
	}
	// Exact complete canonical collection witnesses, captured BEFORE Revise.
	// These are fixture-only reads of fresh synthetic rows, never runtime grants.
	var retiredSource, retiredFields, retiredRecipients, retiredNotice, retiredEvents string
	err = q.f.pool.QueryRow(q.f.ctx, "SELECT coalesce(d.html_current_source_json,d.html_source_json)::text,c.fields_json::text,c.recipients_json::text,c.notice_context_json::text,c.ceremony_events_json::text FROM documents d CROSS JOIN LATERAL hash_html_materialization_snapshot_context(d.id)c WHERE d.id=$1 AND d.org_id=$2", original.ID, q.f.org).Scan(&retiredSource, &retiredFields, &retiredRecipients, &retiredNotice, &retiredEvents) //nolint:rawsql -- complete fresh synthetic history oracle only
	if err != nil {
		t.Fatal(err)
	}
	// Capture complete paused state immediately before the actual revision.
	// These fixture-only observations never write caches or grant runtime work.
	pausedRecipients, err := q.f.q.ListRecipientsByDocument(q.f.ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(pausedRecipients, func(i, j int) bool { return pausedRecipients[i].ID.String() < pausedRecipients[j].ID.String() })
	pausedChange, err := q.f.q.GetChangeRequest(q.f.ctx, generated.GetChangeRequestParams{ID: requests[0].ID, OrgID: q.f.org})
	if err != nil || pausedChange.Status != "resolved" || !pausedChange.Resolution.Valid || pausedChange.Resolution.String != "approved" {
		t.Fatal("actual approved request absent", err)
	}
	var retiredBefore, revisedBefore int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*)::integer FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND kind='ceremony_retired'),(SELECT count(*)::integer FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.revised')", original.ID, q.f.org).Scan(&retiredBefore, &revisedBefore); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- complete fresh synthetic rollback counts
	pausedMissing := ownedRevisionMissingEventsV1(t, q, original)
	if (commentUnmeasured && pausedMissing != 1) || (!commentUnmeasured && pausedMissing != 0) {
		t.Fatal("actual approved paused event deficit changed before revision")
	}
	wRevise := submitSessionOperationE2E(q.f.s, http.MethodPost, base+"/revise", "", q.cookie)
	if wRevise.Code != http.StatusOK {
		if commentSide != "" && commentUnmeasured {
			if wRevise.Code != http.StatusServiceUnavailable || wRevise.Header().Get("Retry-After") != "1" || wRevise.Body.String() != "{\"error\":\"revision temporarily unavailable\"}\n" {
				t.Fatal("comment deficit produced an unexpected refusal", wRevise.Code)
			}
			after, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: q.f.org})
			if err != nil || !reflect.DeepEqual(paused, after) {
				t.Fatal("refused revision changed complete paused document", err)
			}
			afterRecipients, err := q.f.q.ListRecipientsByDocument(q.f.ctx, original.ID)
			if err != nil {
				t.Fatal(err)
			}
			sort.Slice(afterRecipients, func(i, j int) bool { return afterRecipients[i].ID.String() < afterRecipients[j].ID.String() })
			afterChange, err := q.f.q.GetChangeRequest(q.f.ctx, generated.GetChangeRequestParams{ID: requests[0].ID, OrgID: q.f.org})
			if err != nil || !reflect.DeepEqual(pausedChange, afterChange) || !reflect.DeepEqual(pausedRecipients, afterRecipients) {
				t.Fatal("refused revision changed recipients/credentials/approved request", err)
			}
			var retiredAfter, revisedAfter int
			if err := q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*)::integer FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND kind='ceremony_retired'),(SELECT count(*)::integer FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.revised')", original.ID, q.f.org).Scan(&retiredAfter, &revisedAfter); err != nil || retiredAfter != retiredBefore || revisedAfter != revisedBefore {
				t.Fatal("refused revision committed retirement/evidence", err)
			} //nolint:rawsql -- actual rollback counts, no source/cache repair
			if ownedRevisionMissingEventsV1(t, q, original) != 1 {
				t.Fatal("refused revision repaired or changed the actual missing comment measurement")
			}
			ownedRevisionConsumedV1(t, q)
			t.Logf("actual %s comment deficit: POST201, one unmeasured comment event, real changes/approval then revision503/retry1; complete paused document/recipients/approved request preserved, no retirement/revised event, actual drain joined", commentSide)
		}
		t.Fatalf("genuine %s comment revision must succeed: status=%d", commentSide, wRevise.Code)
	}
	if commentUnmeasured {
		t.Fatal("revision accepted an unmeasured actual comment event")
	}
	draft, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: q.f.org})
	if err != nil || draft.Status != "draft" {
		t.Fatal("actual ceremony did not reopen draft", err)
	}
	var historyRows int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND kind='ceremony_retired'", original.ID, q.f.org).Scan(&historyRows); err != nil || historyRows != 1 {
		t.Fatal("actual retired ceremony snapshot count incorrect", err)
	} //nolint:rawsql -- entire fresh target snapshot set
	var gotSource, gotFields, gotRecipients, gotNotice, gotEvents string
	err = q.f.pool.QueryRow(q.f.ctx, "SELECT source_json::text,fields_json::text,recipients_json::text,notice_context_json::text,ceremony_events_json::text FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND kind='ceremony_retired'", original.ID, q.f.org).Scan(&gotSource, &gotFields, &gotRecipients, &gotNotice, &gotEvents) //nolint:rawsql -- compare complete immutable retained collections without truncation
	if err != nil || gotSource != retiredSource || gotFields != retiredFields || gotRecipients != retiredRecipients || gotNotice != retiredNotice || gotEvents != retiredEvents {
		t.Fatal("retired ceremony lost or altered complete source/fields/recipients/notice/events", err)
	}
	if old, err := q.f.s.Sign.LookupByToken(q.f.ctx, auth.HashMagicToken(parties[0].Token)); err == nil {
		_ = old.CloseReadV1()
		t.Fatal("retired ceremony credential survived editable draft")
	}
	var draftSource, draftFields, draftRecipients, draftNotice, draftEvents string
	err = q.f.pool.QueryRow(q.f.ctx, "SELECT coalesce(d.html_current_source_json,d.html_source_json)::text,c.fields_json::text,c.recipients_json::text,c.notice_context_json::text,c.ceremony_events_json::text FROM documents d CROSS JOIN LATERAL hash_html_materialization_snapshot_context(d.id)c WHERE d.id=$1 AND d.org_id=$2", original.ID, q.f.org).Scan(&draftSource, &draftFields, &draftRecipients, &draftNotice, &draftEvents) //nolint:rawsql -- complete pre-append synthetic draft oracle
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := htmlsource.Commitment(draft)
	if err != nil {
		t.Fatal(err)
	}
	text := "Human-approved revised synthetic service scope"
	input := htmlDocumentRevisionInput{ExpectedUpdatedAt: draft.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: commitment, Values: htmlStringMap{"scope": text}, Summary: "Human-approved scope revision"}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationE2E(q.f.s, http.MethodPost, base+"/html/revisions", string(body), q.cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("genuine declared text revision=%d %s", w.Code, w.Body.String())
	}
	revised, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(revised.HtmlSourceJson, original.HtmlSourceJson) || revised.HtmlCurrentMaterializationSequence.Int32 != 2 || revised.HtmlCurrentMaterializationID == original.HtmlCurrentMaterializationID || revised.PdfStorageKey == original.PdfStorageKey || revised.HtmlReviewedBy.Valid || revised.HtmlReviewedAt.Valid || len(revised.HtmlReviewedPdfSha256) != 0 {
		t.Fatal("revision changed approved origin or reused old identity/review/PDF key")
	}
	values := map[string]string{}
	if json.Unmarshal(revised.VariablesJson, &values) != nil || values["scope"] != text {
		t.Fatal("actual revised variables lost the declared human text")
	}
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND kind='draft_superseded'", original.ID, q.f.org).Scan(&historyRows); err != nil || historyRows != 1 {
		t.Fatal("actual superseded draft snapshot count incorrect", err)
	} //nolint:rawsql -- exact complete fresh target history set
	err = q.f.pool.QueryRow(q.f.ctx, "SELECT source_json::text,fields_json::text,recipients_json::text,notice_context_json::text,ceremony_events_json::text FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND kind='draft_superseded'", original.ID, q.f.org).Scan(&gotSource, &gotFields, &gotRecipients, &gotNotice, &gotEvents) //nolint:rawsql -- complete immutable superseded context, no truncation
	if err != nil || gotSource != draftSource || gotFields != draftFields || gotRecipients != draftRecipients || gotNotice != draftNotice || gotEvents != draftEvents {
		t.Fatal("new materialization lost complete superseded draft context", err)
	}
	// This is expected to fail on the old revision path: real Project invalidates
	// M91/M93 and new managed fields lack91. Only an actual owned producer may
	// derive the replacement rows; this test never refreshes them.
	_ = ownedDetailsCachesReadV1(t, q, revised)
	newFields, err := q.f.q.ListFieldsByDocument(q.f.ctx, revised.ID)
	if err != nil || len(newFields) != 2 {
		t.Fatal("fresh intended-party fields absent", err)
	}
	for _, field := range newFields {
		if oldFieldIDs[field.ID.String()] {
			t.Fatal("revision reused retired field identity")
		}
		var measured int
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM field_signing_policy_sizes_v1 WHERE field_id=$1 AND document_id=$2 AND org_id=$3", field.ID, revised.ID, q.f.org).Scan(&measured); err != nil || measured != 1 {
			t.Fatal("genuine fresh field policy measurement absent", err)
		}
	} //nolint:rawsql -- exact fresh producer measurement presence, never refresh
	newCommitment, err := htmlsource.Commitment(revised)
	if err != nil || newCommitment == commitment {
		t.Fatal("actual new source commitment absent", err)
	}
	review, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: revised.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(revised.PdfSha256), ExpectedHTMLSourceCommitment: newCommitment})
	if w := submitSessionOperationE2E(q.f.s, http.MethodPost, base+"/html/review", string(review), q.cookie); w.Code != http.StatusOK {
		t.Fatalf("exact new PDF review=%d %s", w.Code, w.Body.String())
	}
	ownedRevisionConsumedV1(t, q) // All preceding route consumers have actually ended.
	actor := sendengine.Actor{UserID: &q.f.user.ID, OrgID: q.f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != q.f.user.ID || user.OrgID != q.f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	sent, err := q.f.s.Send.Send(q.f.ctx, actor, revised.ID)
	defer sent.CloseConsumerV1() // Failure cleanup; links remain live through the loop.
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatal("genuine revised configured-Resolver resend failed", err)
	}
	resent, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: revised.ID, OrgID: q.f.org})
	if err != nil || !resent.Article13NoticeEpochAt.Time.After(original.Article13NoticeEpochAt.Time) {
		t.Fatal("resend reused old Article13 ceremony epoch", err)
	}
	// The Send result is an actual live borrower while its links are consumed.
	// Baseline every native field/vector after preceding consumers have ended;
	// each signer must add ZERO surviving work to this exact caller baseline.
	q.reconcileV1(t)
	sendPending := q.runtime.SessionsV1().PendingV1()
	sendResources := q.snapshotV1(t)
	var finalToken string
	for i, link := range sent.Links {
		u, err := url.Parse(link.URL)
		if err != nil {
			t.Fatal(err)
		}
		token := strings.TrimPrefix(u.Path, "/sign/")
		if token == parties[0].Token || token == parties[1].Token {
			t.Fatal("resend reused a retired credential")
		}
		fresh := q.lookupV1(t, token)
		if err := fresh.ValidateReadMaterializationV1(); err != nil {
			t.Fatal(err)
		}
		notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), fresh)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := signerArticle13NoticeEvidence(fresh, notice)
		if err != nil {
			t.Fatal(err)
		}
		result, err := q.f.s.Sign.Sign(q.f.ctx, fresh, sign.SignInput{TypedName: link.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic revised contract qualifier"})
		if err != nil {
			t.Fatal("genuine revised two-party sign", err)
		}
		if i == 0 && result.Completed {
			t.Fatal("first revised signer completed both parties")
		}
		if i == 1 {
			if !result.Completed {
				t.Fatal("revised contract didnot complete")
			}
			u, err := url.Parse(result.FinalPDFURL)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) != 3 || parts[0] != "sign" || parts[2] != "final-pdf" {
				t.Fatal("actual completed capability route changed")
			}
			finalToken = parts[1]
		}
		if err := fresh.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		q.reconcileV1(t)
		if pending := q.runtime.SessionsV1().PendingV1(); pending != sendPending {
			t.Fatalf("signer work survived actual close while Send result remains live: got%+v want%+v", pending, sendPending)
		}
		if resources := q.snapshotV1(t); resources != sendResources {
			t.Fatalf("signer resources changed the actual live Send baseline: got%+v want%+v", resources, sendResources)
		}
	}
	sent.CloseConsumerV1() // Actual final use of every returned link has ended.
	ownedRevisionConsumedV1(t, q)
	completed, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: resent.ID, OrgID: q.f.org})
	if err != nil || completed == nil || completed.Status != "completed" || !sameSignerDocumentSource(resent, completed) {
		t.Fatal("revised completion lost agreed source or completed state", err)
	}
	type artifact struct {
		key, version pgtype.Text
		digest       []byte
	}
	artifacts := []artifact{
		{completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha},
		{completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256},
		{completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256},
		{completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256},
	}
	verified := make([][]byte, 0, len(artifacts))
	for _, artifact := range artifacts {
		if !artifact.key.Valid || strings.TrimSpace(artifact.key.String) == "" || !artifact.version.Valid || strings.TrimSpace(artifact.version.String) == "" || len(artifact.digest) != sha256.Size {
			t.Fatal("revised completion omitted one of four exact artifact/version/digest pins")
		}
		body, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, artifact.key.String, artifact.digest, artifact.version)
		if err != nil {
			t.Fatal("revised exact-version evidence retrieval", err)
		}
		sum := sha256.Sum256(body)
		if !bytes.Equal(sum[:], artifact.digest) {
			t.Fatal("revised artifact digest differs from committed bytes")
		}
		verified = append(verified, body)
	}
	if !bytes.HasPrefix(verified[0], []byte("%PDF-")) || !bytes.HasPrefix(verified[1], []byte("%PDF-")) || !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(verified[2]), string(verified[3])) {
		t.Fatal("revised final PDF/certificate/payload/detached-signature evidence failed")
	}
	// The historical certificate payload is canonical HTML, not JSON. Use the
	// actual first-party verifier, including its unique-attribute validation.
	claims, err := evidencepkg.ParseCertificateCommitments(verified[2])
	nameSHA := sha256.Sum256([]byte(completed.Name))
	if err != nil || claims.DocumentID != completed.ID.String() || claims.OrgID != completed.OrgID.String() || claims.DocumentNameSHA256 != hex.EncodeToString(nameSHA[:]) || claims.FinalPDFSHA256 != hex.EncodeToString(completed.FinalPdfSha) || claims.CompletionEffectiveAt != completed.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano) || claims.DocumentEventsCount < 1 {
		t.Fatal("revised signed certificate does not bind exact document/organisation/name/finalPDF/completion/event claims", err)
	}
	if finalToken == "" {
		t.Fatal("new completed artifact capability absent")
	}
	if w := q.requestV1(finalToken, "/final-pdf"); w.Code != http.StatusOK || !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) {
		t.Fatalf("actual revised final response=%d", w.Code)
	} else if digest := sha256.Sum256(w.Body.Bytes()); !bytes.Equal(digest[:], completed.FinalPdfSha) {
		t.Fatal("revised public final PDF response differs from exact committed final artifact")
	}
	ownedRevisionConsumedV1(t, q)
}

func ownedRevisionConsumedV1(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	q.assertObserversOnlyV1(t)
	if p := q.runtime.SessionsV1().PendingV1(); p.HTMLInputProducers != 0 {
		t.Fatal("actual executing input producer survived joined revision response", p)
	}
}

// Pure observation of fresh isolated fixture rows. No measurement creation,
// application permission, budget, or source repair is provided by this helper.
func ownedRevisionMissingEventsV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) int {
	t.Helper()
	var missing int
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT count(*)::integer FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND e.org_id=$2 AND m.measurement_server_version_num=current_setting('server_version_num')::integer WHERE e.document_id=$1 AND m.event_id IS NULL`, doc.ID, q.f.org).Scan(&missing) //nolint:rawsql -- exact all-event/current-version measurement completeness oracle
	if err != nil {
		t.Fatal(err)
	}
	return missing
}

func ownedRevisionCommentProbeV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, token, notice, side string) bool {
	t.Helper()
	if side != "signer" && side != "sender" {
		t.Fatal("unknown closed comment probe side")
	}
	if ownedRevisionMissingEventsV1(t, q, doc) != 0 {
		t.Fatal("fresh no-comment source was already unmeasured")
	}
	recipients, err := q.f.q.ListRecipientsByDocument(q.f.ctx, doc.ID)
	if err != nil || len(recipients) != 2 {
		t.Fatal("actual intended recipients absent", err)
	}
	var intended *generated.Recipient
	for _, rec := range recipients {
		if bytes.Equal(rec.MagicTokenHash, auth.HashMagicToken(token)) {
			if intended != nil {
				t.Fatal("actual token maps to multiple recipients")
			}
			intended = rec
		}
	}
	if intended == nil {
		t.Fatal("selected actual comment token has no recipient")
	}
	actor, err := q.f.q.GetUser(q.f.ctx, q.f.user.ID)
	if err != nil || actor.OrgID != q.f.org {
		t.Fatal("actual comment actor unavailable", err)
	}
	author := intended.Name
	if side == "sender" {
		author = actor.Name
		if author == "" {
			author = actor.Email
		}
	}
	// Count exactly the built-in comment notification, before later changes.
	mailBefore := map[string]int{}
	for _, email := range []string{q.f.user.Email, recipients[0].Email, recipients[1].Email} {
		var n int
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE to_email=$1 AND subject=$2", email, "New comment on "+doc.Name).Scan(&n); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- synchronous transactional outbox witness only
		mailBefore[email] = n
	}
	const body = "Synthetic agreed discussion before a genuine contract revision"
	encoded, err := json.Marshal(createCommentInput{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	var response *httptest.ResponseRecorder
	if side == "signer" {
		r := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/sign/"+token+"/comments", bytes.NewReader(encoded)).WithContext(q.f.ctx)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", q.f.s.PublicURL)
		r.Header.Set(signerNoticeDigestHeader, notice)
		response = httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(response, r)
	} else {
		response = submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/comments", string(encoded), q.cookie)
	}
	var result commentResponse
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Body != body || result.AuthorSide != side || result.AuthorName != author {
		t.Fatal("actual comment was not created through its public handler", response.Code)
	}
	comments, err := q.f.q.ListComments(q.f.ctx, doc.ID)
	if err != nil || len(comments) != 1 || comments[0].ID.String() != result.ID || comments[0].Body != body || comments[0].AuthorSide != side || comments[0].AuthorName != author {
		t.Fatal("actual committed comment row differs", err)
	}
	comment := comments[0]
	if (side == "signer" && (!comment.RecipientID.Valid || comment.RecipientID.Bytes != intended.ID || comment.UserID.Valid)) || (side == "sender" && (!comment.UserID.Valid || comment.UserID.Bytes != q.f.user.ID || comment.RecipientID.Valid)) {
		t.Fatal("actual comment author scope differs")
	}
	var events, measured int
	var payload []byte
	var recipientID, actorID pgtype.UUID
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT count(*)::integer,count(m.event_id)::integer FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.measurement_server_version_num=current_setting('server_version_num')::integer WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.comment_posted'`, doc.ID, q.f.org).Scan(&events, &measured); err != nil || events != 1 || measured < 0 || measured > 1 {
		t.Fatal("actual comment event/measurement cardinality differs", err)
	} //nolint:rawsql -- fresh current-version measurement observation only
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT payload_json,recipient_id,actor_user_id FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.comment_posted'", doc.ID, q.f.org).Scan(&payload, &recipientID, &actorID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- one actual bounded fresh event evidence oracle
	var evidence map[string]json.RawMessage
	var gotSide string
	if json.Unmarshal(payload, &evidence) != nil || json.Unmarshal(evidence["side"], &gotSide) != nil || gotSide != side {
		t.Fatal("actual comment side evidence differs")
	}
	if side == "signer" {
		var boundNotice string
		if json.Unmarshal(evidence[article13.AuditNoticeDigestKey], &boundNotice) != nil || boundNotice != notice {
			t.Fatal("actual comment audit notice differs from acknowledged digest")
		}
		if !recipientID.Valid || recipientID.Bytes != comment.RecipientID.Bytes || actorID.Valid || article13.ValidateAuditPayload(payload, q.f.org, doc.ID, comment.RecipientID.Bytes) != nil {
			t.Fatal("actual public comment lost complete notice/recipient evidence")
		}
	} else if !actorID.Valid || actorID.Bytes != q.f.user.ID || recipientID.Valid || len(evidence) != 5 {
		t.Fatal("actual staff comment changed actor/fixed evidence audit policy")
	}
	// New native writes bind the actual persisted text/identity. Historical
	// side-only events remain unchanged and explicitly unbound in matcher tests.
	actualEvents, evidenceErr := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, Limit: 1000})
	if evidenceErr != nil {
		t.Fatal(evidenceErr)
	}
	boundComment := false
	for _, actualEvent := range actualEvents {
		if actualEvent.Kind == "document.comment_posted" {
			matched, err := sign.CommentAuditEvidenceMatchesV1(actualEvent, comment)
			if err != nil || !matched || boundComment {
				t.Fatal("new actual comment evidence differs", err)
			}
			boundComment = true
		}
	}
	if !boundComment {
		t.Fatal("new actual comment evidence missing")
	}
	for email, before := range mailBefore {
		expected := 0
		if (side == "signer" && email == q.f.user.Email) || (side == "sender" && email != q.f.user.Email) {
			expected = 1
		}
		var after int
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE to_email=$1 AND subject=$2", email, "New comment on "+doc.Name).Scan(&after); err != nil || after != before+expected {
			t.Fatal("actual comment notification recipients/count differ", err)
		} //nolint:rawsql -- transactional outbox only, no SMTP claim
	}
	missing := ownedRevisionMissingEventsV1(t, q, doc)
	if missing != 1-measured {
		t.Fatal("unrelated event deficit confounds actual comment reproduction")
	}
	ownedRevisionConsumedV1(t, q)
	if measured != 1 || missing != 0 {
		t.Fatal("fresh native comment audit lacks intrinsic measurement", measured, missing)
	}
	t.Logf("actual %s comment POST201: one committed scoped row, complete original side/notice evidence and intended transactional notifications; measured=%d missing=%d", side, measured, missing)
	return missing == 1
}
