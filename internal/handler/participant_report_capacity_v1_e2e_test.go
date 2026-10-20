//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/render"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Both modes retain a real first legal response, then admit 70 individually
// valid staff comments through the public native endpoint. The new response
// capacity gate must refuse the final response before any legal DB effects
// commit. This does not claim that partly signed growth/headroom is closed:
// these comments are still admitted by the current separate comment owner.
// The original source/normal Send/real notice and current link remain required.
func TestParticipantReportCapacityRefusesOversizeResponseBeforeCommitV1E2E(t *testing.T) {
	for _, mode := range []string{"signature", "acknowledgement"} {
		t.Run(mode, func(t *testing.T) {
			var q *ownedPublicReadFixtureV1
			var doc *generated.Document
			var parties []signerBrowserPartyE2E
			if mode == "signature" {
				q = newOwnedPublicReadFixtureV1(t)
				doc, parties = q.createSentV1(t)
			} else {
				q, doc, parties = participantCapacityAcknowledgement253(t)
			}
			if len(parties) != 2 {
				t.Fatal("capacity regression requires two genuinely sent parties")
			}
			defer q.assertObserversOnlyV1(t)
			first, err := participantCapacityRespond253(t, q, parties[0], mode)
			if err != nil || first == nil || first.Completed {
				t.Fatal("first genuine legal response did not leave the ceremony active", err)
			}
			body := strings.Repeat("{\"k\":\"v\"}\n", 1000)
			if utf8.RuneCountInString(body) != 10000 || len(body) > 40*1024 {
				t.Fatal("comment fixture exceeds the original individual limits")
			}
			raw, err := json.Marshal(createCommentInput{Body: body})
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < 70; index++ {
				response := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/comments", string(raw), q.cookie)
				var comment commentResponse
				if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &comment) != nil || comment.Body != body || comment.AuthorSide != "sender" {
					t.Fatalf("actual staff comment %d was not admitted: status=%d", index+1, response.Code)
				}
				if index == 0 {
					participantCapacityActualSource253(t, q, doc.ID, body, 1, false)
				}
			}
			participantCapacityActualSource253(t, q, doc.ID, body, 70, true)
			before := participantCapacityLegalState253(t, q, doc.ID)
			result, err := participantCapacityRespond253(t, q, parties[1], mode)
			if !errors.Is(err, sign.ErrParticipantReportCapacityV1) || result != nil {
				t.Fatalf("oversized %s response was not refused by the typed precommit capacity gate: result_present=%v error=%v", mode, result != nil, err)
			}
			if participantCapacityLegalState253(t, q, doc.ID) != before {
				t.Fatal("capacity refusal committed a legal response, history, audit, receipt, notification or finalization change")
			}
			// HTTP reads prove the original credential is still usable. A second
			// response is still over capacity; it must return the fixed operator
			// copy rather than accept or disclose provider/database diagnostics.
			bootstrap := q.requestV1(parties[1].Token, "")
			var page signerContextResponse
			if bootstrap.Code != http.StatusOK || json.Unmarshal(bootstrap.Body.Bytes(), &page) != nil || page.Recipient.ID != parties[1].RecipientID || page.Privacy.NoticeDigest == "" {
				t.Fatal("capacity refusal invalidated the original current authenticated link", bootstrap.Code)
			}
			endpoint, requestBody := "/accept", []byte("{}")
			if mode == "signature" {
				endpoint = "/sign"
				requestBody, err = json.Marshal(signerSignInput{TypedName: parties[1].Name, Font: "Caveat"})
				if err != nil {
					t.Fatal(err)
				}
			}
			request := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/sign/"+parties[1].Token+endpoint, bytes.NewReader(requestBody)).WithContext(q.f.ctx)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", q.f.s.PublicURL)
			request.Header.Set(signerNoticeDigestHeader, page.Privacy.NoticeDigest)
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, request)
			var rejected struct {
				Error string `json:"error"`
			}
			const expectedCopy = "this negotiation's evidence report has reached Hash's size limit; contact the sender before continuing"
			if response.Code != http.StatusConflict || json.Unmarshal(response.Body.Bytes(), &rejected) != nil || rejected.Error != expectedCopy {
				t.Fatal("public capacity refusal did not return the fixed409 copy", response.Code)
			}
			if participantCapacityLegalState253(t, q, doc.ID) != before {
				t.Fatal("repeated public capacity refusal changed original legal DB effects")
			}
			// Real native signature archive PUT/preparation may have occurred.
			// Neither physical provider effects nor unrelated preparation tables
			// are asserted absent by this legal-commit/credential regression.
		})
	}
}

func participantCapacityRespond253(t *testing.T, q *ownedPublicReadFixtureV1, party signerBrowserPartyE2E, mode string) (*sign.Result, error) {
	t.Helper()
	rc := q.lookupV1(t, party.Token)
	defer func() {
		if err := rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
	}()
	notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "acknowledgement" {
		return q.f.s.Sign.Accept(q.f.ctx, rc, sign.ParticipantResponseEvidence{Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic native report capacity regression"})
	}
	return q.f.s.Sign.Sign(q.f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic native report capacity regression"})
}

// This is only a lower-bound size observation from actual committed forensic
// events and comments, not a native report, replacement cutoff or capability.
// The full final certificate must also contain all other retained report rows.
// The one-comment prefix must format successfully; the original 70-comment
// lower bound must hit the exact capped V2 HTML formatter, not an old uncapped
// HTMLV2 length. If V2 ever fits that history, this source oracle must fail and
// the actual public-source boundary must be re-established, never relabelled.
func participantCapacityActualSource253(t *testing.T, q *ownedPublicReadFixtureV1, document uuid.UUID, body string, wantComments int, wantCapacity bool) {
	t.Helper()
	var cutoff time.Time
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT max(created_at) FROM events WHERE document_id=$1 AND org_id=$2", document, q.f.org).Scan(&cutoff); err != nil || cutoff.IsZero() {
		t.Fatal("actual committed report event cutoff unavailable", err)
	}
	rows, err := q.f.q.ListComments(q.f.ctx, document)
	if err != nil || len(rows) != wantComments {
		t.Fatal("exact actual admitted comment prefix unavailable", len(rows), err)
	}
	events, err := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: document, Valid: true}, Limit: 10001})
	if err != nil || len(events) >= 10001 {
		t.Fatal("actual untruncated ordinary event set unavailable", err)
	}
	report := render.ParticipantReportV1{Schema: render.ParticipantReportSchemaV1, DocumentID: document.String(), Cutoff: cutoff.UTC().Format(time.RFC3339Nano)}
	report.Events, err = render.ParticipantReportEventsV1(events, cutoff)
	if err != nil {
		t.Fatal("actual report event commitments invalid", err)
	}
	for _, row := range rows {
		projected, err := render.ParticipantReportCommentV1FromRow(row, events)
		if err != nil || projected.Body != body || projected.Evidence != "body-and-actor-associated" || projected.Side != "sender" {
			t.Fatal("admitted comment lost its original forensic body/actor association", err)
		}
		report.Comments = append(report.Comments, projected)
	}
	// V1 is only the retained section input to the new exact public V2
	// projection. No V1 output or allow-both schema can satisfy this probe.
	documents, err := q.f.q.ListParticipantReportHistoryScopeV2(q.f.ctx, generated.ListParticipantReportHistoryScopeV2Params{OrgID: q.f.org, DocumentID: document})
	if err != nil || len(documents) == 0 {
		t.Fatal("actual capacity history family unavailable")
	}
	v2, err := render.NewParticipantReportV2(render.ParticipantNarrativeScopeDraft402{Org: q.f.org, Root: document, Documents: documents}, events, report)
	if err != nil {
		t.Fatal("actual original capacity source cannot project exact V2")
	}
	canonical, _, err := v2.CanonicalV2()
	if err != nil || len(canonical) >= render.MaxCertificatePayloadBytesV1 {
		t.Fatal("actual V2 canonical lower bound is not below the unchanged payload ceiling", len(canonical))
	}
	markup, _, htmlErr := v2.HTMLV3()
	if wantCapacity {
		if !errors.Is(htmlErr, render.ErrCertificatePayloadCapacityV1) || markup != "" {
			t.Fatal("actual 70-comment V2 HTML lower bound does not cross the unchanged payload ceiling")
		}
	} else if htmlErr != nil || len(markup) == 0 || len(markup) >= render.MaxCertificatePayloadBytesV1 {
		t.Fatal("actual early comment prefix does not have a successful bounded V2 presentation")
	}

	var measured int
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT count(*)::integer FROM events e
 JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id
 WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.comment_posted'
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND m.payload_wire_bytes=octet_length(e.payload_json::text)`, document, q.f.org).Scan(&measured); err != nil || measured != wantComments {
		t.Fatal("actual admitted staff comments lack their original fresh measurements", measured, err)
	} //nolint:rawsql -- observation only; no measurement repair/backfill
	t.Logf("actual admitted comments=%d V2_canonical_lower_bound_bytes=%d bounded_HTMLV3_bytes=%d HTMLV3_capacity_refused=%v certificate_payload_limit=%d", wantComments, len(canonical), len(markup), errors.Is(htmlErr, render.ErrCertificatePayloadCapacityV1), render.MaxCertificatePayloadBytesV1)
}

// Equality fingerprints only the legal transaction's durable rows. Original
// pre-mutation PDF target/admission preparation is intentionally outside this
// oracle; a capacity refusal is not a zero-IO/whole-estate rollback claim.
func participantCapacityLegalState253(t *testing.T, q *ownedPublicReadFixtureV1, document uuid.UUID) string {
	t.Helper()
	var state string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_array(
 md5(to_jsonb(d)::text),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb)::text) FROM recipients r WHERE r.document_id=d.id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]'::jsonb)::text) FROM signatures s WHERE s.document_id=d.id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb)::text) FROM events e WHERE e.document_id=d.id AND e.org_id=d.org_id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.event_id),'[]'::jsonb)::text) FROM html_snapshot_event_payload_sizes_v1 m WHERE m.document_id=d.id AND m.org_id=d.org_id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.id),'[]'::jsonb)::text) FROM document_comments c WHERE c.document_id=d.id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.recipient_id),'[]'::jsonb)::text) FROM document_package_responses_v1 r WHERE r.document_id=d.id AND r.org_id=d.org_id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.id),'[]'::jsonb)::text) FROM email_deliveries m WHERE m.to_email=(SELECT u.email FROM users u WHERE u.id=d.sender_id) OR m.to_email IN(SELECT r.email FROM recipients r WHERE r.document_id=d.id)),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(i)),'[]'::jsonb)::text) FROM document_finalization_intents i WHERE i.document_id=d.id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(p)),'[]'::jsonb)::text) FROM document_ordinary_finalization_preparations_v1 p WHERE p.document_id=d.id AND p.org_id=d.org_id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.kind),'[]'::jsonb)::text) FROM document_ordinary_finalization_outputs_v1 o WHERE o.document_id=d.id AND o.org_id=d.org_id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(p)),'[]'::jsonb)::text) FROM document_participant_reports_v1 p WHERE p.document_id=d.id AND p.org_id=d.org_id),
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.recipient_id),'[]'::jsonb)::text) FROM document_participant_report_deliveries_v1 r WHERE r.document_id=d.id AND r.org_id=d.org_id)
 )::text FROM documents d WHERE d.id=$1 AND d.org_id=$2`, document, q.f.org).Scan(&state)
	if err != nil || state == "" {
		t.Fatal("actual scoped legal-state fingerprint unavailable", err)
	} //nolint:rawsql -- bounded known70-row synthetic equality witness, never authority
	return state
}

func participantCapacityAcknowledgement253(t *testing.T, tracers ...pgx.QueryTracer) (*ownedPublicReadFixtureV1, *generated.Document, []signerBrowserPartyE2E) {
	t.Helper()
	q := newOwnedPublicReadFixtureProfileV1(t, false, false, tracers...)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Both parties acknowledge this exact imported PDF.")))
	var imported struct {
		Document documentResponse `json:"document"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &imported) != nil || imported.Document.ID == uuid.Nil {
		t.Fatal("genuine ordinary acknowledgement intake failed", response.Code)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: imported.Document.ID, OrgID: f.org})
	if err != nil || doc.SourceKind != "pdf" || !doc.PdfStorageVersionID.Valid || len(doc.PdfSha256) != 32 {
		t.Fatal("genuine acknowledgement original pins unavailable", err)
	}
	raw, err := json.Marshal(map[string]any{"expected_updated_at": doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "requires_signature": false})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/documents/" + doc.ID.String()
	patched := submitSessionOperationE2E(f.s, http.MethodPatch, base, string(raw), q.cookie)
	if patched.Code != http.StatusOK {
		t.Fatal("public ordinary acknowledgement mode configuration failed", patched.Code)
	}
	for _, role := range []string{"buyer", "seller"} {
		raw, err := json.Marshal(map[string]any{"email": role + "@capacity.example.test", "name": "Capacity " + role, "role": role, "order_index": 0, "locale": "en"})
		if err != nil {
			t.Fatal(err)
		}
		created := submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", string(raw), q.cookie)
		if created.Code != http.StatusCreated {
			t.Fatal("public acknowledgement participant creation failed", created.Code)
		}
	}
	actor := sendengine.Actor{OrgID: f.org, UserID: &f.user.ID, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	sent, err := f.s.Send.Send(f.ctx, actor, doc.ID)
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatal("normal native ordinary acknowledgement Send failed", err)
	}
	parties := make([]signerBrowserPartyE2E, 0, 2)
	for _, link := range sent.Links {
		u, err := url.Parse(link.URL)
		if err != nil || !strings.HasPrefix(u.Path, "/sign/") {
			t.Fatal("actual acknowledgement invite URL invalid", err)
		}
		parties = append(parties, signerBrowserPartyE2E{Token: strings.Clone(strings.TrimPrefix(u.Path, "/sign/")), RecipientID: link.RecipientID, Name: strings.Clone(link.Name), Role: strings.Clone(link.Role)})
	}
	doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || doc.RequiresSignature || doc.Status != "sent" || doc.SigningAdmissionPolicy != "historical" {
		t.Fatal("actual ordinary acknowledgement Send state differs", err)
	}
	return q, doc, parties
}
