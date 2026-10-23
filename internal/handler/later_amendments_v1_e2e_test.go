//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type laterAmendmentFixture483 struct {
	completed           completedPackageFixture248
	q                   *ownedPublicReadFixtureV1
	original, candidate *generated.Document
	create              amendments.CreateV1
	record              amendments.RecordV1
	before              string
}

func laterAmendmentOriginalSnapshot483(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) string {
	t.Helper()
	var out string
	e := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_array(to_jsonb(d),
 COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM recipients r WHERE r.document_id=d.id),'[]'::jsonb),
 COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM signatures s WHERE s.document_id=d.id),'[]'::jsonb),
 COALESCE((SELECT jsonb_agg(to_jsonb(p) ORDER BY p.completion_effective_at) FROM document_participant_reports_v1 p WHERE p.document_id=d.id),'[]'::jsonb),
 COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c.revision) FROM document_package_captures_v1 c WHERE c.document_id=d.id),'[]'::jsonb))::text
 FROM documents d WHERE d.id=$1 AND d.org_id=$2`, id, q.f.org).Scan(&out)
	if e != nil {
		t.Fatal(e)
	}
	return out
}

type laterAmendmentRetainedPeer483 struct{ base *completedPackagePeer248 }

func (p laterAmendmentRetainedPeer483) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")
	if r.Method == http.MethodGet && r.URL.Query().Has("retention") && key != p.base.mainKey {
		p.base.mu.Lock()
		until := p.base.until[key]
		p.base.mu.Unlock()
		if until.IsZero() {
			if r.URL.Query().Get("versionId") != "import-version-1" {
				http.Error(w, "wrong version", 400)
				return
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, "<Retention></Retention>")
			return
		}
	}
	p.base.ServeHTTP(w, r)
}
func laterAmendmentCandidate483(t *testing.T, q *ownedPublicReadFixtureV1, mode amendments.ModeV1) *generated.Document {
	t.Helper()
	// The original fixture's completed-output peer deliberately requires retained
	// PUTs. Reuse its SAME object map through the genuine transient-intake peer
	// only for this new independent upload; restore the retained reader afterward.
	endpoint := httptest.NewServer(q.storagePeer)
	defer endpoint.Close()
	prior := q.f.s.Storage
	intake, e := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(endpoint.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-amendment-intake", SecretKey: "synthetic-amendment-intake-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if e != nil {
		t.Fatal(e)
	}
	q.f.s.Storage = intake
	candidate := packageImported220(t, q, "Separate amendment483: exact later terms and process, original agreement referenced by owner review.")
	q.f.s.Storage = prior
	base := "/api/v1/documents/" + candidate.ID.String()
	if mode != amendments.SignatureV1 {
		raw, _ := json.Marshal(map[string]any{"expected_updated_at": candidate.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "requires_signature": false})
		w := submitSessionOperationE2E(q.f.s, http.MethodPatch, base, string(raw), q.cookie)
		if w.Code != 200 {
			t.Fatal("fresh acknowledgement representation", w.Code, w.Body.String())
		}
	}
	if mode != amendments.AgreedNoticeV1 {
		raw, _ := json.Marshal(map[string]any{"email": "amendment-party@example.test", "name": "Synthetic Amendment Party", "role": "signer", "locale": "en", "order_index": 0})
		w := submitSessionOperationE2E(q.f.s, http.MethodPost, base+"/recipients", string(raw), q.cookie)
		if w.Code != 201 {
			t.Fatal("fresh amendment party", w.Code, w.Body.String())
		}
		if mode == amendments.SignatureV1 {
			var recipient struct {
				ID uuid.UUID `json:"id"`
			}
			if json.Unmarshal(w.Body.Bytes(), &recipient) != nil || recipient.ID == uuid.Nil {
				t.Fatal("recipient identity")
			}
			field, _ := json.Marshal(map[string]any{"expected_pdf_sha256": hex.EncodeToString(candidate.PdfSha256), "recipient_id": recipient.ID.String(), "type": "signature", "page": 1, "x_pct": 10, "y_pct": 70, "w_pct": 40, "h_pct": 12, "required": true})
			w = submitSessionOperationE2E(q.f.s, http.MethodPost, base+"/fields", string(field), q.cookie)
			if w.Code != 201 {
				t.Fatal("fresh amendment signature layout", w.Code, w.Body.String())
			}
		}
	}
	return packageLatest223(t, q, candidate.ID)
}
func newLaterAmendmentFixture483(t *testing.T, mode amendments.ModeV1) laterAmendmentFixture483 {
	t.Helper()
	completed := newCompletedPackageFixture248(t, false)
	q := completed.active.q
	original := packageLatest223(t, q, completed.active.m.Capture.DocumentID)
	before := laterAmendmentOriginalSnapshot483(t, q, original.ID)
	candidate := laterAmendmentCandidate483(t, q, mode)
	retainedPeer := httptest.NewServer(laterAmendmentRetainedPeer483{base: completed.peer})
	t.Cleanup(retainedPeer.Close)
	client, e := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(retainedPeer.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-amendment-retained", SecretKey: "synthetic-amendment-retained-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if e != nil {
		t.Fatal(e)
	}
	q.f.s.Storage = client
	q.f.s.Sign.Storage = client
	q.f.s.Send.Storage = client
	in := amendments.CreateV1{RequestID: uuid.New(), ExpectedHeadRevision: "0", AmendmentDocumentID: candidate.ID, ExpectedDocumentUpdatedAt: candidate.UpdatedAt.Time, Mode: mode, CoverReviewed: true, Basis: amendments.BasisV1{Kind: "reviewed_legacy_clause", ClauseReference: "Synthetic existing agreement, clause12", ReviewedClause: "For this controlled test, the owner reviewed the agreement clause permitting signature, explicit acknowledgement, or email notice of later changes.", AllowedModes: []amendments.ModeV1{amendments.SignatureV1, amendments.AcknowledgementV1, amendments.AgreedNoticeV1}, AllowedChannels: []string{"email"}, EffectiveCondition: "Synthetic clause conditions only; no legal effectiveness inferred from enqueue or SMTP."}}
	body, _ := json.Marshal(in)
	w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+original.ID.String()+"/amendments", string(body), q.cookie)
	var out amendments.OutcomeV1
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.State != "committed" || out.Amendment == nil {
		t.Fatal("actual native amendment link", w.Code, w.Body.String())
	}
	if laterAmendmentOriginalSnapshot483(t, q, original.ID) != before {
		t.Fatal("link rewrote completed original/source/recipients/signatures/report/capture")
	}
	return laterAmendmentFixture483{completed: completed, q: q, original: original, candidate: candidate, create: in, record: *out.Amendment, before: before}
}
func issueLaterNotice483(t *testing.T, f laterAmendmentFixture483) (amendments.NoticeV1, amendments.IssueNoticeV1) {
	t.Helper()
	var e error
	f.q.f.s.NoticeAccess, e = f.q.runtime.NewLaterAmendmentNoticeAccessV1(f.q.f.s.Storage, f.q.f.s.Cookies, f.q.f.s.PublicURL)
	if e != nil {
		t.Fatal(e)
	}
	candidate := packageLatest223(t, f.q, f.candidate.ID)
	in := amendments.IssueNoticeV1{RequestID: uuid.New(), ExpectedHeadRevision: f.record.Revision, ExpectedDocumentUpdatedAt: candidate.UpdatedAt.Time, Subject: "Synthetic agreed DPA change notice", Text: "Please read the exact later document files at the private notice link. This email is not a signature or acknowledgement.", RecipientEmails: []string{"legal@example.test"}, Reviewed: true}
	raw, _ := json.Marshal(in)
	w := submitSessionOperationE2E(f.q.f.s, http.MethodPost, "/api/v1/documents/"+f.original.ID.String()+"/amendments/"+f.record.ID.String()+"/notice", string(raw), f.q.cookie)
	var out amendments.OutcomeV1
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Notice == nil || out.State != "committed" {
		t.Fatal("actual notice/outbox/capability transaction", w.Code, w.Body.String())
	}
	return *out.Notice, in
}
func TestLaterAmendmentNativeModesAndOriginalImmutabilityV1E2E(t *testing.T) {
	for _, mode := range []amendments.ModeV1{amendments.SignatureV1, amendments.AcknowledgementV1, amendments.AgreedNoticeV1} {
		t.Run(string(mode), func(t *testing.T) {
			f := newLaterAmendmentFixture483(t, mode)
			base := "/api/v1/documents/" + f.original.ID.String()
			w := submitSessionOperationE2E(f.q.f.s, http.MethodGet, base+"/amendments", "", f.q.cookie)
			var inventory amendments.InventoryV1
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &inventory) != nil || inventory.HeadID == nil || *inventory.HeadID != f.record.ID || inventory.HeadRevision != "1" || len(inventory.Amendments) != 1 || inventory.FrozenPolicies == nil {
				t.Fatal("native inventory", w.Code, w.Body.String())
			}
			w = submitSessionOperationE2E(f.q.f.s, http.MethodGet, "/api/v1/documents/"+f.candidate.ID.String()+"/amendment", "", f.q.cookie)
			var relation amendments.CandidateRelationV1
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &relation) != nil || relation.OriginalDocumentID != f.original.ID || relation.Amendment.Mode != mode {
				t.Fatal("direct candidate mode lookup", w.Code, w.Body.String())
			}
			replay, _ := json.Marshal(f.create)
			w = submitSessionOperationE2E(f.q.f.s, http.MethodPost, base+"/amendments", string(replay), f.q.cookie)
			var out amendments.OutcomeV1
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.State != "unchanged" || out.Amendment == nil || out.Amendment.ID != f.record.ID {
				t.Fatal("exact replay", w.Code, w.Body.String())
			}
			edit, _ := json.Marshal(map[string]any{"expected_updated_at": packageLatest223(t, f.q, f.candidate.ID).UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "name": "Attempted linked source replacement"})
			w = submitSessionOperationE2E(f.q.f.s, http.MethodPatch, "/api/v1/documents/"+f.candidate.ID.String(), string(edit), f.q.cookie)
			if w.Code >= 200 && w.Code < 300 {
				t.Fatal("linked source remained editable")
			}
			if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
				t.Fatal("later operation mutated completed originals")
			}
			f.q.assertObserversOnlyV1(t)
		})
	}
}
func TestLaterAmendmentStaleHeadAndRevokedOwnerHaveNoEffectsV1E2E(t *testing.T) {
	f := newLaterAmendmentFixture483(t, amendments.SignatureV1)
	base := "/api/v1/documents/" + f.original.ID.String() + "/amendments"
	second := laterAmendmentCandidate483(t, f.q, amendments.SignatureV1)
	in := f.create
	in.RequestID = uuid.New()
	in.AmendmentDocumentID = second.ID
	in.ExpectedDocumentUpdatedAt = second.UpdatedAt.Time
	raw, _ := json.Marshal(in)
	w := submitSessionOperationE2E(f.q.f.s, http.MethodPost, base, string(raw), f.q.cookie)
	if w.Code != 409 {
		t.Fatal("stale current head", w.Code, w.Body.String())
	}
	changed := f.create
	changed.Basis.ReviewedClause += " Changed."
	raw, _ = json.Marshal(changed)
	w = submitSessionOperationE2E(f.q.f.s, http.MethodPost, base, string(raw), f.q.cookie)
	if w.Code != 409 {
		t.Fatal("changed replay accepted", w.Code, w.Body.String())
	}
	if _, e := f.q.f.q.UpdateUserRole(f.q.f.ctx, generated.UpdateUserRoleParams{ID: f.q.f.user.ID, OrgID: f.q.f.org, Role: "viewer"}); e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(f.create)
	w = submitSessionOperationE2E(f.q.f.s, http.MethodPost, base, string(raw), f.q.cookie)
	if w.Code != 403 {
		t.Fatal("revoked owner replay authorized", w.Code, w.Body.String())
	}
	var count int
	if e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT count(*) FROM document_amendments_v1 WHERE original_document_id=$1`, f.original.ID).Scan(&count); e != nil || count != 1 {
		t.Fatal("refusal appended relation", count, e)
	}
	if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
		t.Fatal("refusal mutated original")
	}
}
func TestLaterAmendmentNoticeRealOutboxReplayAndNoResponseV1E2E(t *testing.T) {
	f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
	notice, in := issueLaterNotice483(t, f)
	if len(notice.Deliveries) != 1 || notice.Deliveries[0].RecipientEmail != in.RecipientEmails[0] || notice.Deliveries[0].State != "queued" || notice.VerifiedReceipts == nil || len(notice.VerifiedReceipts) != 0 {
		t.Fatal("notice invented delivery/response", notice)
	}
	raw, _ := json.Marshal(in)
	path := "/api/v1/documents/" + f.original.ID.String() + "/amendments/" + f.record.ID.String() + "/notice"
	w := submitSessionOperationE2E(f.q.f.s, http.MethodPost, path, string(raw), f.q.cookie)
	var replay amendments.OutcomeV1
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &replay) != nil || replay.State != "unchanged" || replay.Notice == nil || replay.Notice.ID != notice.ID {
		t.Fatal("notice replay", w.Code, w.Body.String())
	}
	in.Text += " Different reviewed terms."
	raw, _ = json.Marshal(in)
	w = submitSessionOperationE2E(f.q.f.s, http.MethodPost, path, string(raw), f.q.cookie)
	if w.Code != 409 {
		t.Fatal("changed notice replay", w.Code, w.Body.String())
	}
	w = submitSessionOperationE2E(f.q.f.s, http.MethodPost, "/api/v1/documents/"+f.candidate.ID.String()+"/send", `{"lawful_basis":"contract"}`, f.q.cookie)
	if w.Code >= 200 && w.Code < 300 {
		t.Fatal("notice document entered signing ceremony")
	}
	var deliveries, access, responses, reports int
	var status string
	e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT (SELECT count(*) FROM document_amendment_notice_deliveries_v1 WHERE notice_id=$1),(SELECT count(*) FROM document_amendment_notice_access_v1 WHERE notice_id=$1),(SELECT count(*) FROM signatures WHERE document_id=$2),(SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$2),(SELECT status FROM documents WHERE id=$2)`, notice.ID, f.candidate.ID).Scan(&deliveries, &access, &responses, &reports, &status)
	if e != nil || deliveries != 1 || access != 1 || responses != 0 || reports != 0 || status != "draft" {
		t.Fatal("notice synthesized signing/report state", deliveries, access, responses, reports, status, e)
	}
	if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
		t.Fatal("notice rewrote completed original")
	}
	f.q.assertObserversOnlyV1(t)
}
func TestLaterAmendmentIndependentSignatureAndAcceptCompleteOwnReportV1E2E(t *testing.T) {
	for _, mode := range []amendments.ModeV1{amendments.SignatureV1, amendments.AcknowledgementV1} {
		t.Run(string(mode), func(t *testing.T) {
			f := newLaterAmendmentFixture483(t, mode)
			actor := packageActor220(t, f.q)
			sent, e := f.q.f.s.Send.Send(f.q.f.ctx, send.Actor{OrgID: actor.OrgID, UserID: &actor.UserID, Via: "rest", LawfulBasis: "contract", Authorize: actor.Authorize}, f.candidate.ID)
			defer sent.CloseConsumerV1()
			if e != nil || sent.Status != "sent" || len(sent.Links) != 1 {
				t.Fatal("ordinary independent amendment Send", e)
			}
			link := sent.Links[0]
			u, e := url.Parse(link.URL)
			if e != nil {
				t.Fatal(e)
			}
			token := strings.TrimPrefix(u.Path, "/sign/")
			if token == f.completed.token || token == f.completed.active.token {
				t.Fatal("original credential reused for later proposal")
			}
			sent.CloseConsumerV1()
			rc := f.q.lookupV1(t, token)
			defer rc.CloseReadV1()
			if rc.Document.ID != f.candidate.ID || rc.Document.RequiresSignature != (mode == amendments.SignatureV1) {
				t.Fatal("ordinary response authority changed mode/document")
			}
			notice, e := f.q.f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
			if e != nil {
				t.Fatal(e)
			}
			evidence, e := signerArticle13NoticeEvidence(rc, notice)
			if e != nil {
				t.Fatal(e)
			}
			var response *sign.Result
			if mode == amendments.SignatureV1 {
				response, e = f.q.f.s.Sign.Sign(f.q.f.ctx, rc, sign.SignInput{TypedName: link.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic separate later amendment signature"})
			} else {
				response, e = f.q.f.s.Sign.Accept(f.q.f.ctx, rc, sign.ParticipantResponseEvidence{Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic separate later amendment explicit Accept"})
			}
			if e != nil || response == nil || !response.Completed || response.Status != "completed" {
				t.Fatal("ordinary fresh amendment completion", response, e)
			}
			if e = rc.CloseReadV1(); e != nil {
				t.Fatal(e)
			}
			var reports, deliveries, signatures, accepted, originEvents int
			e = f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT (SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$1),
 (SELECT count(*) FROM document_participant_report_deliveries_v1 WHERE document_id=$1),
 (SELECT count(*) FROM signatures WHERE document_id=$1),(SELECT count(*) FROM recipients WHERE document_id=$1 AND status='accepted'),
 (SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.amendment_linked' AND payload_json->>'original_document_id'=$2)
 `, f.candidate.ID, f.original.ID.String()).Scan(&reports, &deliveries, &signatures, &accepted, &originEvents)
			if e != nil || reports != 1 || deliveries != 2 || originEvents != 1 || (mode == amendments.SignatureV1 && (signatures != 1 || accepted != 0)) || (mode == amendments.AcknowledgementV1 && (signatures != 0 || accepted != 1)) {
				t.Fatal("new ceremony/report/outbox/origin scope", reports, deliveries, signatures, accepted, originEvents, e)
			}
			if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
				t.Fatal("new ceremony rewrote original evidence")
			}
			f.q.assertObserversOnlyV1(t)
		})
	}
}
func TestLaterAmendmentNoticeOutboxFailureRollsBackAuditAndCapabilitiesV1E2E(t *testing.T) {
	f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
	var e error
	f.q.f.s.NoticeAccess, e = f.q.runtime.NewLaterAmendmentNoticeAccessV1(f.q.f.s.Storage, f.q.f.s.Cookies, f.q.f.s.PublicURL)
	if e != nil {
		t.Fatal(e)
	}
	name := "amendment_notice_refuse_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ident := pgx.Identifier{name}.Sanitize()
	sequenceName := "notice_refuse_entered_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	sequence := pgx.Identifier{sequenceName}.Sanitize()
	// PostgreSQL sequences are deliberately nontransactional. Exactly one
	// observed nextval proves this REAL injected trigger was reached before
	// rollback; an earlier capacity/authorization refusal cannot pass this test.
	sql := `CREATE SEQUENCE ` + sequence + ` MINVALUE 1 MAXVALUE 2 START 1 NO CYCLE;
 CREATE FUNCTION ` + ident + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='` + f.q.f.org.String() + `'::uuid THEN PERFORM nextval('` + sequenceName + `'::regclass);RAISE EXCEPTION 'synthetic exact notice-ref failure';END IF;RETURN NEW;END $$`
	if _, e = f.q.f.pool.Exec(f.q.f.ctx, sql); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, e := f.q.f.pool.Exec(cleanup, `DROP TRIGGER IF EXISTS `+ident+` ON document_amendment_notice_deliveries_v1`); e != nil {
			t.Error(e)
		}
		if _, e := f.q.f.pool.Exec(cleanup, `DROP FUNCTION IF EXISTS `+ident+`() `); e != nil {
			t.Error(e)
		}
		if _, e := f.q.f.pool.Exec(cleanup, `DROP SEQUENCE IF EXISTS `+sequence); e != nil {
			t.Error(e)
		}
	})
	if _, e = f.q.f.pool.Exec(f.q.f.ctx, `CREATE TRIGGER `+ident+` BEFORE INSERT ON document_amendment_notice_deliveries_v1 FOR EACH ROW EXECUTE FUNCTION `+ident+`() `); e != nil {
		t.Fatal(e)
	}
	input := amendments.IssueNoticeV1{RequestID: uuid.New(), ExpectedHeadRevision: f.record.Revision, ExpectedDocumentUpdatedAt: packageLatest223(t, f.q, f.candidate.ID).UpdatedAt.Time, Subject: "Synthetic atomic refusal " + uuid.NewString(), Text: "Reviewed files at the exact private notice link; refusal must enqueue nothing.", RecipientEmails: []string{"legal@example.test"}, Reviewed: true}
	var queueBefore int
	if e = f.q.f.pool.QueryRow(f.q.f.ctx, "SELECT count(*) FROM email_deliveries").Scan(&queueBefore); e != nil {
		t.Fatal(e)
	} //nolint:rawsql -- preserve only the genuinely committed prior creation alert
	raw, _ := json.Marshal(input)
	w := submitSessionOperationE2E(f.q.f.s, http.MethodPost, "/api/v1/documents/"+f.original.ID.String()+"/amendments/"+f.record.ID.String()+"/notice", string(raw), f.q.cookie)
	if w.Code >= 200 && w.Code < 300 {
		t.Fatal("forced transactional refusal became success", w.Code, w.Body.String())
	}
	var called bool
	var last int64
	if e = f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT last_value,is_called FROM `+sequence).Scan(&last, &called); e != nil || !called || last != 1 {
		t.Fatal("actual targeted outbox trigger was not reached exactly once; an earlier refusal is not rollback proof", last, called, e)
	} //nolint:rawsql -- independent nontransactional failure-entry witness
	var queueAfter int
	if e = f.q.f.pool.QueryRow(f.q.f.ctx, "SELECT count(*) FROM email_deliveries").Scan(&queueAfter); e != nil || queueAfter != queueBefore {
		t.Fatal("failed notice leaked operational owner mail or legal notice mail", queueBefore, queueAfter, e)
	} //nolint:rawsql -- all actual outbox effects, including separate owner notification
	var notices, mails, events, capabilities int
	e = f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT
 (SELECT count(*) FROM document_amendment_notices_v1 WHERE amendment_id=$1),
 (SELECT count(*) FROM email_deliveries WHERE subject=$2),
 (SELECT count(*) FROM events WHERE document_id=$3 AND kind='document.amendment_notice_queued' AND payload_json->>'amendment_id'=$4),
 (SELECT count(*) FROM document_amendment_notice_access_v1 c JOIN document_amendment_notices_v1 n ON n.id=c.notice_id WHERE n.amendment_id=$1)`, f.record.ID, input.Subject, f.original.ID, f.record.ID.String()).Scan(&notices, &mails, &events, &capabilities)
	if e != nil || notices != 0 || mails != 0 || events != 0 || capabilities != 0 {
		t.Fatal("partial notice transaction survived", notices, mails, events, capabilities, e)
	}
	if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
		t.Fatal("failed notice changed original evidence")
	}
	f.q.assertObserversOnlyV1(t)
}
