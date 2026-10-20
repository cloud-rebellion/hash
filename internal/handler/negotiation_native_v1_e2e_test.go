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
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/actiontoken"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type nativeNegotiation262 struct {
	q                   *ownedPublicReadFixtureV1
	document            *generated.Document
	token, noticeDigest string
	change              *generated.ChangeRequest
	recipient           uuid.UUID
}

// Genuine supported block/manual-PDF birth, party/field authoring, public
// unresolved definition and normal native Send. The original128/64 profile and
// synthetic bounded renderer/storage/mail boundaries remain explicit.
func nativeNegotiationStart262(t *testing.T, pdf, auto bool) *nativeNegotiation262 {
	t.Helper()
	q, d := nativeBindingDocument259(t, pdf)
	q.f.s.ActionSecret = "synthetic-native-negotiation262-action-key"
	q.f.s.Sign.ActionSecret = q.f.s.ActionSecret
	if auto {
		r := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/settings/change-approval-mode", `{"mode":"auto_apply"}`, q.cookie)
		if r.Code != http.StatusOK {
			t.Fatal("actual owner approval-mode setting failed", r.Code)
		}
	}
	if r := nativeBindingPublic259(q, q.f.ctx, d.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, q.cookie); r.Code != http.StatusOK {
		t.Fatal("actual negotiation unresolved definition failed", r.Code)
	}
	n := &nativeNegotiation262{q: q, document: d}
	n.token = n.sendV1(t)
	var err error
	n.document, err = q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: d.ID, OrgID: q.f.org})
	if err != nil || n.document.Status != "sent" || len(n.document.HtmlSourceJson) != 0 {
		t.Fatal("actual ordinary negotiation ceremony absent", err)
	}
	bootstrap := q.requestV1(n.token, "")
	var page signerContextResponse
	if bootstrap.Code != http.StatusOK || json.Unmarshal(bootstrap.Body.Bytes(), &page) != nil || page.DocumentID != d.ID || page.Privacy.NoticeDigest == "" {
		t.Fatal("actual ordinary notice bootstrap absent", bootstrap.Code)
	}
	n.noticeDigest = page.Privacy.NoticeDigest
	nativeBindingMeasurement259(t, q.f, d.ID)
	q.assertObserversOnlyV1(t)
	return n
}

func (n *nativeNegotiation262) sendV1(t *testing.T) string {
	t.Helper()
	r := submitSessionOperationE2E(n.q.f.s, http.MethodPost, "/api/v1/documents/"+n.document.ID.String()+"/send", `{"lawful_basis":"contract"}`, n.q.cookie)
	var sent sendDocumentResponse
	if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &sent) != nil || sent.Status != "sent" || len(sent.Links) != 1 {
		t.Fatal("actual negotiation Send failed", r.Code)
	}
	n.recipient = sent.Links[0].RecipientID
	u, err := url.Parse(sent.Links[0].URL)
	if err != nil || !strings.HasPrefix(u.Path, "/sign/") {
		t.Fatal("actual normal invitation missing", err)
	}
	return strings.TrimPrefix(u.Path, "/sign/")
}

func (n *nativeNegotiation262) requestV1() *httptest.ResponseRecorder {
	body, err := json.Marshal(signerRequestChangesInput{Message: "Please adjust the agreed terms", BlockID: "body", Quote: "Agreed terms", Context: "Native negotiation fixture", Proposed: "Revised agreed terms"})
	if err != nil {
		panic(err) // fixed string-only input
	}
	r := httptest.NewRequest(http.MethodPost, n.q.f.s.PublicURL+"/sign/"+n.token+"/request-changes", bytes.NewReader(body)).WithContext(n.q.f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", n.q.f.s.PublicURL)
	r.Header.Set(signerNoticeDigestHeader, n.noticeDigest)
	w := httptest.NewRecorder()
	n.q.f.s.Routes().ServeHTTP(w, r)
	return w
}

func (n *nativeNegotiation262) pauseV1(t *testing.T) {
	t.Helper()
	var before, after int
	if err := n.q.f.pool.QueryRow(n.q.f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE to_email=$1", n.q.f.user.Email).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if r := n.requestV1(); r.Code != http.StatusOK {
		t.Fatal("actual notice-bound ordinary request failed", r.Code)
	}
	if err := n.q.f.pool.QueryRow(n.q.f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE to_email=$1", n.q.f.user.Email).Scan(&after); err != nil || after != before+1 {
		t.Fatal("actual owner negotiation notification missing or duplicated", err)
	}
	rows, err := n.q.f.q.ListChangeRequests(n.q.f.ctx, n.document.ID)
	if err != nil || len(rows) != 1 || rows[0].Status != "open" || rows[0].Message != "Please adjust the agreed terms" {
		t.Fatal("actual open negotiation request absent", err)
	}
	n.change, err = n.q.f.q.GetChangeRequest(n.q.f.ctx, generated.GetChangeRequestParams{ID: rows[0].ID, OrgID: n.q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	nativeBindingMeasurement259(t, n.q.f, n.document.ID)
	n.q.assertObserversOnlyV1(t)
}

func (n *nativeNegotiation262) resolveV1(t *testing.T, approve, action bool) *httptest.ResponseRecorder {
	t.Helper()
	choice := "deny"
	if approve {
		choice = "approve"
	}
	if !action {
		return submitSessionOperationE2E(n.q.f.s, http.MethodPost, "/api/v1/documents/"+n.document.ID.String()+"/change-requests/"+n.change.ID.String()+"/"+choice, "", n.q.cookie)
	}
	// Consume the actual native notification's signed action capability; this
	// fixture does not mint a replacement link or substitute a staff identity.
	var body string
	if err := n.q.f.pool.QueryRow(n.q.f.ctx, "SELECT html_body FROM email_deliveries WHERE to_email=$1 ORDER BY created_at DESC,id DESC LIMIT 1", n.q.f.user.Email).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var token string
	for _, match := range regexp.MustCompile(`/a/cr\?t=([A-Za-z0-9_.-]+)`).FindAllStringSubmatch(html.UnescapeString(body), -1) {
		claims, err := actiontoken.Verify(n.q.f.s.ActionSecret, match[1], time.Now())
		if err == nil && claims.Kind == "cr" && claims.Action == choice && claims.OrgID == n.q.f.org.String() && claims.DocID == n.document.ID.String() && claims.TargetID == n.change.ID.String() {
			token = match[1]
		}
	}
	if token == "" {
		t.Fatal("actual owner notification omitted the exact signed action")
	}
	r := httptest.NewRequest(http.MethodPost, n.q.f.s.PublicURL+"/a/cr", strings.NewReader(url.Values{"t": {token}}.Encode())).WithContext(n.q.f.ctx)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", n.q.f.s.PublicURL)
	w := httptest.NewRecorder()
	n.q.f.s.Routes().ServeHTTP(w, r)
	return w
}

func nativeNegotiationVersions262(t *testing.T, n *nativeNegotiation262) map[uuid.UUID]string {
	t.Helper()
	rows, err := n.q.f.pool.Query(n.q.f.ctx, "SELECT id,encode(sha256(convert_to(to_jsonb(v)::text,'UTF8')),'hex') FROM document_versions v WHERE document_id=$1 AND org_id=$2", n.document.ID, n.q.f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := make(map[uuid.UUID]string)
	for rows.Next() {
		var id uuid.UUID
		var digest string
		if err := rows.Scan(&id, &digest); err != nil {
			t.Fatal(err)
		}
		out[id] = digest
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func nativeNegotiationEventWitness262(t *testing.T, n *nativeNegotiation262, approve, action bool) []render.ParticipantReportEventV1 {
	t.Helper()
	events, err := n.q.f.q.ListChainedEventsPageForOrg(n.q.f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: n.q.f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	counts := [3]int{}
	var out []render.ParticipantReportEventV1
	for _, event := range events {
		if !event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != n.document.ID || (event.Kind != audit.KindChangesRequested && event.Kind != audit.KindDocumentRevised) {
			continue
		}
		row, rowErr := audit.RecomputeEventRowHash(event)
		var fields map[string]any
		if rowErr != nil || !bytes.Equal(row, event.RowHash) || json.Unmarshal(event.PayloadHashed, &fields) != nil {
			t.Fatal("actual negotiation event lost original hashed preimage", rowErr)
		}
		actor, recipient := "", ""
		if event.ActorUserID.Valid {
			actor = uuid.UUID(event.ActorUserID.Bytes).String()
		}
		if event.RecipientID.Valid {
			recipient = uuid.UUID(event.RecipientID.Bytes).String()
		}
		switch {
		case event.Kind == audit.KindDocumentRevised:
			if len(fields) != 0 || actor != n.q.f.user.ID.String() || recipient != "" {
				t.Fatal("actual revision changed original payload or actor")
			}
			counts[2]++
		case fields["resolution"] != nil:
			resolution, wantActor := "denied", n.q.f.user.ID.String()
			if approve {
				resolution = "approved"
			}
			if action {
				wantActor = ""
			}
			if len(fields) != 2 || fields["change_request"] != n.change.ID.String() || fields["resolution"] != resolution || actor != wantActor || recipient != "" {
				t.Fatal("actual decision changed original payload or action/staff association")
			}
			counts[1]++
		default:
			if len(fields) != 9 || fields["message"] != "Please adjust the agreed terms" || fields["block_id"] != "body" || fields["quote"] != "Agreed terms" || fields["notice_digest"] != n.noticeDigest || actor != "" || recipient != n.recipient.String() {
				t.Fatal("actual request lost original notice, payload or recipient association")
			}
			if fields["change_request"] != n.change.ID.String() || n.change.ID == uuid.Nil ||
				fields["context"] != n.change.Context || n.change.Context != "Native negotiation fixture" ||
				fields["proposed"] != n.change.Proposed || n.change.Proposed != "Revised agreed terms" {
				t.Fatal("actual request omitted its native row identity or original context/proposed preimage")
			}
			counts[0]++
		}
		out = append(out, render.ParticipantReportEventV1{ID: event.ID.String(), DocumentID: n.document.ID.String(), Kind: event.Kind, At: event.CreatedAt.Time.UTC().Format(time.RFC3339Nano), ActorID: actor, RecipientID: recipient, RowSHA256: hex.EncodeToString(event.RowHash)})
	}
	if counts != [3]int{1, 1, 1} {
		t.Fatal("actual request/decision/revision event set changed", counts)
	}
	return out
}

func TestNativeOrdinaryNegotiationResendAndMandatoryReportV1E2E(t *testing.T) {
	for _, c := range []struct {
		name                               string
		pdf, auto, approve, action, sender bool
	}{
		{name: "blocks auto apply sender session", auto: true, approve: true, sender: true},
		{name: "blocks accept real email action", approve: true, action: true},
		{name: "manual PDF auto apply remains source no-op", pdf: true, auto: true, approve: true},
		{name: "manual PDF deny real email action then sender revision", pdf: true, action: true, sender: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := nativeNegotiationStart262(t, c.pdf, c.auto)
			if c.sender {
				owner := seedSessionOwnerE2E(t, n.q.f.ctx, n.q.f.q, n.q.f.org)
				r := submitSessionOperationE2E(n.q.f.s, http.MethodPatch, "/api/v1/members/"+n.q.f.user.ID.String()+"/role", `{"role":"sender"}`, dsrSessionCookieE2E(t, n.q.f.s, owner, 0, time.Hour))
				if r.Code != http.StatusOK {
					t.Fatal("actual sender fixture role transition failed", r.Code)
				}
			}
			versions := nativeNegotiationVersions262(t, n)
			// Some ordinary import paths have no saved version row. Preserve
			// every actual existing version without manufacturing one here.
			n.pauseV1(t)
			if r := n.resolveV1(t, c.approve, c.action); r.Code != http.StatusOK {
				t.Fatal("actual ordinary resolution failed", r.Code)
			}
			paused, err := n.q.f.q.GetDocument(n.q.f.ctx, generated.GetDocumentParams{ID: n.document.ID, OrgID: n.q.f.org})
			if err != nil || paused.Status != "changes_requested" {
				t.Fatal("resolution altered paused ceremony state", err)
			}
			if !c.pdf && c.auto && c.approve {
				if !bytes.Contains(paused.BlocksJson, []byte("Revised agreed terms")) || bytes.Equal(paused.BlocksJson, n.document.BlocksJson) {
					t.Fatal("actual native blocks auto-apply did not change the original quoted text")
				}
			} else if !bytes.Equal(paused.BlocksJson, n.document.BlocksJson) || paused.PdfStorageKey != n.document.PdfStorageKey || !bytes.Equal(paused.PdfSha256, n.document.PdfSha256) {
				t.Fatal("approval/denial unexpectedly changed original source")
			}
			nativeBindingMeasurement259(t, n.q.f, n.document.ID)
			n.q.assertObserversOnlyV1(t)
			r := submitSessionOperationE2E(n.q.f.s, http.MethodPost, "/api/v1/documents/"+n.document.ID.String()+"/revise", "", n.q.cookie)
			if r.Code != http.StatusOK {
				t.Fatal("actual ordinary Revise failed", r.Code)
			}
			draft, err := n.q.f.q.GetDocument(n.q.f.ctx, generated.GetDocumentParams{ID: n.document.ID, OrgID: n.q.f.org})
			if err != nil || draft.Status != "draft" || draft.SentAt.Valid {
				t.Fatal("actual ordinary ceremony did not reopen draft", err)
			}
			var fakeHTML int
			if err := n.q.f.pool.QueryRow(n.q.f.ctx, "SELECT count(*)::integer FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2", n.document.ID, n.q.f.org).Scan(&fakeHTML); err != nil || fakeHTML != 0 {
				t.Fatal("ordinary revision invented an HTML snapshot", err)
			}
			wantEvents := nativeNegotiationEventWitness262(t, n, c.approve, c.action)
			if old, err := n.q.f.s.Sign.LookupByToken(n.q.f.ctx, auth.HashMagicToken(n.token)); err == nil {
				_ = old.CloseReadV1()
				t.Fatal("retired ordinary credential survived editable draft")
			}
			fresh := n.sendV1(t)
			if fresh == n.token {
				t.Fatal("resend reused the original ceremony credential")
			}
			terminal, err := ordinaryPreparationSign249(t, n.q, fresh, "Native Binding Signer")
			if err != nil || terminal == nil || !terminal.Completed {
				t.Fatal("ordinary negotiation prevented actual signature/report completion", err)
			}
			completed, err := n.q.f.q.GetDocument(n.q.f.ctx, generated.GetDocumentParams{ID: n.document.ID, OrgID: n.q.f.org})
			if err != nil || completed.Status != "completed" {
				t.Fatal("actual negotiated completion missing", err)
			}
			payload, err := readDocumentArtifact(n.q.f.ctx, n.q.f.s.Storage, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := readDocumentArtifact(n.q.f.ctx, n.q.f.s.Storage, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := evidence.ParseCertificateCommitments(payload)
			if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || claims.ParticipantReportRows < 6 || !sign.Verify(n.q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
				t.Fatal("mandatory report omitted negotiated history or actual detached signature", err)
			}
			report := assertFreshParticipantReport406(t, n.q.f, completed, payload)
			for _, want := range wantEvents {
				matches := 0
				for _, actual := range report.Events {
					if actual.Event.ID == want.ID {
						if actual.Event != want {
							t.Fatal("signed report negotiation tuple differs from original hashed event")
						}
						if want.Kind == audit.KindChangesRequested && actual.Request == nil && actual.Decision == nil {
							t.Fatal("fresh negotiation request/decision lost original typed details")
						}
						matches++
					}
				}
				if matches != 1 {
					t.Fatal("signed report omitted or duplicated original negotiation event", matches)
				}
			}
			var reports, deliveries int
			var exact bool
			err = n.q.f.pool.QueryRow(n.q.f.ctx, "SELECT count(*)::integer,coalesce(bool_and(encode(report_sha256,'hex')=$3 AND final_pdf_sha256=$4 AND audit_cert_sha256=$5 AND audit_payload_sha256=$6 AND audit_signature_sha256=$7),false) FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2", completed.ID, n.q.f.org, claims.ParticipantReportSHA256, completed.FinalPdfSha, completed.AuditCertSha256, completed.AuditPayloadSha256, completed.AuditSignatureSha256).Scan(&reports, &exact)
			if err != nil || reports != 1 || !exact {
				t.Fatal("actual negotiated report lost original artifact association", err)
			}
			if err := n.q.f.pool.QueryRow(n.q.f.ctx, "SELECT count(*)::integer FROM document_participant_report_deliveries_v1 WHERE document_id=$1 AND org_id=$2", completed.ID, n.q.f.org).Scan(&deliveries); err != nil || deliveries != 2 {
				t.Fatal("actual sender/participant report delivery references missing", err)
			}
			w := httptest.NewRecorder()
			n.q.f.s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, terminal.AuditCertURL, nil).WithContext(n.q.f.ctx))
			if w.Code != http.StatusOK || !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) {
				t.Fatal("actual mandatory negotiated report download failed", w.Code)
			}
			after := nativeNegotiationVersions262(t, n)
			for id, digest := range versions {
				if after[id] != digest {
					t.Fatal("negotiation changed or removed original saved version")
				}
			}
			nativeBindingMeasurement259(t, n.q.f, n.document.ID)
			n.q.assertObserversOnlyV1(t)
		})
	}
}

func nativeNegotiationSnapshot262(t *testing.T, n *nativeNegotiation262) map[string][32]byte {
	t.Helper()
	out := nativeOrgSourceLegalDigests257d(t, n.q.f)
	for _, table := range []string{"change_requests", "html_document_materialization_snapshots"} {
		var raw string
		if err := n.q.f.pool.QueryRow(n.q.f.ctx, "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)), '[]'::jsonb)::text FROM "+table+" r WHERE document_id=$1", n.document.ID).Scan(&raw); err != nil {
			t.Fatal("read actual fixed rollback witness", table, err)
		}
		out[table] = sha256.Sum256([]byte(raw))
	}
	return out
}

func TestNativeOrdinaryNegotiationFreshMeasurementFailureRollsBackV1E2E(t *testing.T) {
	for _, stage := range []string{"request", "resolution with actual blocks apply", "revision"} {
		t.Run(stage, func(t *testing.T) {
			n := nativeNegotiationStart262(t, false, true)
			if stage != "request" {
				n.pauseV1(t)
			}
			if stage == "revision" {
				if r := n.resolveV1(t, true, false); r.Code != http.StatusOK {
					t.Fatal("actual pre-revision approval failed", r.Code)
				}
			}
			before := nativeNegotiationSnapshot262(t, n)
			effects := nativeOrgSourceEffectsSnapshot257d(n.q)
			name := "negotiation_measurement_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			if _, err := n.q.f.pool.Exec(n.q.f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.document_id='%s'::uuid THEN RAISE EXCEPTION 'fixture fresh negotiation measurement failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON html_snapshot_event_payload_sizes_v1 FOR EACH ROW EXECUTE FUNCTION %s()`, name, n.document.ID, name, name)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := n.q.f.pool.Exec(ctx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON html_snapshot_event_payload_sizes_v1; DROP FUNCTION IF EXISTS %s()", name, name)); err != nil {
					t.Error(err)
				}
			})
			var response *httptest.ResponseRecorder
			switch stage {
			case "request":
				response = n.requestV1()
			case "resolution with actual blocks apply":
				response = n.resolveV1(t, true, false)
			case "revision":
				response = submitSessionOperationE2E(n.q.f.s, http.MethodPost, "/api/v1/documents/"+n.document.ID.String()+"/revise", "", n.q.cookie)
			}
			// Actual M94 failure joins the existing native availability sentinel;
			// all three original transports already expose its503/Retry-After1.
			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
				t.Fatal("fresh-measurement failure lost existing availability wire", response.Code)
			}
			after := nativeNegotiationSnapshot262(t, n)
			for table, digest := range before {
				if after[table] != digest {
					t.Fatal("failed native negotiation changed legal/source/credential/request/measurement/outbox state", table)
				}
			}
			actual := nativeOrgSourceEffectsSnapshot257d(n.q)
			if actual.puts != effects.puts || actual.deletes != effects.deletes || actual.rendererCalls != effects.rendererCalls || len(actual.objects) != len(effects.objects) {
				t.Fatal("failed native negotiation changed external effects")
			}
			for key, digest := range effects.objects {
				if actual.objects[key] != digest {
					t.Fatal("failed negotiation changed stored object bytes")
				}
			}
			n.q.assertObserversOnlyV1(t)
		})
	}
}

// Independent negative query controls confer no native producer authority and
// write no successful measurement. The positive is the actual fixed auto-apply
// writer above, not a direct SQL cache insertion or on-demand backfill.
func TestNativeNegotiatedBlockMeasurementScopeRefusalsV1E2E(t *testing.T) {
	t.Run("paused blocks tuple", func(t *testing.T) {
		n := nativeNegotiationStart262(t, false, true)
		n.pauseV1(t)
		paused, err := n.q.f.q.GetDocument(n.q.f.ctx, generated.GetDocumentParams{ID: n.document.ID, OrgID: n.q.f.org})
		if err != nil {
			t.Fatal(err)
		}
		actual := generated.MeasureNegotiatedBlocksResponseV1Params{DocumentID: paused.ID, OrgID: paused.OrgID, ExpectedUpdatedAt: paused.UpdatedAt}
		for _, c := range []struct {
			name   string
			change func(*generated.MeasureNegotiatedBlocksResponseV1Params)
		}{
			{"foreign tenant", func(p *generated.MeasureNegotiatedBlocksResponseV1Params) { p.OrgID = uuid.New() }},
			{"unknown document", func(p *generated.MeasureNegotiatedBlocksResponseV1Params) { p.DocumentID = uuid.New() }},
			{"stale actual clock", func(p *generated.MeasureNegotiatedBlocksResponseV1Params) {
				p.ExpectedUpdatedAt.Time = p.ExpectedUpdatedAt.Time.Add(-time.Microsecond)
			}},
		} {
			t.Run(c.name, func(t *testing.T) {
				before := nativeNegotiationSnapshot262(t, n)
				bad := actual
				c.change(&bad)
				if _, err := n.q.f.q.MeasureNegotiatedBlocksResponseV1(n.q.f.ctx, bad); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("wrong negotiation source scope wrote a measurement", err)
				}
				after := nativeNegotiationSnapshot262(t, n)
				for table, digest := range before {
					if after[table] != digest {
						t.Fatal("refused scoped measurement changed actual state", table)
					}
				}
			})
		}
		n.q.assertObserversOnlyV1(t)
	})
	for _, source := range []string{"sent blocks", "paused PDF", "reopened draft"} {
		t.Run(source, func(t *testing.T) {
			fixture := nativeNegotiationStart262(t, source == "paused PDF", false)
			if source != "sent blocks" {
				fixture.pauseV1(t)
			}
			if source == "reopened draft" {
				r := submitSessionOperationE2E(fixture.q.f.s, http.MethodPost, "/api/v1/documents/"+fixture.document.ID.String()+"/revise", "", fixture.q.cookie)
				if r.Code != http.StatusOK {
					t.Fatal("actual draft precondition failed", r.Code)
				}
			}
			row, err := fixture.q.f.q.GetDocument(fixture.q.f.ctx, generated.GetDocumentParams{ID: fixture.document.ID, OrgID: fixture.q.f.org})
			if err != nil {
				t.Fatal(err)
			}
			before := nativeNegotiationSnapshot262(t, fixture)
			p := generated.MeasureNegotiatedBlocksResponseV1Params{DocumentID: row.ID, OrgID: row.OrgID, ExpectedUpdatedAt: row.UpdatedAt}
			if _, err := fixture.q.f.q.MeasureNegotiatedBlocksResponseV1(fixture.q.f.ctx, p); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("wrong actual format/status wrote a paused-block measurement", err)
			}
			after := nativeNegotiationSnapshot262(t, fixture)
			for table, digest := range before {
				if after[table] != digest {
					t.Fatal("refused actual format/status measurement changed state", table)
				}
			}
			fixture.q.assertObserversOnlyV1(t)
		})
	}
}
