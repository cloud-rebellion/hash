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
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func ordinaryExpiryDraftV1(t *testing.T, tracers ...pgx.QueryTracer) (*ownedPublicReadFixtureV1, *generated.Document, string) {
	t.Helper()
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, ChildAddressBytes: 2 << 30, PDFWorkers: 1, SQLSessions: 8, ProviderStreams: 2, RendererRequests: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, ChildAddressBytes: 2 << 30, PDFWorkers: 1, SQLSessions: 4, ProviderStreams: 1, RendererRequests: 1}, MaxGrants: 128, MaxOrganisationGrants: 96}
	q := newOwnedPublicReadFixtureAllocated257dV1(t, false, limits, tracers...)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: versions.New(f.q), Billing: f.s.Billing, Send: f.s.Send, PDFCreationSessions: q.runtime.SessionsV1()})
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, Name: "Synthetic expiry regression", KeyPrefix: key.Prefix, KeyHash: key.Hash, Scopes: []string{"read", "write:authoring", "write:workflow"}}); err != nil {
		t.Fatal(err)
	}
	source := json.RawMessage(`{"version":1,"blocks":[{"id":"heading","type":"heading","text":"Internal functionality test","attrs":{"level":1}},{"id":"purpose","type":"paragraph","text":"Synthetic two-party signature and artifact verification."},{"id":"no-effect","type":"paragraph","text":"No commercial effect or obligations."},{"id":"parties","type":"paragraph","text":"Both independent test participants must sign."},{"id":"acknowledgement","type":"paragraph","text":"Signing confirms only completion of this synthetic test."},{"id":"first-signature","type":"signature_field","attrs":{"recipient_role":"signer","label":"First required signature"}},{"id":"second-signature","type":"signature_field","attrs":{"recipient_role":"approver","label":"Second required signature"}}]}`)
	response := submitDocumentCreationE2E(f, f.ctx, "mcp", key.Plaintext, map[string]any{"name": "Synthetic ordinary expiry regression", "source_kind": "blocks", "purpose": "signing", "blocks_json": source, "variables_json": map[string]string{}})
	var envelope struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
	}
	if json.Unmarshal(response.Body.Bytes(), &envelope) != nil || envelope.Result.IsError || len(envelope.Result.Content) != 1 {
		t.Fatalf("real MCP creation failed: HTTP%d", response.Code)
	}
	var doc generated.Document
	if json.Unmarshal([]byte(envelope.Result.Content[0].Text), &doc) != nil || doc.ID == uuid.Nil {
		t.Fatal("actual newly created document missing")
	}
	// Source-equality witnesses use original DB JSONB bytes, not the JSON wire
	// representation (RawMessage compaction and null encoding differ).
	baseline, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || baseline == nil || baseline.ID != doc.ID || baseline.SourceKind != "blocks" || !baseline.RequiresSignature {
		t.Fatal("fresh pre-mutation native source baseline unavailable", err)
	}
	doc = *baseline
	for _, role := range []string{"signer", "approver"} {
		body, _ := json.Marshal(map[string]any{"name": "Synthetic " + role, "email": role + "@example.test", "role": role, "locale": "en", "order_index": 0})
		w := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/recipients", string(body), q.cookie)
		if w.Code != http.StatusCreated {
			t.Fatalf("actual recipient creation failed: HTTP%d", w.Code)
		}
	}
	return q, &doc, key.Plaintext
}

func ordinaryExpiryMCPV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, key, expiry string) {
	t.Helper()
	w := submitRecipientMCPE2E(q.f, "set_expiry", key, map[string]any{"document_id": doc.ID, "expires_at": expiry})
	var envelope struct {
		Error  json.RawMessage
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || (len(envelope.Error) != 0 && string(envelope.Error) != "null") || envelope.Result.IsError || len(envelope.Result.Content) != 1 || w.Code != http.StatusOK {
		t.Fatalf("real MCP expiry failed: HTTP%d", w.Code)
	}
	var returned generated.Document
	var expectedWire generated.Document
	wire, err := json.Marshal(doc)
	if err != nil || json.Unmarshal(wire, &expectedWire) != nil {
		t.Fatal("native source wire projection failed", err)
	}
	if json.Unmarshal([]byte(envelope.Result.Content[0].Text), &returned) != nil || returned.ID != doc.ID || returned.OrgID != q.f.org || !sameSignerDocumentSource(&expectedWire, &returned) {
		t.Fatal("MCP expiry returned a different document/source")
	}
	if expiry == "" {
		if returned.ExpiresAt.Valid {
			t.Fatal("MCP clear response retained an expiry")
		}
	} else {
		requested, err := time.Parse(time.RFC3339, expiry)
		if err != nil || !returned.ExpiresAt.Valid || !returned.ExpiresAt.Time.Equal(requested.Truncate(time.Microsecond)) {
			t.Fatal("MCP set response differs from the requested expiry")
		}
	}
}

// Reproduce the actual pre-fix producer, not deletion of an existing cache.
// Every row/hash is created with the frozen pre-measurement audit recipe in the
// same guarded expiry transaction. The current logger deliberately measures all
// document events, so using it would no longer reproduce the historical defect.
// No measurement row is deleted or native grant seeded.
func ordinaryLegacyExpiryV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, payload map[string]any) {
	t.Helper()
	f := q.f
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	guard, err := authoring.LockDraft(f.ctx, tx, authoring.Actor{OrgID: f.org, UserID: f.user.ID, Authorize: func(context.Context, pgx.Tx, *generated.User) error { return nil }}, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	expiry := guard.Document.ExpiresAt
	if value, present := payload["expires_at"]; present {
		text, ok := value.(string)
		parsed, err := time.Parse(time.RFC3339, text)
		if !ok || err != nil {
			t.Fatal("legacy producer requires its actual requested expiry")
		}
		expiry = pgtype.Timestamptz{Time: parsed, Valid: true}
	}
	if _, err = f.q.WithTx(tx).UpdateDraftDocumentDetailsV1(f.ctx, generated.UpdateDraftDocumentDetailsV1Params{ID: doc.ID, OrgID: f.org, Name: guard.Document.Name, ExpiresAt: expiry}); err != nil {
		t.Fatal(err)
	}
	ordinaryLegacyExpiryEventV1(t, f, tx, doc.ID, payload)
	if err = guard.Recheck(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}

// Freeze only the old producer's event insertion; later Send/Sign and forensic
// verification still execute the current implementation. Preserve its org lock,
// fail-closed head read, microsecond ordering and exact canonical chain preimage.
func ordinaryLegacyExpiryEventV1(t *testing.T, f lifecycleAuthorizationFixture, tx pgx.Tx, documentID uuid.UUID, payload map[string]any) {
	t.Helper()
	q := f.q.WithTx(tx)
	if err := q.AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	head, err := q.LatestEventChainHeadForOrg(f.ctx, f.org)
	var previous []byte
	if err == nil {
		previous = head.RowHash
		if head.CreatedAt.Valid && !createdAt.After(head.CreatedAt.Time) {
			createdAt = head.CreatedAt.Time.Add(time.Microsecond)
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("historical expiry chain head:", err)
	}
	rowHash := audit.ChainHashRecord(audit.HashInput{Prev: previous, OrgID: f.org, DocID: documentID,
		ActorID: f.user.ID, Kind: audit.KindDocumentUpdated, CreatedAt: createdAt, Payload: raw})
	_, err = q.InsertEvent(f.ctx, generated.InsertEventParams{OrgID: f.org,
		DocumentID: pgtype.UUID{Bytes: documentID, Valid: true}, ActorUserID: pgtype.UUID{Bytes: f.user.ID, Valid: true},
		Kind: audit.KindDocumentUpdated, PayloadJson: raw, PayloadHashed: raw, PrevHash: previous, RowHash: rowHash,
		CreatedAt: pgtype.Timestamptz{Time: createdAt, Valid: true}})
	if err != nil {
		t.Fatal("historical unmeasured expiry event:", err)
	}
}

func ordinaryExpirySendV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) []signerBrowserPartyE2E {
	t.Helper()
	f := q.f
	sent, err := f.s.Send.Send(f.ctx, sendengine.Actor{OrgID: f.org, UserID: &f.user.ID, Via: "mcp", Tool: "send_document", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}, doc.ID)
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatalf("actual Send failed: error_type=%T", err)
	}
	parties := make([]signerBrowserPartyE2E, 0, 2)
	for _, link := range sent.Links {
		u, err := url.Parse(link.URL)
		if err != nil || !strings.HasPrefix(u.Path, "/sign/") {
			t.Fatal("local synthetic invitation malformed")
		}
		parties = append(parties, signerBrowserPartyE2E{Token: strings.Clone(strings.TrimPrefix(u.Path, "/sign/")), RecipientID: link.RecipientID, Name: link.Name, Role: link.Role})
	}
	return parties
}

func ordinaryExpirySignV1(t *testing.T, q *ownedPublicReadFixtureV1, party signerBrowserPartyE2E) (*sign.Result, error) {
	t.Helper()
	rc := q.lookupV1(t, party.Token)
	notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the full real reader alive through response admission and finalization.
	result, err := q.f.s.Sign.Sign(q.f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic ordinary expiry regression"})
	if closeErr := rc.CloseReadV1(); closeErr != nil {
		t.Fatal(closeErr)
	}
	q.assertObserversOnlyV1(t)
	return result, err
}

func ordinaryExpiryHistoryV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) (string, int) {
	t.Helper()
	var fingerprint string
	var missing int
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT COALESCE(md5(jsonb_agg(to_jsonb(e) ORDER BY e.id)::text),''),count(*) FILTER(WHERE NOT EXISTS(SELECT 1 FROM html_snapshot_event_payload_sizes_v1 c WHERE c.event_id=e.id))::integer FROM events e WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.updated'`, doc.ID, q.f.org).Scan(&fingerprint, &missing) //nolint:rawsql -- bounded original expiry-row equality oracle only
	if err != nil || fingerprint == "" {
		t.Fatal("original synthetic expiry history absent", err)
	}
	return fingerprint, missing
}

func TestOrdinaryBlocksMCPExpiryAndLegacyMeasurementTwoSignE2E(t *testing.T) {
	for _, mode := range []string{"owned-expiry-and-clear", "retained-legacy-expiry"} {
		t.Run(mode, func(t *testing.T) {
			q, doc, key := ordinaryExpiryDraftV1(t)
			expiry := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
			if mode == "retained-legacy-expiry" {
				ordinaryLegacyExpiryV1(t, q, doc, map[string]any{"via": "mcp", "tool": "set_expiry", "expires_at": expiry})
			} else {
				ordinaryExpiryMCPV1(t, q, doc, key, expiry)
				ordinaryExpiryMCPV1(t, q, doc, key, "")
				cleared, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
				if err != nil || cleared.ExpiresAt.Valid {
					t.Fatal("explicit expiry clear failed", err)
				}
				if !sameSignerDocumentSource(doc, cleared) {
					t.Fatal("explicit expiry clear changed the original native source")
				}
				ordinaryExpiryMCPV1(t, q, doc, key, expiry)
				var total, measured int
				err = q.f.pool.QueryRow(q.f.ctx, `SELECT count(*)::integer,count(*) FILTER(WHERE EXISTS(SELECT 1 FROM html_snapshot_event_payload_sizes_v1 c WHERE c.event_id=e.id AND c.document_id=e.document_id AND c.org_id=e.org_id AND c.payload_wire_bytes=octet_length(e.payload_json::text) AND c.measurement_server_version_num=current_setting('server_version_num')::integer))::integer FROM events e WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.updated' AND convert_from(e.payload_hashed,'UTF8')::jsonb->>'tool'='set_expiry'`, doc.ID, q.f.org).Scan(&total, &measured) //nolint:rawsql -- exact three real MCP producer receipts, never cache seeding
				if err != nil || total != 3 || measured != 3 {
					t.Fatal("not all three set/clear/set operations produced measured audit events", total, measured, err)
				}
			}
			before, missing := ordinaryExpiryHistoryV1(t, q, doc)
			if (mode == "retained-legacy-expiry" && missing != 1) || (mode != "retained-legacy-expiry" && missing != 0) {
				t.Fatal("real expiry producer measurement mismatch", missing)
			}
			parties := ordinaryExpirySendV1(t, q, doc)
			for index, party := range parties {
				result, err := ordinaryExpirySignV1(t, q, party)
				if err != nil || result == nil || result.Completed != (index == 1) {
					t.Fatalf("actual Sign failed: index=%d type=%T stage=%s", index, err, sign.BlockSignatureFailureStageV1(err))
				}
			}
			current, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
			if err != nil || current.Status != "completed" {
				t.Fatalf("both required parties did not reach durable completion: status=%s error_type=%T", current.Status, err)
			}
			if !sameSignerDocumentSource(doc, current) {
				t.Fatal("all-party completion changed the original native source")
			}
			after, missing := ordinaryExpiryHistoryV1(t, q, doc)
			if after != before || missing != 0 {
				t.Fatal("expiry recovery altered original forensic event bytes or left a missing cache")
			}
			for _, artifact := range []struct {
				key, version pgtype.Text
				digest       []byte
			}{{current.FinalPdfKey, current.FinalPdfVersionID, current.FinalPdfSha}, {current.AuditCertKey, current.AuditCertVersionID, current.AuditCertSha256}} {
				b, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, artifact.key.String, artifact.digest, artifact.version)
				if err != nil || !bytes.HasPrefix(b, []byte("%PDF-")) {
					t.Fatal("real completed PDF/certificate artifact unavailable", err)
				}
			}
			payload, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, current.AuditPayloadKey.String, current.AuditPayloadSha256, current.AuditPayloadVersionID)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, current.AuditSignatureKey.String, current.AuditSignatureSha256, current.AuditSignatureVersionID)
			if err != nil || !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
				t.Fatal("completed certificate signature verification failed", err)
			}
			q.assertObserversOnlyV1(t)
		})
	}
}

func TestOrdinaryBlocksLegacyExpiryMeasurementRefusalRollsBackE2E(t *testing.T) {
	for _, mode := range []string{"partial-cache-rollback", "numeric-display-before-body"} {
		t.Run(mode, func(t *testing.T) { ordinaryExpiryRefusalV1(t, mode) })
	}
}

type ordinaryExpiryBodyTraceV1 struct {
	armed atomic.Bool
	reads atomic.Int64
}

func (p *ordinaryExpiryBodyTraceV1) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if p.armed.Load() && strings.Contains(q.SQL, "-- name: GetEventByID") {
		p.reads.Add(1)
	}
	return ctx
}
func (*ordinaryExpiryBodyTraceV1) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func ordinaryExpiryRefusalV1(t *testing.T, mode string) {
	trace := &ordinaryExpiryBodyTraceV1{}
	q, doc, _ := ordinaryExpiryDraftV1(t, trace)
	expiry := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
	ordinaryLegacyExpiryV1(t, q, doc, map[string]any{"via": "mcp", "tool": "set_expiry", "expires_at": expiry})
	wantMissing := 2
	if mode == "partial-cache-rollback" {
		ordinaryLegacyExpiryV1(t, q, doc, map[string]any{"via": "mcp", "tool": "attach_metadata", "key": "unrelated", "value": "must-not-recover"})
	} else {
		wantMissing = 1
		// Adversarial DISPLAY projection only: the original hashed preimage and
		// every original chain byte remain untouched. Tiny binary numeric expands
		// beyond the body wire bound if a formatter sees it before the header gate.
		if _, err := q.f.pool.Exec(q.f.ctx, `UPDATE events SET payload_json=jsonb_build_object('via','mcp','tool','set_expiry','expires_at',1e100000::numeric) WHERE document_id=$1 AND org_id=$2 AND kind='document.updated'`, doc.ID, q.f.org); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- isolated adversarial display-only fixture, never production/history repair
		var physical, wire int
		if err := q.f.pool.QueryRow(q.f.ctx, `SELECT pg_column_size(payload_json),octet_length(payload_json::text) FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.updated'`, doc.ID, q.f.org).Scan(&physical, &wire); err != nil || physical > 4096 || wire <= 32768 {
			t.Fatal("numeric display fixture does not demonstrate amplification", physical, wire, err)
		} //nolint:rawsql -- trusted fixed100KiB negative-fixture oracle, not native funding/authority
	}
	before, missing := ordinaryExpiryHistoryV1(t, q, doc)
	if missing != wantMissing {
		t.Fatal("legacy producer missing measurement count differs", missing)
	}
	parties := ordinaryExpirySendV1(t, q, doc)
	trace.armed.Store(true)
	result, err := ordinaryExpirySignV1(t, q, parties[0])
	trace.armed.Store(false)
	if result != nil || !errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) || sign.BlockSignatureFailureStageV1(err) != "report_admit" {
		t.Fatalf("unknown legacy event bypassed strict admission: type=%T stage=%s", err, sign.BlockSignatureFailureStageV1(err))
	}
	after, missing := ordinaryExpiryHistoryV1(t, q, doc)
	if after != before || missing != wantMissing {
		t.Fatal("refusal committed a partial cache repair or altered history")
	}
	if mode == "numeric-display-before-body" && trace.reads.Load() != 0 {
		t.Fatal("unsafe numeric display reached GetEventByID before scalar refusal", trace.reads.Load())
	}
	if mode == "partial-cache-rollback" && trace.reads.Load() != 1 {
		t.Fatal("partial recovery did not exercise exactly one valid candidate before refusal", trace.reads.Load())
	}
	var signed int
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM recipients WHERE document_id=$1 AND status='signed'", doc.ID).Scan(&signed); err != nil || signed != 0 {
		t.Fatal("refused signature committed recipient state", err)
	} //nolint:rawsql -- actual rollback oracle only
	q.assertObserversOnlyV1(t)
}
