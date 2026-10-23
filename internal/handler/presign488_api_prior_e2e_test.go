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
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Same real TLS client, context, request encoding and response-read/close bound
// as the primary caller. Only the original verified API bearer is installed;
// no session cookie/private auth receipt is substituted or printed.
func (h presign488HTTP) callAPIPriorV1(ctx context.Context, method, path, bearer string, value any) (presign488Response, error) {
	var out presign488Response
	var raw []byte
	var err error
	if value != nil {
		raw, err = json.Marshal(value)
		if err != nil {
			return out, errors.New("encode controlled API request")
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, h.base+path, bytes.NewReader(raw))
	if err != nil {
		return out, errors.New("construct controlled API request")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", h.base)
	r.Header.Set("User-Agent", "Hash controlled pre-sign488 API-prior journey")
	r.Header.Set("Authorization", "Bearer "+bearer)
	response, err := h.client.Do(r)
	if err != nil {
		return out, fmt.Errorf("controlled API HTTP transport: %T", err)
	}
	out.code, out.header = response.StatusCode, response.Header.Clone()
	out.body, err = io.ReadAll(io.LimitReader(response.Body, 64*1024*1024+1))
	closed := response.Body.Close()
	if err != nil || closed != nil || len(out.body) > 64*1024*1024 {
		return out, errors.New("controlled API response not completely read and closed")
	}
	return out, nil
}
func presign488APIPriorCallV1(t *testing.T, h presign488HTTP, ctx context.Context, method, path, bearer string, in any, want int) presign488Response {
	t.Helper()
	out, err := h.callAPIPriorV1(ctx, method, path, bearer, in)
	if err != nil || out.code != want {
		if h.queryTrace != nil {
			total, successful, hashes := h.queryTrace.successfulSnapshotV1()
			t.Logf("bounded successful native query frontier: query_total=%d successful_total=%d last16_sql_sha256=%v", total, successful, hashes)
		}
		sum := sha256.Sum256(out.body)
		t.Fatalf("controlled API-prior phase status=%d want=%d bytes=%d body_sha256=%x error_type=%T", out.code, want, len(out.body), sum, err)
	}
	return out
}

// Extend the genuine session supersession SELECT-only inventory with the exact
// API source seals. API-key last-used bookkeeping is not an execution effect.
func presign488APIPriorInventoryV1(t *testing.T, q *ownedPublicReadFixtureV1) [3][32]byte {
	t.Helper()
	base := presign488SupersessionInventory(t, q)
	var raw []byte
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY executor_credential_id,request_id),'[]'::jsonb) FROM presign_source_requests_v1 r WHERE org_id=$1`, q.f.org).Scan(&raw); err != nil {
		t.Fatal("actual API source seal inventory unavailable")
	}
	return [3][32]byte{base[0], base[1], sha256.Sum256(raw)}
}

// The dedicated top creates its own complete genuine primary contract before
// arriving here. It never runs the session-link creator on this parent.
func presign488APIPriorSupersessionAfterCompletion(t *testing.T, q *ownedPublicReadFixtureV1, h presign488HTTP, template *generated.Template, parent *generated.Document, execution presign.Execution, assets presignexecute.AssetSetV1, finalBodies [][]byte, retained func(string, string, time.Time) bool) {
	t.Helper()
	f := q.f
	x := execution.Snapshot()
	if parent == nil || parent.Status != "completed" || template == nil || template.ID != x.Document.Template.ID || x.Document.ID != parent.ID || len(finalBodies) != 4 || retained == nil || !parent.FinalizationRetainUntil.Valid {
		t.Fatal("genuine independent completed API parent prerequisite missing")
	}
	parentBefore := presign488SupersessionParentState(t, q, parent.ID)
	parentEffects := presign488Counts(t, q, parent.ID)
	minted, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal("controlled original API key mint failed")
	}
	credential, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, KeyPrefix: minted.Prefix, KeyHash: minted.Hash, Name: "Controlled second-parent API prior488", Scopes: []string{"write:authoring", "write:workflow"}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true}})
	if err != nil || credential == nil || credential.ID == uuid.Nil {
		t.Fatal("actual finite scoped API credential unavailable")
	}
	policy, grant := preSign488ApprovedAPIAuthorityV1(t, preSign488PreparationFixtureV1{q: q, h: h, template: template}, parent, credential.ID)
	before := presign488APIPriorInventoryV1(t, q)
	response := presign488Call(t, h, f.ctx, http.MethodGet, "/api/v1/presign/supersessions/documents/"+parent.ID.String()+"/context", nil, true, "", http.StatusOK)
	if len(response.body) > 1<<20 || response.header.Get("Cache-Control") != "no-store" {
		t.Fatal("actual independent parent context bound differs")
	}
	ready := presign488Decode[presign488SupersessionReady](t, response.body)
	p := ready.Prior
	tp := p.Template
	xp := x.Document.Template
	if ready.SchemaVersion != 1 || ready.State != "ready" || ready.OrgID != f.org || ready.UserID != f.user.ID || !ready.CreationAvailable || p.ValidateV1() != nil || p.ExecutionID != x.ID || p.ExecutionSHA256 != execution.Commitment() || p.DocumentID != parent.ID || p.SourceCommitment != x.Document.Materialization.SourceCommitment || p.MaterializationID != x.Document.Materialization.ID || p.MaterializationRevision != x.Document.Materialization.Revision || tp.ID != xp.ID || tp.Version != xp.Version || tp.ContentSHA256 != xp.ContentSHA256 || tp.ApprovedBy != xp.ApprovedBy || !tp.ApprovedAt.Equal(xp.ApprovedAt) || ready.Template.ID != template.ID || ready.Template.Version != template.Version || ready.Template.ContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) {
		t.Fatal("actual API prior context differs from genuine independent parent")
	}
	if presign488APIPriorInventoryV1(t, q) != before {
		t.Fatal("API parent context performed source or execution effects")
	}
	var birthsBefore, sealsBefore, linksBefore, auditsBefore int
	const lineage = `SELECT (SELECT count(*) FROM html_document_creation_requests WHERE org_id=$1),(SELECT count(*) FROM presign_source_requests_v1 WHERE org_id=$1),(SELECT count(*) FROM presign_supersessions_v1 WHERE org_id=$1),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='presign.execution.superseded')`
	if err = f.pool.QueryRow(f.ctx, lineage, f.org).Scan(&birthsBefore, &sealsBefore, &linksBefore, &auditsBefore); err != nil {
		t.Fatal("actual API lineage baseline unavailable")
	}
	// Independent expected commitment of the genuine minted row. This does not
	// create the private middleware admission; only the actual bearer can do so.
	bindingRaw, err := json.Marshal(struct {
		Org, User, Credential uuid.UUID
		Hash                  []byte
	}{f.org, f.user.ID, credential.ID, minted.Hash})
	if err != nil {
		t.Fatal("controlled expected API identity encoding unavailable")
	}
	digestHash := sha256.New()
	_, _ = digestHash.Write([]byte("hash:presign-original-api-key:v1\x00"))
	_, _ = digestHash.Write(bindingRaw)
	binding := hex.EncodeToString(digestHash.Sum(nil))
	in := preSignAPISourceInputV1{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, Policy: policy, Grant: grant, DocumentName: "Fresh approved API linked contract", Prior: &p}
	expectedDigest, err := preSignSourceInputDigestV1(in, f.org, f.user.ID, credential.ID, binding)
	if err != nil {
		t.Fatal("actual API prior command cannot be bound")
	}
	const route = "/api/automation/v1/presign/documents"
	createdResponse := presign488APIPriorCallV1(t, h, f.ctx, http.MethodPost, route, minted.Plaintext, in, http.StatusCreated)
	created := presign488Decode[pdfadmission.PreSignAPISourceViewV1](t, createdResponse.body)
	if createdResponse.header.Get("Cache-Control") != "no-store" || created.SchemaVersion != 1 || created.State != "committed" || created.RequestID != in.RequestID || created.InputSHA256 != expectedDigest || created.Source == nil || created.Source.DocumentID == uuid.Nil || created.Source.DocumentID == parent.ID || created.Source.MaterializationRevision != 1 || created.Source.SourceCommitment == p.SourceCommitment {
		t.Fatal("actual API prior source result differs")
	}
	source := created.Source
	fresh, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: source.DocumentID, OrgID: f.org})
	if err != nil || fresh == nil || fresh.Status != "draft" || fresh.SenderID != f.user.ID || fresh.Name != in.DocumentName || !fresh.TemplateID.Valid || uuid.UUID(fresh.TemplateID.Bytes) != template.ID || !fresh.RequiresSignature || fresh.RoutingMode != "parallel" || fresh.SourceKind != "pdf" || fresh.SigningAdmissionPolicy != "historical" || fresh.IsEnvelope || fresh.ParentEnvelopeID.Valid || fresh.HtmlReviewedAt.Valid || fresh.HtmlReviewedBy.Valid || !fresh.UpdatedAt.Time.Equal(source.DocumentUpdatedAt) || uuid.UUID(fresh.HtmlCurrentMaterializationID.Bytes) != source.MaterializationID || int64(fresh.HtmlCurrentMaterializationSequence.Int32) != source.MaterializationRevision || fresh.HtmlEffectiveSourceCommitment.String != source.SourceCommitment || hex.EncodeToString(fresh.PdfSha256) != source.PDFSHA256 || htmlsource.Validate(fresh, false) != nil {
		t.Fatal("actual API successor is not the exact fresh unreviewed draft")
	}
	var signatures, executions, uses, recipients, pending, fields int
	err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM signatures WHERE document_id=$1),(SELECT count(*) FROM presign_executions WHERE document_id=$1),(SELECT count(*) FROM presign_execution_uses u JOIN presign_executions e ON e.org_id=u.org_id AND e.id=u.execution_id WHERE e.document_id=$1),(SELECT count(*) FROM recipients WHERE document_id=$1),(SELECT count(*) FROM recipients WHERE document_id=$1 AND status='pending' AND sent_at IS NULL AND first_viewed_at IS NULL AND signed_at IS NULL),(SELECT count(*) FROM document_fields WHERE document_id=$1)`, fresh.ID).Scan(&signatures, &executions, &uses, &recipients, &pending, &fields)
	if err != nil || signatures != 0 || executions != 0 || uses != 0 || recipients != 2 || pending != 2 || fields != 2 || presign488Counts(t, q, parent.ID) != parentEffects {
		t.Fatal("actual API successor executed, signed, invited or changed original counts")
	}
	var births, seals, links, audits int
	if err = f.pool.QueryRow(f.ctx, lineage, f.org).Scan(&births, &seals, &links, &audits); err != nil || births != birthsBefore+1 || seals != sealsBefore+1 || links != linksBefore+1 || audits != auditsBefore+1 {
		t.Fatal("actual API birth must add exactly one M79, API seal, link and supersession event")
	}
	var actual struct {
		Input, Credential, PolicySHA, GrantSHA, TemplateSHA, PDF, EventHash, Payload, Hashed                                           []byte
		User, Policy, Grant, Template, Document, Materialization, PriorExecution, PriorDocument, LinkedDocument, Actor, Request, Event uuid.UUID
		PolicyRevision, GrantRevision, TemplateVersion, MaterializationRevision                                                        int64
		Source, Kind                                                                                                                   string
		Pages                                                                                                                          int32
	}
	err = f.pool.QueryRow(f.ctx, `SELECT r.input_sha256,r.original_credential_sha256,r.executor_user_id,r.policy_id,r.policy_revision,r.policy_sha256,r.grant_id,r.grant_revision,r.grant_sha256,r.template_id,r.template_version,r.template_content_sha256,r.document_id,r.materialization_id,r.materialization_revision,r.source_commitment,r.base_pdf_sha256,r.page_count,s.prior_execution_id,s.prior_document_id,s.document_id,s.actor_user_id,s.request_id,s.audit_event_id,ev.kind,ev.row_hash,ev.payload_json,ev.payload_hashed
 FROM presign_source_requests_v1 r
 JOIN html_document_creation_requests b ON b.org_id=r.org_id AND b.actor_user_id=r.executor_user_id AND b.request_id=r.creation_request_id
 JOIN documents d ON d.id=r.document_id AND d.org_id=r.org_id
 JOIN html_document_materializations m ON m.id=r.materialization_id AND m.org_id=r.org_id AND m.document_id=d.id
 JOIN presign_supersessions_v1 s ON s.org_id=r.org_id AND s.actor_user_id=r.executor_user_id AND s.request_id=r.request_id AND s.document_id=r.document_id
 JOIN events ev ON ev.id=s.audit_event_id
 WHERE r.org_id=$1 AND r.executor_credential_id=$2 AND r.request_id=$3 AND r.state='committed' AND r.close_event_id IS NULL AND r.crm_bindings_sha256 IS NULL
 AND r.creation_request_id=r.request_id AND r.input_sha256=b.input_digest AND b.original_document_id=r.document_id AND b.current_document_id=r.document_id AND b.template_id=r.template_id
 AND b.html_materialization_id=r.materialization_id AND b.html_source_commitment=r.source_commitment AND b.pdf_sha256=r.base_pdf_sha256 AND b.page_count=r.page_count
 AND r.original_document_updated_at=d.updated_at AND r.materialization_id=d.html_current_materialization_id AND r.materialization_revision=m.sequence
 AND r.base_pdf_key=d.pdf_storage_key AND r.base_pdf_version_id=d.pdf_storage_version_id AND r.base_pdf_sha256=d.pdf_sha256
 AND r.base_pdf_key=m.pdf_key AND r.base_pdf_version_id=m.pdf_version_id AND r.base_pdf_sha256=m.pdf_sha256 AND r.page_count=m.page_count
 AND ev.org_id=s.org_id AND ev.document_id=s.document_id AND ev.actor_user_id=s.actor_user_id AND ev.recipient_id IS NULL`, f.org, credential.ID, in.RequestID).Scan(&actual.Input, &actual.Credential, &actual.User, &actual.Policy, &actual.PolicyRevision, &actual.PolicySHA, &actual.Grant, &actual.GrantRevision, &actual.GrantSHA, &actual.Template, &actual.TemplateVersion, &actual.TemplateSHA, &actual.Document, &actual.Materialization, &actual.MaterializationRevision, &actual.Source, &actual.PDF, &actual.Pages, &actual.PriorExecution, &actual.PriorDocument, &actual.LinkedDocument, &actual.Actor, &actual.Request, &actual.Event, &actual.Kind, &actual.EventHash, &actual.Payload, &actual.Hashed)
	if err != nil || hex.EncodeToString(actual.Input) != expectedDigest || hex.EncodeToString(actual.Credential) != binding || actual.User != f.user.ID || actual.Policy != policy.ID || actual.PolicyRevision != policy.Revision || hex.EncodeToString(actual.PolicySHA) != policy.SHA256 || actual.Grant != grant.ID || actual.GrantRevision != grant.Revision || hex.EncodeToString(actual.GrantSHA) != grant.SHA256 || actual.Template != template.ID || actual.TemplateVersion != int64(template.Version) || hex.EncodeToString(actual.TemplateSHA) != hex.EncodeToString(template.HtmlContentSha256) || actual.Document != fresh.ID || actual.Materialization != source.MaterializationID || actual.MaterializationRevision != source.MaterializationRevision || actual.Source != source.SourceCommitment || hex.EncodeToString(actual.PDF) != source.PDFSHA256 || actual.Pages != source.PageCount || actual.PriorExecution != x.ID || actual.PriorDocument != parent.ID || actual.LinkedDocument != fresh.ID || actual.Actor != f.user.ID || actual.Request != in.RequestID || actual.Event == uuid.Nil || actual.Kind != "presign.execution.superseded" || len(actual.EventHash) != 32 {
		t.Fatal("actual API policy/seal/M79/link/audit tuple differs")
	}
	var payload, hashed map[string]any
	if json.Unmarshal(actual.Payload, &payload) != nil || json.Unmarshal(actual.Hashed, &hashed) != nil || !reflect.DeepEqual(payload, hashed) {
		t.Fatal("actual API supersession hashed audit differs")
	}
	want := map[string]any{"prior_execution_id": x.ID.String(), "prior_execution_sha256": execution.Commitment(), "prior_document_id": parent.ID.String(), "document_id": fresh.ID.String(), "request_id": in.RequestID.String(), "source_commitment": source.SourceCommitment}
	if !reflect.DeepEqual(payload, want) {
		t.Fatal("actual API supersession audit is not exact six-key lineage")
	}
	after := presign488APIPriorInventoryV1(t, q)
	recovered := presign488Decode[pdfadmission.PreSignAPISourceViewV1](t, presign488APIPriorCallV1(t, h, f.ctx, http.MethodGet, route+"/requests/"+in.RequestID.String(), minted.Plaintext, nil, http.StatusOK).body)
	replay := presign488Decode[pdfadmission.PreSignAPISourceViewV1](t, presign488APIPriorCallV1(t, h, f.ctx, http.MethodPost, route, minted.Plaintext, in, http.StatusOK).body)
	if !reflect.DeepEqual(recovered, created) || !reflect.DeepEqual(replay, created) || presign488APIPriorInventoryV1(t, q) != after {
		t.Fatal("original API GET/POST replay changed source, link or repeated effects")
	}
	changed := in
	differentPrior := p
	differentPrior.MaterializationID = uuid.New()
	changed.Prior = &differentPrior
	presign488APIPriorCallV1(t, h, f.ctx, http.MethodPost, route, minted.Plaintext, changed, http.StatusConflict)
	changed = in
	changed.DocumentName += " changed"
	presign488APIPriorCallV1(t, h, f.ctx, http.MethodPost, route, minted.Plaintext, changed, http.StatusConflict)
	changed = in
	changed.RequestID = uuid.New()
	presign488APIPriorCallV1(t, h, f.ctx, http.MethodPost, route, minted.Plaintext, changed, http.StatusConflict)
	if presign488APIPriorInventoryV1(t, q) != after {
		t.Fatal("API mutant or parent reuse left durable source/execution/outbox effects")
	}
	linked := presign488Decode[struct {
		SchemaVersion   int       `json:"schema_version"`
		State           string    `json:"state"`
		OrgID           uuid.UUID `json:"org_id"`
		UserID          uuid.UUID `json:"user_id"`
		PriorDocumentID uuid.UUID `json:"prior_document_id"`
		DocumentID      uuid.UUID `json:"document_id"`
	}](t, presign488Call(t, h, f.ctx, http.MethodGet, "/api/v1/presign/supersessions/documents/"+parent.ID.String()+"/context", nil, true, "", http.StatusOK).body)
	if linked.SchemaVersion != 1 || linked.State != "linked" || linked.OrgID != f.org || linked.UserID != f.user.ID || linked.PriorDocumentID != parent.ID || linked.DocumentID != fresh.ID || presign488APIPriorInventoryV1(t, q) != after {
		t.Fatal("actual API successor context did not recover same linked outcome")
	}
	if presign488SupersessionParentState(t, q, parent.ID) != parentBefore || presign488Counts(t, q, parent.ID) != parentEffects {
		t.Fatal("API supersession changed original completed parent or execution counts")
	}
	var executionRaw, assetsRaw []byte
	err = f.pool.QueryRow(f.ctx, `SELECT e.canonical_execution,a.canonical_assets FROM presign_executions e JOIN presign_execution_assets_v1 a ON a.org_id=e.org_id AND a.execution_id=e.id WHERE e.org_id=$1 AND e.document_id=$2`, f.org, parent.ID).Scan(&executionRaw, &assetsRaw)
	if err != nil || !bytes.Equal(executionRaw, execution.CanonicalJSON()) || !bytes.Equal(assetsRaw, assets.CanonicalJSON()) {
		t.Fatal("API supersession rewrote original execution or archive")
	}
	artifacts := []struct {
		key, version string
		sha, body    []byte
	}{{parent.FinalPdfKey.String, parent.FinalPdfVersionID.String, parent.FinalPdfSha, finalBodies[0]}, {parent.AuditCertKey.String, parent.AuditCertVersionID.String, parent.AuditCertSha256, finalBodies[1]}, {parent.AuditPayloadKey.String, parent.AuditPayloadVersionID.String, parent.AuditPayloadSha256, finalBodies[2]}, {parent.AuditSignatureKey.String, parent.AuditSignatureVersionID.String, parent.AuditSignatureSha256, finalBodies[3]}}
	for _, a := range artifacts {
		body, e := f.s.Storage.GetVerifiedVersion(f.ctx, a.key, a.version, a.sha)
		if e != nil || !bytes.Equal(body, a.body) || !retained(a.key, a.version, parent.FinalizationRetainUntil.Time) {
			t.Fatal("API supersession changed exact completed bytes or retention")
		}
	}
	originalObjects := []presign.ArtifactPin{x.Document.BasePDF.Artifact}
	for _, a := range assets.Snapshot().Objects {
		originalObjects = append(originalObjects, a.Object)
	}
	for _, o := range originalObjects {
		if !retained(o.StorageKey, o.VersionID, parent.FinalizationRetainUntil.Time) {
			t.Fatal("API supersession shortened original base/archive retention")
		}
	}
}
