//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/google/uuid"
)

type presign488SupersessionReady struct {
	SchemaVersion     int                                        `json:"schema_version"`
	State             string                                     `json:"state"`
	OrgID             uuid.UUID                                  `json:"org_id"`
	UserID            uuid.UUID                                  `json:"user_id"`
	CreationAvailable bool                                       `json:"creation_available"`
	Prior             pdfadmission.PreSignSupersessionParentV1   `json:"prior"`
	Template          pdfadmission.PreSignSupersessionTemplateV1 `json:"template"`
}

// Extends the existing real HTML inventory with the actual M79/link/audit and
// pre-sign tables. SELECT-only test observation; no source/receipt is seeded.
func presign488SupersessionInventory(t *testing.T, q *ownedPublicReadFixtureV1) [2][32]byte {
	t.Helper()
	var raw []byte
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
 'births',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY actor_user_id,request_id),'[]'::jsonb) FROM html_document_creation_requests r WHERE org_id=$1),
 'links',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY prior_execution_id),'[]'::jsonb) FROM presign_supersessions_v1 r WHERE org_id=$1),
 'executions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM presign_executions r WHERE org_id=$1),
 'assets',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY execution_id),'[]'::jsonb) FROM presign_execution_assets_v1 r WHERE org_id=$1),
 'publications',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY execution_id),'[]'::jsonb) FROM presign_execution_publications_v1 r WHERE org_id=$1),
 'uses',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY execution_id),'[]'::jsonb) FROM presign_execution_uses r WHERE org_id=$1),
 'requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY executor_kind,executor_user_id,executor_credential_id,request_id),'[]'::jsonb) FROM presign_execution_requests r WHERE org_id=$1),
 'preparations',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM presign_preparations_v1 r WHERE org_id=$1),
 'objects',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY preparation_id,role),'[]'::jsonb) FROM presign_preparation_objects_v1 r WHERE org_id=$1),
 'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM signatures r WHERE document_id IN(SELECT id FROM documents WHERE org_id=$1)),
 'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM email_deliveries r)
 )`, q.f.org).Scan(&raw)
	if err != nil {
		t.Fatal("supersession exact extended inventory unavailable")
	}
	return [2][32]byte{sha256.Sum256(htmlContractInventoryE2E(t, q.f)), sha256.Sum256(raw)}
}

func presign488SupersessionParentState(t *testing.T, q *ownedPublicReadFixtureV1, parent uuid.UUID) [32]byte {
	t.Helper()
	var raw []byte
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
 'document',(SELECT to_jsonb(r) FROM documents r WHERE id=$2 AND org_id=$1),
 'execution',(SELECT to_jsonb(r) FROM presign_executions r WHERE document_id=$2 AND org_id=$1),
 'assets',(SELECT to_jsonb(r) FROM presign_execution_assets_v1 r WHERE document_id=$2 AND org_id=$1),
 'publication',(SELECT to_jsonb(r) FROM presign_execution_publications_v1 r WHERE document_id=$2 AND org_id=$1),
 'uses',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY execution_id),'[]'::jsonb) FROM presign_execution_uses r WHERE org_id=$1 AND execution_id IN(SELECT id FROM presign_executions WHERE org_id=$1 AND document_id=$2)),
 'requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY executor_kind,executor_user_id,executor_credential_id,request_id),'[]'::jsonb) FROM presign_execution_requests r WHERE org_id=$1 AND execution_id IN(SELECT id FROM presign_executions WHERE org_id=$1 AND document_id=$2)),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM events r WHERE document_id=$2 AND org_id=$1),
 'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id=$2),
 'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM signatures r WHERE document_id=$2),
 'fields',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM document_fields r WHERE document_id=$2),
 'materializations',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY sequence),'[]'::jsonb) FROM html_document_materializations r WHERE document_id=$2 AND org_id=$1),
 'versions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM document_versions r WHERE document_id=$2 AND org_id=$1)
 )`, q.f.org, parent).Scan(&raw)
	if err != nil {
		t.Fatal("completed parent exact preservation inventory unavailable")
	}
	return sha256.Sum256(raw)
}

// Paste the one invocation from the packet AFTER all genuine primary completed
// evidence assertions and BEFORE q.assertObserversOnlyV1(t). This helper creates
// exactly one successor; it does not run the API-positive case on that parent.
func presign488SessionSupersessionAfterCompletion(t *testing.T, q *ownedPublicReadFixtureV1, h presign488HTTP, template *generated.Template, parent *generated.Document, execution presign.Execution, assets presignexecute.AssetSetV1, finalBodies [][]byte, retained func(string, string, time.Time) bool) {
	t.Helper()
	f := q.f
	x := execution.Snapshot()
	if parent == nil || parent.Status != "completed" || retained == nil || template == nil || template.ID != x.Document.Template.ID || x.Document.ID != parent.ID || len(finalBodies) != 4 || !parent.FinalizationRetainUntil.Valid {
		t.Fatal("genuine completed primary prerequisite missing")
	}
	parentBefore := presign488SupersessionParentState(t, q, parent.ID)
	before := presign488SupersessionInventory(t, q)
	sideEffectsBefore := presign488Counts(t, q, parent.ID)
	var birthBefore, linkBefore, auditBefore int
	const lineageCounts = `SELECT (SELECT count(*) FROM html_document_creation_requests WHERE org_id=$1),(SELECT count(*) FROM presign_supersessions_v1 WHERE org_id=$1),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='presign.execution.superseded')`
	if err := f.pool.QueryRow(f.ctx, lineageCounts, f.org).Scan(&birthBefore, &linkBefore, &auditBefore); err != nil {
		t.Fatal("original lineage counts unavailable")
	}
	path := "/api/v1/presign/supersessions/documents/" + parent.ID.String() + "/context"
	response := presign488Call(t, h, f.ctx, "GET", path, nil, true, "", 200)
	if len(response.body) > 1<<20 || response.header.Get("Cache-Control") != "no-store" {
		t.Fatal("context body/header bound differs")
	}
	ready := presign488Decode[presign488SupersessionReady](t, response.body)
	p := ready.Prior
	pin := p.Template
	pin.ApprovedAt = x.Document.Template.ApprovedAt
	if ready.SchemaVersion != 1 || ready.State != "ready" || ready.OrgID != f.org || ready.UserID != f.user.ID || !ready.CreationAvailable || p.ValidateV1() != nil ||
		p.ExecutionID != x.ID || p.ExecutionSHA256 != execution.Commitment() || p.DocumentID != parent.ID || p.SourceCommitment != x.Document.Materialization.SourceCommitment || p.MaterializationID != x.Document.Materialization.ID || p.MaterializationRevision != x.Document.Materialization.Revision ||
		pin != x.Document.Template || !p.Template.ApprovedAt.Equal(x.Document.Template.ApprovedAt) || ready.Template.ID != template.ID || ready.Template.Version != template.Version || ready.Template.ContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) {
		t.Fatal("ready context does not bind actual actor/parent/current template")
	}
	if presign488SupersessionInventory(t, q) != before {
		t.Fatal("context read changed durable effects")
	}
	values := htmlStringMap{}
	for k, v := range ready.Template.Defaults {
		values[k] = v
	}
	declared := false
	for _, v := range ready.Template.Values {
		if v.Name == "customer_name" {
			declared = true
		}
	}
	if !declared {
		t.Fatal("primary actual contract lacks declared customer name")
	}
	values["customer_name"] = "Fresh linked customer"
	var sections htmlStringMap
	if len(ready.Template.Sections) > 0 {
		sections = make(htmlStringMap, len(ready.Template.Sections))
	}
	for _, s := range ready.Template.Sections {
		sections[s.Name] = s.DefaultText
	}
	in := preSignSupersessionInputV1{Prior: p, TemplateID: ready.Template.ID, Source: htmlDocumentInput{Name: "Fresh linked contract", ExpectedTemplateVersion: ready.Template.Version, ExpectedTemplateContentSHA256: ready.Template.ContentSHA256, Values: values, Sections: sections, RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.user.ID}}
	digest, err := preSignSupersessionInputDigestV1(authoring.Actor{OrgID: f.org, UserID: f.user.ID}, in)
	if err != nil {
		t.Fatal("actual context cannot form genuine fresh source")
	}
	created := presign488Decode[pdfadmission.PreSignSupersessionViewV1](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/supersessions", in, true, "", 201).body)
	if created.SchemaVersion != 1 || created.State != "committed" || created.RequestID != in.Source.RequestID || created.PriorExecutionID != x.ID || created.PriorDocumentID != parent.ID || created.DocumentID == parent.ID || created.DocumentID == uuid.Nil || created.SourceCommitment == p.SourceCommitment {
		t.Fatal("new linked outcome differs")
	}
	fresh, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.DocumentID, OrgID: f.org})
	if err != nil || fresh == nil || fresh.Status != "draft" || fresh.SenderID != f.user.ID || !fresh.TemplateID.Valid || uuid.UUID(fresh.TemplateID.Bytes) != template.ID || !fresh.RequiresSignature || fresh.RoutingMode != "parallel" || fresh.SourceKind != "pdf" || fresh.SigningAdmissionPolicy != "historical" || fresh.IsEnvelope || fresh.ParentEnvelopeID.Valid || fresh.HtmlReviewedAt.Valid || fresh.HtmlReviewedBy.Valid || fresh.HtmlCurrentMaterializationID == parent.HtmlCurrentMaterializationID || fresh.HtmlCurrentMaterializationSequence.Int32 != 1 || fresh.HtmlEffectiveSourceCommitment.String != created.SourceCommitment || htmlsource.Validate(fresh, false) != nil {
		t.Fatal("linked source is not fresh/unreviewed")
	}
	var sigs, executions, uses, recipients, pendingRecipients, fields int
	err = f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM signatures WHERE document_id=$1),(SELECT count(*) FROM presign_executions WHERE document_id=$1),
 (SELECT count(*) FROM presign_execution_uses u JOIN presign_executions e ON e.org_id=u.org_id AND e.id=u.execution_id WHERE e.document_id=$1),
 (SELECT count(*) FROM recipients WHERE document_id=$1),
 (SELECT count(*) FROM recipients WHERE document_id=$1 AND status='pending' AND sent_at IS NULL AND first_viewed_at IS NULL AND signed_at IS NULL),
 (SELECT count(*) FROM document_fields WHERE document_id=$1)`, fresh.ID).Scan(&sigs, &executions, &uses, &recipients, &pendingRecipients, &fields)
	if err != nil || sigs != 0 || executions != 0 || uses != 0 || recipients != 2 || pendingRecipients != 2 || fields != 2 || presign488Counts(t, q, parent.ID) != sideEffectsBefore {
		t.Fatal("create-only draft signed, executed, invited or reused parties")
	}
	var births, links, audits int
	if err = f.pool.QueryRow(f.ctx, lineageCounts, f.org).Scan(&births, &links, &audits); err != nil || births != birthBefore+1 || links != linkBefore+1 || audits != auditBefore+1 {
		t.Fatal("birth must add exactly one M79/link/supersession audit")
	}
	var actualDigest, eventHash []byte
	var actualPrior, actualParent, actualDocument, request, actor, event uuid.UUID
	var payload, hashed []byte
	var eventKind string
	err = f.pool.QueryRow(f.ctx, `SELECT b.input_digest,s.prior_execution_id,s.prior_document_id,s.document_id,s.request_id,s.actor_user_id,s.audit_event_id,ev.kind,ev.row_hash,ev.payload_json,ev.payload_hashed
 FROM presign_supersessions_v1 s JOIN html_document_creation_requests b ON b.org_id=s.org_id AND b.actor_user_id=s.actor_user_id AND b.request_id=s.request_id
 JOIN events ev ON ev.id=s.audit_event_id WHERE s.org_id=$1 AND s.prior_execution_id=$2
 AND b.original_document_id=s.document_id AND b.current_document_id=s.document_id AND b.template_id=$3
 AND b.html_materialization_id=$4 AND b.html_source_commitment=$5 AND b.pdf_sha256=$6
 AND ev.org_id=s.org_id AND ev.document_id=s.document_id AND ev.actor_user_id=s.actor_user_id AND ev.recipient_id IS NULL`, f.org, x.ID, template.ID, fresh.HtmlCurrentMaterializationID, fresh.HtmlEffectiveSourceCommitment.String, fresh.PdfSha256).Scan(&actualDigest, &actualPrior, &actualParent, &actualDocument, &request, &actor, &event, &eventKind, &eventHash, &payload, &hashed)
	if err != nil || hex.EncodeToString(actualDigest) != digest || actualPrior != x.ID || actualParent != parent.ID || actualDocument != fresh.ID || request != in.Source.RequestID || actor != f.user.ID || event == uuid.Nil || eventKind != "presign.execution.superseded" || len(eventHash) != 32 {
		t.Fatal("actual M79/link/audit tuple differs")
	}
	var got, hashedPayload map[string]any
	if json.Unmarshal(payload, &got) != nil || json.Unmarshal(hashed, &hashedPayload) != nil || !reflect.DeepEqual(got, hashedPayload) {
		t.Fatal("actual supersession hashed payload differs")
	}
	want := map[string]any{"prior_execution_id": x.ID.String(), "prior_execution_sha256": execution.Commitment(), "prior_document_id": parent.ID.String(), "document_id": fresh.ID.String(), "request_id": in.Source.RequestID.String(), "source_commitment": created.SourceCommitment}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("supersession audit is not exact six-key actual lineage")
	}
	after := presign488SupersessionInventory(t, q)
	recovered := presign488Decode[pdfadmission.PreSignSupersessionViewV1](t, presign488Call(t, h, f.ctx, "GET", "/api/v1/presign/supersessions/requests/"+in.Source.RequestID.String(), nil, true, "", 200).body)
	replay := presign488Decode[pdfadmission.PreSignSupersessionViewV1](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/supersessions", in, true, "", 200).body)
	if recovered != created || replay != created || presign488SupersessionInventory(t, q) != after {
		t.Fatal("original GET/POST replay changed link or repeated effects")
	}
	changed := in
	changed.Prior.MaterializationID = uuid.New()
	presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/supersessions", changed, true, "", 409)
	changed = in
	changed.Source.Name += " changed"
	presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/supersessions", changed, true, "", 409)
	changed = in
	changed.Source.RequestID = uuid.New()
	presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/supersessions", changed, true, "", 409)
	if presign488SupersessionInventory(t, q) != after {
		t.Fatal("mutant or second-parent request left effects, including M79/link/audit")
	}
	linked := presign488Decode[struct {
		SchemaVersion   int       `json:"schema_version"`
		State           string    `json:"state"`
		OrgID           uuid.UUID `json:"org_id"`
		UserID          uuid.UUID `json:"user_id"`
		PriorDocumentID uuid.UUID `json:"prior_document_id"`
		DocumentID      uuid.UUID `json:"document_id"`
	}](t, presign488Call(t, h, f.ctx, "GET", path, nil, true, "", 200).body)
	if linked.SchemaVersion != 1 || linked.State != "linked" || linked.OrgID != f.org || linked.UserID != f.user.ID || linked.PriorDocumentID != parent.ID || linked.DocumentID != fresh.ID || presign488SupersessionInventory(t, q) != after {
		t.Fatal("linked context does not recover actual successor without effects")
	}
	if presign488SupersessionParentState(t, q, parent.ID) != parentBefore {
		t.Fatal("supersession changed original completed document/evidence")
	}
	var exRaw, assetRaw []byte
	err = f.pool.QueryRow(f.ctx, `SELECT e.canonical_execution,a.canonical_assets FROM presign_executions e JOIN presign_execution_assets_v1 a ON a.org_id=e.org_id AND a.execution_id=e.id WHERE e.org_id=$1 AND e.document_id=$2`, f.org, parent.ID).Scan(&exRaw, &assetRaw)
	if err != nil || !bytes.Equal(exRaw, execution.CanonicalJSON()) || !bytes.Equal(assetRaw, assets.CanonicalJSON()) {
		t.Fatal("supersession rewrote original execution/assets")
	}
	artifacts := []struct {
		key, version string
		sha, body    []byte
	}{{parent.FinalPdfKey.String, parent.FinalPdfVersionID.String, parent.FinalPdfSha, finalBodies[0]}, {parent.AuditCertKey.String, parent.AuditCertVersionID.String, parent.AuditCertSha256, finalBodies[1]}, {parent.AuditPayloadKey.String, parent.AuditPayloadVersionID.String, parent.AuditPayloadSha256, finalBodies[2]}, {parent.AuditSignatureKey.String, parent.AuditSignatureVersionID.String, parent.AuditSignatureSha256, finalBodies[3]}}
	for _, a := range artifacts {
		body, e := f.s.Storage.GetVerifiedVersion(f.ctx, a.key, a.version, a.sha)
		if e != nil || !bytes.Equal(body, a.body) || !retained(a.key, a.version, parent.FinalizationRetainUntil.Time) {
			t.Fatal("original final exact bytes/retention changed")
		}
	}
}
