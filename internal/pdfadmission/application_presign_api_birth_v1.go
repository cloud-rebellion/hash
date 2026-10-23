// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// No private source body, object key, VersionId or credential commitment is
// returned by the public original-request projection.
type PreSignAPISourcePinsV1 struct {
	DocumentID              uuid.UUID `json:"document_id"`
	DocumentUpdatedAt       time.Time `json:"document_updated_at"`
	MaterializationID       uuid.UUID `json:"materialization_id"`
	MaterializationRevision int64     `json:"materialization_revision"`
	SourceCommitment        string    `json:"source_commitment"`
	PDFSHA256               string    `json:"pdf_sha256"`
	PageCount               int32     `json:"page_count"`
}
type PreSignAPISourceViewV1 struct {
	SchemaVersion int                     `json:"schema_version"`
	RequestID     uuid.UUID               `json:"request_id"`
	State         string                  `json:"state"`
	InputSHA256   string                  `json:"input_sha256,omitempty"`
	Source        *PreSignAPISourcePinsV1 `json:"source,omitempty"`
}

// This command selects only original request identity and reviewed references.
// The private auth admission and actual M79/native document supply authority.
type PreSignAPISourceCommandV1 struct {
	RequestID     uuid.UUID
	InputSHA256   string
	Policy, Grant presign.Reference
}

func preSignSourceDigestV1(v string) ([]byte, bool) {
	raw, err := hex.DecodeString(v)
	return raw, err == nil && len(raw) == 32 && hex.EncodeToString(raw) == v
}

// Registry rows are measured before their real canonical bodies are read.
// API and grantor users use the same original reader's native actor loans.
func (r *ApplicationHTMLAuthoringReaderV1) LockPreSignAPIBirthAuthorityV1(ctx context.Context, a auth.PreSignAPIAdmissionV1, policy, grant presign.Reference) (presignregistry.ExecutionAuthorityV1, error) {
	var zero presignregistry.ExecutionAuthorityV1
	if r == nil || r.self != r || a.OrgID() == uuid.Nil || a.CredentialID() == uuid.Nil {
		return zero, ErrHTMLAuthoringReadV1
	}
	if err := r.AcquireActorV1(ctx, a.OrgID(), a.UserID(), false); err != nil {
		return zero, err
	}
	r.mu.Lock()
	if !r.valid(ctx) || r.session.state.org != a.OrgID() {
		r.mu.Unlock()
		return zero, ErrHTMLAuthoringReadV1
	}
	db := &applicationOwnedDBTXV1{session: r.session.state}
	var grantor uuid.UUID
	err := db.QueryRow(ctx, `SELECT grantor_user_id FROM presign_grants WHERE org_id=$1 AND id=$2`, a.OrgID(), grant.ID).Scan(&grantor)
	r.mu.Unlock()
	if err != nil {
		return zero, err
	}
	if err = r.AcquireActorV1(ctx, a.OrgID(), grantor, false); err != nil {
		return zero, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) {
		return zero, ErrHTMLAuthoringReadV1
	}
	var definitionBytes, policyBytes, grantBytes int64
	err = db.QueryRow(ctx, `SELECT octet_length(p.canonical_definition)::bigint,octet_length(p.canonical_policy)::bigint,octet_length(g.canonical_grant)::bigint
 FROM presign_workflow_revisions p JOIN presign_grant_revisions g ON g.org_id=p.org_id
 WHERE p.org_id=$1 AND p.policy_id=$2 AND p.revision=$3 AND g.grant_id=$4 AND g.revision=$5
 AND g.policy_id=p.policy_id AND g.policy_revision=p.revision AND g.policy_sha256=p.policy_sha256`, a.OrgID(), policy.ID, policy.Revision, grant.ID, grant.Revision).Scan(&definitionBytes, &policyBytes, &grantBytes)
	if err != nil {
		return zero, err
	}
	if definitionBytes < 1 || definitionBytes > presignregistry.MaxDefinitionBytes || policyBytes < 1 || policyBytes > presign.MaxSnapshotBytes || grantBytes < 1 || grantBytes > presign.MaxSnapshotBytes {
		return zero, ErrHTMLAuthoringReadV1
	}
	raw, err := htmlAuthoringSumV1(definitionBytes, policyBytes, grantBytes)
	if err != nil {
		return zero, err
	}
	if err = r.acquire(ctx, raw, 0); err != nil {
		return zero, err
	}
	actor, err := presignregistry.NewAPIExecutionActorV1(a)
	if err != nil {
		return zero, err
	}
	owned, tx, done, err := applicationSessionSQLBorrowV1(ctx, r.session.state, true)
	if err != nil {
		return zero, err
	}
	defer done()
	return presignregistry.LockExecutionAuthorityV1(owned, tx, actor, policy, grant)
}

func (r *ApplicationHTMLAuthoringReaderV1) ReadPreSignAPISourceV1(ctx context.Context, a auth.PreSignAPIAdmissionV1, request uuid.UUID) (PreSignAPISourceViewV1, error) {
	out := PreSignAPISourceViewV1{SchemaVersion: 1, RequestID: request, State: "unconfirmed"}
	if r == nil || r.self != r || request == uuid.Nil {
		return out, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || r.session.state.org != a.OrgID() {
		return out, ErrHTMLAuthoringReadV1
	}
	// Fixed descriptor/projection plus the small original closure audit frame;
	// the same loan precedes its actual audit producer if this is a close call.
	if err := r.acquire(ctx, 8192, 4096); err != nil {
		return out, err
	}
	var credential, input []byte
	var user uuid.UUID
	var document, materialization pgtype.UUID
	var updated pgtype.Timestamptz
	var revision pgtype.Int8
	var source pgtype.Text
	var pdf []byte
	var pages pgtype.Int4
	db := &applicationOwnedDBTXV1{session: r.session.state}
	err := db.QueryRow(ctx, `SELECT state,executor_user_id,original_credential_sha256,input_sha256,document_id,original_document_updated_at,
 materialization_id,materialization_revision,source_commitment,base_pdf_sha256,page_count FROM presign_source_requests_v1
 WHERE org_id=$1 AND executor_credential_id=$2 AND request_id=$3`, a.OrgID(), a.CredentialID(), request).
		Scan(&out.State, &user, &credential, &input, &document, &updated, &materialization, &revision, &source, &pdf, &pages)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	original, ok := preSignSourceDigestV1(a.Commitment())
	if !ok || user != a.UserID() || !bytes.Equal(original, credential) {
		return out, auth.ErrMutationPermissionRevoked
	}
	if out.State == "closed" {
		if len(input) != 0 || document.Valid || updated.Valid || materialization.Valid || revision.Valid || source.Valid || len(pdf) != 0 || pages.Valid {
			return out, ErrHTMLAuthoringReadV1
		}
		return out, nil
	}
	if out.State != "committed" || len(input) != 32 || !document.Valid || uuid.UUID(document.Bytes) == uuid.Nil || !updated.Valid || updated.Time.IsZero() ||
		!materialization.Valid || uuid.UUID(materialization.Bytes) == uuid.Nil || !revision.Valid || revision.Int64 != 1 || !source.Valid || len(pdf) != 32 || !pages.Valid || pages.Int32 < 1 {
		return out, ErrHTMLAuthoringReadV1
	}
	if _, ok := preSignSourceDigestV1(source.String); !ok {
		return out, ErrHTMLAuthoringReadV1
	}
	out.InputSHA256 = hex.EncodeToString(input)
	out.Source = &PreSignAPISourcePinsV1{DocumentID: uuid.UUID(document.Bytes), DocumentUpdatedAt: updated.Time.UTC(), MaterializationID: uuid.UUID(materialization.Bytes), MaterializationRevision: revision.Int64, SourceCommitment: source.String, PDFSHA256: hex.EncodeToString(pdf), PageCount: pages.Int32}
	return out, nil
}

// Called by the genuine HTML pipeline's final original-author recheck, after
// its actual M79 request INSERT and before the SAME transaction commits. Earlier
// preparation callbacks can inspect a tombstone but cannot invent a document.
func (r *ApplicationHTMLAuthoringReaderV1) SealPreSignAPISourceV1(ctx context.Context, a auth.PreSignAPIAdmissionV1, c PreSignAPISourceCommandV1, template presign.TemplatePin) error {
	return r.sealPreSignAPISourceV1(ctx, a, c, template, nil)
}
func (r *ApplicationHTMLAuthoringReaderV1) SealPreSignAPICRMSourceV1(ctx context.Context, a auth.PreSignAPIAdmissionV1, c PreSignAPISourceCommandV1, template presign.TemplatePin, h *ApplicationPreSignCRMSourceV1) error {
	if !h.lockV1() {
		return ErrHTMLAuthoringReadV1
	}
	defer h.unlockV1()
	if h.admission.OrgID() != a.OrgID() || h.admission.UserID() != a.UserID() || h.admission.CredentialID() != a.CredentialID() || h.admission.Commitment() != a.Commitment() || h.command != c || h.template != template {
		return ErrHTMLAuthoringReadV1
	}
	if err := h.checkLockedV1(ctx, r); err != nil {
		return err
	}
	return r.sealPreSignAPISourceV1(ctx, a, c, template, h)
}
func (r *ApplicationHTMLAuthoringReaderV1) sealPreSignAPISourceV1(ctx context.Context, a auth.PreSignAPIAdmissionV1, c PreSignAPISourceCommandV1, template presign.TemplatePin, crm *ApplicationPreSignCRMSourceV1) error {
	input, ok := preSignSourceDigestV1(c.InputSHA256)
	if !ok {
		return ErrHTMLAuthoringReadV1
	}
	prior, err := r.ReadPreSignAPISourceV1(ctx, a, c.RequestID)
	if err != nil {
		return err
	}
	if prior.State == "closed" {
		return presignregistry.ErrConflict
	}
	if prior.State == "committed" {
		if prior.InputSHA256 != c.InputSHA256 {
			return presignregistry.ErrConflict
		}
		return nil
	}
	authority, err := r.LockPreSignAPIBirthAuthorityV1(ctx, a, c.Policy, c.Grant)
	if err != nil {
		return err
	}
	definition := authority.Definition()
	if definition.Kind != presignregistry.KindApprovedData || (definition.DataRules.CRM != nil) != (crm != nil) || authority.Policy().Snapshot().Template != template ||
		authority.Grant().Snapshot().Grantor.UserID != a.UserID() {
		return presignregistry.ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || r.session.state.org != a.OrgID() {
		return ErrHTMLAuthoringReadV1
	}
	db := &applicationOwnedDBTXV1{session: r.session.state}
	var actualDocument uuid.UUID
	var actualInput []byte
	err = db.QueryRow(ctx, `SELECT original_document_id,input_digest FROM html_document_creation_requests WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`, a.OrgID(), a.UserID(), c.RequestID).Scan(&actualDocument, &actualInput)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if actualDocument != r.session.state.document || !bytes.Equal(actualInput, input) {
		return presignregistry.ErrConflict
	}
	// The final callback validates actual newly inserted source bytes, not the
	// handler's derived maps or a caller-provided source commitment. Existing
	// cache/server-version and exact-wire gates precede this real body read.
	h, err := r.queries.GetHTMLRevisionDocumentReadHeaderV1(ctx, generated.GetHTMLRevisionDocumentReadHeaderV1Params{DocumentID: actualDocument, OrgID: a.OrgID()})
	if err != nil {
		return err
	}
	if h == nil || h.ID != actualDocument || h.OrgID != a.OrgID() || h.ServerVersionNum <= 0 || h.PolicyMeasurementServerVersionNum != h.ServerVersionNum ||
		h.ResponseMeasurementServerVersionNum != h.ServerVersionNum || h.ReportMeasurementServerVersionNum != h.ServerVersionNum {
		return ErrHTMLAuthoringReadV1
	}
	wire, err := htmlAuthoringSumV1(h.HtmlOriginWireBytes, h.HtmlCurrentWireBytes, h.VariablesWireBytes, h.BlocksWireBytes, h.MetadataWireBytes, h.ReportWireBytes)
	if err != nil {
		return err
	}
	if err = r.acquire(ctx, h.RawTextBytes, wire); err != nil {
		return err
	}
	doc, err := r.queries.ReadSignerDocumentV1(ctx, generated.ReadSignerDocumentV1Params{DocumentID: actualDocument, OrgID: a.OrgID(), ExpectedUpdatedAt: h.UpdatedAt,
		ExpectedHtmlOriginWireBytes: h.HtmlOriginWireBytes, ExpectedHtmlCurrentWireBytes: h.HtmlCurrentWireBytes, ExpectedVariablesWireBytes: h.VariablesWireBytes,
		ExpectedBlocksWireBytes: h.BlocksWireBytes, ExpectedMetadataWireBytes: h.MetadataWireBytes, ExpectedReportWireBytes: h.ReportWireBytes})
	if err != nil {
		return err
	}
	if doc == nil || doc.ID != actualDocument || doc.OrgID != a.OrgID() || doc.UpdatedAt != h.UpdatedAt || signerDocumentRawBytesV1(doc) != h.RawTextBytes ||
		int64(len(doc.HtmlSourceJson)) != h.HtmlOriginWireBytes || int64(len(doc.HtmlCurrentSourceJson)) != h.HtmlCurrentWireBytes ||
		int64(len(doc.VariablesJson)) != h.VariablesWireBytes || int64(len(doc.BlocksJson)) != h.BlocksWireBytes ||
		int64(len(doc.Metadata)) != h.MetadataWireBytes || int64(len(doc.MetadataRedactionReport)) != h.ReportWireBytes {
		return ErrHTMLAuthoringReadV1
	}
	var bindingsSHA []byte
	if crm != nil {
		if err = r.acquire(ctx, 64*4096, 64*4096); err != nil {
			return err
		}
		_, digest, e := crm.reportsLockedV1(ctx, r, doc)
		if e != nil {
			return e
		}
		var valid bool
		bindingsSHA, valid = preSignSourceDigestV1(digest)
		if !valid {
			return ErrHTMLAuthoringReadV1
		}
	} else if _, err = presignregistry.EvaluateExecutionData(definition, authority.Grant().Snapshot().Grantor, doc, nil, authority.ObservedAt()); err != nil {
		return err
	}
	credential, ok := preSignSourceDigestV1(a.Commitment())
	if !ok {
		return ErrHTMLAuthoringReadV1
	}
	policy, ok := preSignSourceDigestV1(c.Policy.SHA256)
	if !ok {
		return ErrHTMLAuthoringReadV1
	}
	grant, ok := preSignSourceDigestV1(c.Grant.SHA256)
	if !ok {
		return ErrHTMLAuthoringReadV1
	}
	content, ok := preSignSourceDigestV1(template.ContentSHA256)
	if !ok {
		return ErrHTMLAuthoringReadV1
	}
	tag, err := db.Exec(ctx, `INSERT INTO presign_source_requests_v1(org_id,executor_credential_id,request_id,executor_user_id,original_credential_sha256,state,input_sha256,
 policy_id,policy_revision,policy_sha256,grant_id,grant_revision,grant_sha256,template_id,template_version,template_content_sha256,
 creation_request_id,document_id,original_document_updated_at,materialization_id,materialization_revision,source_commitment,base_pdf_key,base_pdf_version_id,base_pdf_sha256,page_count,crm_bindings_sha256)
 SELECT d.org_id,$2,$3,d.sender_id,$4,'committed',$5,$6,$7,$8,$9,$10,$11,r.template_id,$12,$13,r.request_id,d.id,d.updated_at,
 m.id,m.sequence,r.html_source_commitment,m.pdf_key,m.pdf_version_id,m.pdf_sha256,m.page_count,$17
 FROM html_document_creation_requests r JOIN documents d ON d.org_id=r.org_id AND d.id=r.original_document_id
 JOIN html_document_materializations m ON m.org_id=d.org_id AND m.document_id=d.id AND m.id=d.html_current_materialization_id
 WHERE r.org_id=$1 AND r.actor_user_id=$14 AND r.request_id=$3 AND r.input_digest=$5 AND d.id=$15 AND r.current_document_id=d.id
 AND r.template_id=$16 AND d.template_id=r.template_id AND d.status='draft' AND d.deleted_at IS NULL AND d.source_kind='pdf'
 AND d.requires_signature AND NOT d.is_envelope AND d.parent_envelope_id IS NULL AND d.signing_admission_policy='historical'
 AND m.sequence=1 AND m.id=r.html_materialization_id AND encode(m.source_commitment,'hex')=r.html_source_commitment
 AND m.pdf_key=d.pdf_storage_key AND m.pdf_version_id=d.pdf_storage_version_id AND m.pdf_sha256=d.pdf_sha256
 AND m.pdf_sha256=r.pdf_sha256 AND m.page_count=r.page_count`, a.OrgID(), a.CredentialID(), c.RequestID, credential, input, c.Policy.ID, c.Policy.Revision, policy, c.Grant.ID, c.Grant.Revision, grant, template.Version, content, a.UserID(), actualDocument, template.ID, bindingsSHA)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return presignregistry.ErrConflict
	}
	return nil
}

// Caller takes the SAME existing org billing lock as final HTML creation before
// this fixed tombstone. Its actual closure audit is appended before COMMIT.
func (r *ApplicationHTMLAuthoringReaderV1) ClosePreSignAPISourceV1(ctx context.Context, a auth.PreSignAPIAdmissionV1, request, event uuid.UUID) (PreSignAPISourceViewV1, bool, error) {
	prior, err := r.ReadPreSignAPISourceV1(ctx, a, request)
	if err != nil || prior.State != "unconfirmed" {
		return prior, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || r.session.state.org != a.OrgID() {
		return prior, false, ErrHTMLAuthoringReadV1
	}
	if event == uuid.Nil {
		return prior, false, ErrHTMLAuthoringReadV1
	}
	if err = r.acquire(ctx, 4096, 4096); err != nil {
		return prior, false, err
	}
	credential, ok := preSignSourceDigestV1(a.Commitment())
	if !ok {
		return prior, false, ErrHTMLAuthoringReadV1
	}
	db := &applicationOwnedDBTXV1{session: r.session.state}
	tag, err := db.Exec(ctx, `INSERT INTO presign_source_requests_v1(org_id,executor_credential_id,request_id,executor_user_id,original_credential_sha256,state,close_event_id)
 VALUES($1,$2,$3,$4,$5,'closed',$6)`, a.OrgID(), a.CredentialID(), request, a.UserID(), credential, event)
	if err != nil {
		return prior, false, err
	}
	if tag.RowsAffected() != 1 {
		return prior, false, presignregistry.ErrConflict
	}
	prior.State = "closed"
	return prior, true, nil
}
