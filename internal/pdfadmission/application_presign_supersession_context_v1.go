// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
)

type PreSignSupersessionTemplateV1 struct {
	ID            uuid.UUID            `json:"id"`
	Version       int32                `json:"version"`
	ContentSHA256 string               `json:"content_sha256"`
	Values        []htmlmaster.Value   `json:"values"`
	Defaults      map[string]string    `json:"defaults"`
	Sections      []htmlmaster.Section `json:"sections"`
}
type preSignSupersessionReadyV1 struct {
	SchemaVersion     int                           `json:"schema_version"`
	State             string                        `json:"state"`
	OrgID             uuid.UUID                     `json:"org_id"`
	UserID            uuid.UUID                     `json:"user_id"`
	CreationAvailable bool                          `json:"creation_available"`
	Prior             PreSignSupersessionParentV1   `json:"prior"`
	Template          PreSignSupersessionTemplateV1 `json:"template"`
}
type preSignSupersessionLinkedV1 struct {
	SchemaVersion   int       `json:"schema_version"`
	State           string    `json:"state"`
	OrgID           uuid.UUID `json:"org_id"`
	UserID          uuid.UUID `json:"user_id"`
	PriorDocumentID uuid.UUID `json:"prior_document_id"`
	DocumentID      uuid.UUID `json:"document_id"`
}

// The caller holds this reader's real consumer until the returned bounded JSON
// has been written. It retires SQL before writing; no storage/provider read,
// parent values clone or signature operation is represented by this projection.
func (r *ApplicationHTMLAuthoringReaderV1) ReadPreSignSupersessionContextV1(ctx context.Context, user, document uuid.UUID, available bool) ([]byte, error) {
	if r == nil || r.self != r || r.session == nil || r.session.state == nil || document == uuid.Nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	org := r.session.state.org
	if err := r.AcquireActorV1(ctx, org, user, false); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if !r.valid(ctx) {
		r.mu.Unlock()
		return nil, ErrHTMLAuthoringReadV1
	}
	db := &applicationOwnedDBTXV1{session: r.session.state}
	actor, err := r.queries.GetUserForShare(ctx, generated.GetUserForShareParams{ID: user, OrgID: org})
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	var sender, execution uuid.UUID
	var status string
	var size int64
	var expectedSHA []byte
	var deleted, envelope, parent bool
	err = db.QueryRow(ctx, `SELECT d.sender_id,d.status,d.deleted_at IS NOT NULL,d.is_envelope,d.parent_envelope_id IS NOT NULL,
  e.id,e.execution_sha256,octet_length(e.canonical_execution)::bigint
  FROM documents d JOIN presign_executions e ON e.org_id=d.org_id AND e.document_id=d.id
  WHERE d.id=$1 AND d.org_id=$2 FOR UPDATE OF d`, document, org).
		Scan(&sender, &status, &deleted, &envelope, &parent, &execution, &expectedSHA, &size)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if !preSignTerminalParentV1(status) || deleted || envelope || parent || (actor.Role != "owner" && (actor.Role != "sender" || sender != user)) || size < 1 || size > presign.MaxSnapshotBytes || len(expectedSHA) != 32 {
		r.mu.Unlock()
		return nil, presignregistry.ErrConflict
	}
	privacy, err := r.queries.TryCollabArchivePrivacyFence(ctx, org)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if !privacy {
		r.mu.Unlock()
		return nil, presignregistry.ErrConflict
	}
	pending, err := r.queries.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: document, OrgID: org})
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if pending {
		r.mu.Unlock()
		return nil, presignregistry.ErrConflict
	}
	// Includes the bounded final JSON and conservative encoder/copy working set
	// BEFORE either retained original evidence or public projection is produced.
	if err = r.acquire(ctx, size+4096, 1<<20); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	var successor uuid.UUID
	err = db.QueryRow(ctx, `SELECT COALESCE((SELECT document_id FROM presign_supersessions_v1 WHERE org_id=$1 AND prior_execution_id=$2),'00000000-0000-0000-0000-000000000000'::uuid)`, org, execution).Scan(&successor)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if successor != uuid.Nil {
		r.mu.Unlock()
		return json.Marshal(preSignSupersessionLinkedV1{1, "linked", org, user, document, successor})
	}
	var raw []byte
	err = db.QueryRow(ctx, `SELECT canonical_execution FROM presign_executions WHERE org_id=$1 AND id=$2 AND document_id=$3 AND octet_length(canonical_execution)=$4`, org, execution, document, size).Scan(&raw)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != size {
		return nil, ErrHTMLAuthoringReadV1
	}
	original, err := presign.DecodeExecution(raw)
	if err != nil || original.Commitment() != hex.EncodeToString(expectedSHA) {
		return nil, ErrHTMLAuthoringReadV1
	}
	snapshot := original.Snapshot()
	source := snapshot.Document
	p := PreSignSupersessionParentV1{ExecutionID: execution, ExecutionSHA256: original.Commitment(), DocumentID: document, SourceCommitment: source.Materialization.SourceCommitment, MaterializationID: source.Materialization.ID, MaterializationRevision: source.Materialization.Revision, Template: source.Template}
	if snapshot.OrgID != org || source.ID != document {
		return nil, ErrHTMLAuthoringReadV1
	}
	if err = r.CheckPreSignSupersessionParentV1(ctx, user, p, p.Template.ID); err != nil {
		return nil, err
	}
	r.mu.Lock()
	var version int32
	var contentSHA []byte
	if !r.valid(ctx) {
		r.mu.Unlock()
		return nil, ErrHTMLAuthoringReadV1
	}
	err = db.QueryRow(ctx, `SELECT version,html_content_sha256 FROM templates WHERE id=$1 AND org_id=$2 FOR SHARE`, p.Template.ID, org).Scan(&version, &contentSHA)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if len(contentSHA) != 32 {
		return nil, ErrHTMLAuthoringReadV1
	}
	digest := hex.EncodeToString(contentSHA)
	_, revision, err := r.ReadTemplateRevisionExpectedV1(ctx, p.Template.ID, version, digest)
	if err != nil {
		return nil, err
	}
	if revision == nil || !revision.ApprovedAt.Valid || !revision.ApprovedBy.Valid {
		return nil, presignregistry.ErrConflict
	}
	content, err := r.CanonicalRetainedTemplateV1(ctx, p.Template.ID, version)
	if err != nil {
		return nil, err
	}
	master, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		return nil, err
	}
	if master.SchemaVersion != 3 || master.ContractProfile == nil || master.SigningPage == nil {
		return nil, presignregistry.ErrInvalid
	}
	if _, err = htmlmaster.Compile(master); err != nil {
		return nil, err
	}
	defaults := map[string]string{}
	if err = json.Unmarshal(content.DefaultsJSON, &defaults); err != nil {
		return nil, err
	}
	values := append([]htmlmaster.Value{}, master.Values...)
	sections := append([]htmlmaster.Section{}, master.Sections...)
	response, err := json.Marshal(preSignSupersessionReadyV1{1, "ready", org, user, available, p, PreSignSupersessionTemplateV1{p.Template.ID, version, digest, values, defaults, sections}})
	if err != nil {
		return nil, err
	}
	if len(response) > 1<<20 {
		return nil, ErrHTMLAuthoringReadV1
	}
	return response, nil
}
