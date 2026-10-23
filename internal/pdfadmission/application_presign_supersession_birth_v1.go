// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Expected observations only. The native loader reads the actual immutable
// execution/assets and current terminal parent before any new source effects.
type PreSignSupersessionParentV1 struct {
	ExecutionID             uuid.UUID           `json:"execution_id"`
	ExecutionSHA256         string              `json:"execution_sha256"`
	DocumentID              uuid.UUID           `json:"document_id"`
	SourceCommitment        string              `json:"source_commitment"`
	MaterializationID       uuid.UUID           `json:"materialization_id"`
	MaterializationRevision int64               `json:"materialization_revision"`
	Template                presign.TemplatePin `json:"template"`
}

func (p PreSignSupersessionParentV1) ValidateV1() error {
	_, execution := preSignSourceDigestV1(p.ExecutionSHA256)
	_, source := preSignSourceDigestV1(p.SourceCommitment)
	_, content := preSignSourceDigestV1(p.Template.ContentSHA256)
	if p.ExecutionID == uuid.Nil || p.DocumentID == uuid.Nil || p.MaterializationID == uuid.Nil || p.MaterializationRevision < 1 || p.MaterializationRevision > presign.MaxRevision || p.Template.ID == uuid.Nil || p.Template.Version < 1 || p.Template.Version > presign.MaxRevision || p.Template.ApprovedBy == uuid.Nil || p.Template.ApprovedAt.IsZero() || !execution || !source || !content {
		return presignregistry.ErrInvalid
	}
	return nil
}

type PreSignSupersessionViewV1 struct {
	SchemaVersion    int       `json:"schema_version"`
	RequestID        uuid.UUID `json:"request_id"`
	State            string    `json:"state"`
	PriorExecutionID uuid.UUID `json:"prior_execution_id"`
	PriorDocumentID  uuid.UUID `json:"prior_document_id"`
	DocumentID       uuid.UUID `json:"document_id"`
	SourceCommitment string    `json:"source_commitment"`
}
type PreSignSupersessionBirthV1 struct {
	PriorExecutionID     uuid.UUID
	PriorExecutionSHA256 string
	PriorDocumentID      uuid.UUID
	DocumentID           uuid.UUID
	RequestID            uuid.UUID
	SourceCommitment     string
}

func preSignSameTemplateV1(a, b presign.TemplatePin) bool {
	return a.ID == b.ID && a.Version == b.Version && a.ContentSHA256 == b.ContentSHA256 && a.ApprovedBy == b.ApprovedBy && a.ApprovedAt.Equal(b.ApprovedAt)
}
func preSignTerminalParentV1(status string) bool {
	return status == "declined" || status == "voided" || status == "expired" || status == "completed"
}

// Read the actual current approved revision under original native template
// loans before provider/render/storage effects. The genuine HTML pipeline
// subsequently rechecks these same immutable version/content observations.
func (r *ApplicationHTMLAuthoringReaderV1) CheckPreSignSupersessionTemplateV1(ctx context.Context, id uuid.UUID, version int32, digest string) error {
	_, revision, err := r.ReadTemplateRevisionExpectedV1(ctx, id, version, digest)
	if err != nil {
		return err
	}
	if revision == nil || !revision.ApprovedBy.Valid || !revision.ApprovedAt.Valid {
		return presignregistry.ErrConflict
	}
	content, err := r.CanonicalRetainedTemplateV1(ctx, id, version)
	if err != nil {
		return err
	}
	if content.SHA256 != digest {
		return presignregistry.ErrConflict
	}
	master, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		return err
	}
	if master.SchemaVersion != 3 || master.ContractProfile == nil || master.SigningPage == nil {
		return presignregistry.ErrInvalid
	}
	_, err = htmlmaster.Compile(master)
	return err
}

// Same actual reader/session/body registry as the fresh HTML creation. Neither
// a caller DBTX nor a supplied canonical descriptor can replace this read.
func (r *ApplicationHTMLAuthoringReaderV1) CheckPreSignSupersessionParentV1(ctx context.Context, user uuid.UUID, p PreSignSupersessionParentV1, template uuid.UUID) error {
	if r == nil || r.self != r || r.session == nil || r.session.state == nil || p.ValidateV1() != nil || template != p.Template.ID {
		return presignregistry.ErrInvalid
	}
	if err := r.AcquireActorV1(ctx, r.session.state.org, user, false); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) {
		return ErrHTMLAuthoringReadV1
	}
	db := &applicationOwnedDBTXV1{session: r.session.state}
	org := r.session.state.org
	actor, err := r.queries.GetUserForShare(ctx, generated.GetUserForShareParams{ID: user, OrgID: org})
	if err != nil {
		return err
	}
	var sender uuid.UUID
	var status, source string
	var materialization, actualTemplate uuid.UUID
	var revision int64
	var deleted, envelope, parent bool
	err = db.QueryRow(ctx, `SELECT sender_id,status,html_effective_source_commitment,html_current_materialization_id,
  html_current_materialization_sequence::bigint,template_id,deleted_at IS NOT NULL,is_envelope,parent_envelope_id IS NOT NULL
  FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE`, p.DocumentID, org).Scan(&sender, &status, &source, &materialization, &revision, &actualTemplate, &deleted, &envelope, &parent)
	if err != nil {
		return err
	}
	if !preSignTerminalParentV1(status) || deleted || envelope || parent || source != p.SourceCommitment || materialization != p.MaterializationID || revision != p.MaterializationRevision || actualTemplate != p.Template.ID ||
		(actor.Role != "owner" && (actor.Role != "sender" || sender != user)) {
		return presignregistry.ErrConflict
	}
	var linked bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM presign_supersessions_v1 WHERE org_id=$1 AND prior_execution_id=$2)`, org, p.ExecutionID).Scan(&linked); err != nil {
		return err
	}
	if linked {
		return presignregistry.ErrConflict
	}
	// Preserve the existing later-amendment/draft privacy fence before reading
	// retained source bodies. Contention refuses instead of waiting inversely
	// while the terminal parent is locked.
	privacy, err := r.queries.TryCollabArchivePrivacyFence(ctx, org)
	if err != nil {
		return err
	}
	if !privacy {
		return presignregistry.ErrConflict
	}
	pending, err := r.queries.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: p.DocumentID, OrgID: org})
	if err != nil {
		return err
	}
	if pending {
		return presignregistry.ErrConflict
	}
	var lengths [6]int64
	err = db.QueryRow(ctx, `SELECT octet_length(e.canonical_execution)::bigint,octet_length(e.command_canonical)::bigint,
  octet_length(e.admission_canonical)::bigint,octet_length(w.canonical_policy)::bigint,octet_length(g.canonical_grant)::bigint,
  COALESCE(octet_length(a.canonical_assets),0)::bigint
  FROM presign_executions e JOIN presign_workflow_revisions w ON w.org_id=e.org_id AND w.policy_id=e.policy_id AND w.revision=e.policy_revision
  JOIN presign_grant_revisions g ON g.org_id=e.org_id AND g.grant_id=e.grant_id AND g.revision=e.grant_revision
  LEFT JOIN presign_execution_assets_v1 a ON a.org_id=e.org_id AND a.execution_id=e.id AND a.document_id=e.document_id
  WHERE e.org_id=$1 AND e.id=$2 AND e.document_id=$3`, org, p.ExecutionID, p.DocumentID).Scan(&lengths[0], &lengths[1], &lengths[2], &lengths[3], &lengths[4], &lengths[5])
	if err != nil {
		return err
	}
	for _, n := range lengths {
		if n < 1 || n > presign.MaxSnapshotBytes {
			return ErrHTMLAuthoringReadV1
		}
	}
	raw, err := htmlAuthoringSumV1(lengths[0], lengths[1], lengths[2], lengths[3], lengths[4], lengths[5], 8*(2048+256))
	if err != nil {
		return err
	}
	if err = r.acquire(ctx, raw, 0); err != nil {
		return err
	}
	owned, tx, done, err := applicationSessionSQLBorrowV1(ctx, r.session.state, true)
	if err != nil {
		return err
	}
	defer done()
	retained, err := presignexecute.LoadRetainedAssetsV1(owned, tx, org, p.DocumentID)
	if err != nil {
		return err
	}
	x := retained.Execution().Snapshot()
	d := x.Document
	publication := retained.Publication()
	if x.ID != p.ExecutionID || retained.Execution().Commitment() != p.ExecutionSHA256 || x.OrgID != org || d.ID != p.DocumentID || d.SenderID != sender ||
		!preSignSameTemplateV1(d.Template, p.Template) || d.Materialization.ID != materialization || d.Materialization.Revision != revision || d.Materialization.SourceCommitment != source ||
		publication.RetentionCompletedAt.IsZero() || publication.State == "retaining" {
		return presignregistry.ErrConflict
	}
	return nil
}

// Committed original M79/link recovery does not acquire a new grant, require a
// still-approved template or re-admit the prior terminal source. Real original
// session authorization is held by the caller before this fixed native read.
func (r *ApplicationHTMLAuthoringReaderV1) ReadPreSignSupersessionRequestV1(ctx context.Context, user, request uuid.UUID, inputSHA string) (PreSignSupersessionViewV1, error) {
	out := PreSignSupersessionViewV1{SchemaVersion: 1, RequestID: request, State: "unconfirmed"}
	if r == nil || r.self != r || user == uuid.Nil || request == uuid.Nil {
		return out, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) {
		return out, ErrHTMLAuthoringReadV1
	}
	if err := r.acquire(ctx, 4096, 4096); err != nil {
		return out, err
	}
	db := &applicationOwnedDBTXV1{session: r.session.state}
	var digest []byte
	err := db.QueryRow(ctx, `SELECT h.input_digest,s.prior_execution_id,s.prior_document_id,s.document_id,h.html_source_commitment
  FROM html_document_creation_requests h JOIN presign_supersessions_v1 s
  ON s.org_id=h.org_id AND s.actor_user_id=h.actor_user_id AND s.request_id=h.request_id AND s.document_id=h.original_document_id
  WHERE h.org_id=$1 AND h.actor_user_id=$2 AND h.request_id=$3`, r.session.state.org, user, request).
		Scan(&digest, &out.PriorExecutionID, &out.PriorDocumentID, &out.DocumentID, &out.SourceCommitment)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if len(digest) != 32 || out.DocumentID == uuid.Nil || out.PriorDocumentID == uuid.Nil || out.PriorExecutionID == uuid.Nil {
		return out, ErrHTMLAuthoringReadV1
	}
	if _, ok := preSignSourceDigestV1(out.SourceCommitment); !ok {
		return out, ErrHTMLAuthoringReadV1
	}
	if inputSHA != "" && hex.EncodeToString(digest) != inputSHA {
		return out, presignregistry.ErrConflict
	}
	out.State = "committed"
	return out, nil
}

// Earlier author rechecks see no M79 row and can only validate the parent.
// After real birth the same callback obtains actual public facts for one fixed
// audit, then seals its exact event ID/link before the SAME COMMIT.
func (r *ApplicationHTMLAuthoringReaderV1) ReadPreSignSupersessionBirthV1(ctx context.Context, user, request uuid.UUID, inputSHA string, p PreSignSupersessionParentV1, template uuid.UUID) (PreSignSupersessionBirthV1, bool, error) {
	var out PreSignSupersessionBirthV1
	prior, err := r.ReadPreSignSupersessionRequestV1(ctx, user, request, inputSHA)
	if err != nil {
		return out, false, err
	}
	if prior.State == "committed" {
		return out, false, nil
	}
	if err = r.CheckPreSignSupersessionParentV1(ctx, user, p, template); err != nil {
		return out, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) {
		return out, false, ErrHTMLAuthoringReadV1
	}
	input, ok := preSignSourceDigestV1(inputSHA)
	if !ok {
		return out, false, presignregistry.ErrInvalid
	}
	db := &applicationOwnedDBTXV1{session: r.session.state}
	var actualInput []byte
	err = db.QueryRow(ctx, `SELECT original_document_id,input_digest,html_source_commitment FROM html_document_creation_requests
  WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3 AND template_id=$4`, r.session.state.org, user, request, template).
		Scan(&out.DocumentID, &actualInput, &out.SourceCommitment)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if out.DocumentID == p.DocumentID || out.DocumentID != r.session.state.document || !bytes.Equal(input, actualInput) || out.SourceCommitment == p.SourceCommitment {
		return out, false, presignregistry.ErrConflict
	}
	if _, ok := preSignSourceDigestV1(out.SourceCommitment); !ok {
		return out, false, ErrHTMLAuthoringReadV1
	}
	out.PriorExecutionID = p.ExecutionID
	out.PriorExecutionSHA256 = p.ExecutionSHA256
	out.PriorDocumentID = p.DocumentID
	out.RequestID = request
	return out, true, nil
}

func (r *ApplicationHTMLAuthoringReaderV1) SealPreSignSupersessionBirthV1(ctx context.Context, user, request, event uuid.UUID, inputSHA string, p PreSignSupersessionParentV1, template uuid.UUID) error {
	if event == uuid.Nil {
		return ErrHTMLAuthoringReadV1
	}
	facts, ready, err := r.ReadPreSignSupersessionBirthV1(ctx, user, request, inputSHA, p, template)
	if err != nil || !ready {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) {
		return ErrHTMLAuthoringReadV1
	}
	db := &applicationOwnedDBTXV1{session: r.session.state}
	tag, err := db.Exec(ctx, `INSERT INTO presign_supersessions_v1(org_id,prior_execution_id,prior_document_id,document_id,request_id,actor_user_id,audit_event_id)
  VALUES($1,$2,$3,$4,$5,$6,$7)`, r.session.state.org, facts.PriorExecutionID, facts.PriorDocumentID, facts.DocumentID, request, user, event)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return presignregistry.ErrConflict
	}
	return nil
}
