// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/crmreview"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/versions"
)

// This admission is private server state, never decoded from a client proof.
// A renderer can consume its values but cannot replace its original witnesses.
type crmMappingAdmission struct {
	source      *crmDocumentContext
	witness     CRMDocumentWitness
	observation *crmDocumentObservation
	now         func() time.Time
	response    crmDocumentResponseWitness
}

func (a *crmMappingAdmission) checkDeadline() error {
	if a == nil || a.observation == nil || a.source == nil || a.now == nil {
		return errCRMDocumentChanged
	}
	if a.observation.snapshot == nil {
		if len(a.observation.Mappings) != 0 {
			return errCRMDocumentChanged
		}
		return nil
	}
	return crmObservationDeadline(a.observation.snapshot.CompletedAt, a.now())
}

func (a *crmMappingAdmission) checkLocked(ctx context.Context, s *Server, tx pgx.Tx, actor authoring.Actor, id uuid.UUID) error {
	if err := a.checkDeadline(); err != nil {
		return err
	}
	guard, current, err := s.lockCRMDocument(ctx, tx, actor, id)
	if err != nil {
		return err
	}
	if err = a.witness.matches(current); err != nil {
		return err
	}
	if a.observation.snapshot != nil {
		if current.connection == nil || current.connection.Status != "active" || crmIdentity(current.connection) != a.observation.snapshot.Identity {
			return errCRMDocumentChanged
		}
	}
	if err = guard.Recheck(ctx); err != nil {
		return err
	}
	return a.checkDeadline()
}

// Persist the complete explicitly reviewed desired CRM membership. Other source
// bindings are retained unless the reviewer explicitly selected that variable.
// All callers hold the original draft/member/connection/ledger locks.
func (a *crmMappingAdmission) persist(ctx context.Context, s *Server, tx pgx.Tx, actor authoring.Actor, doc *generated.Document) (audit.PendingEvent, error) {
	if err := a.checkDeadline(); err != nil {
		return audit.PendingEvent{}, err
	}
	q := generated.New(tx)
	desired := map[string]crmDocumentMapping{}
	for _, m := range a.observation.Mappings {
		desired[m.Variable] = m
	}
	for _, binding := range a.source.bindings {
		_, keep := desired[binding.VariableName]
		if !keep && (binding.SourceKind == string(crmconnection.Deal) || binding.SourceKind == string(crmconnection.Contact) || binding.SourceKind == string(crmconnection.Company)) {
			if err := q.DeleteVariableBinding(ctx, generated.DeleteVariableBindingParams{DocumentID: doc.ID, VariableName: binding.VariableName}); err != nil {
				return audit.PendingEvent{}, err
			}
		}
	}
	for _, m := range a.observation.Mappings {
		if _, err := q.UpsertVariableBinding(ctx, generated.UpsertVariableBindingParams{DocumentID: doc.ID, VariableName: m.Variable, SourceKind: m.SourceKind, SourceRef: m.SourceRef, SourcePath: m.SourcePath, Fallback: ""}); err != nil {
			return audit.PendingEvent{}, err
		}
	}
	bindings, err := q.ListCRMMappingBindingsForShare(ctx, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return audit.PendingEvent{}, err
	}
	fingerprint, err := crmreview.FullBindingFingerprint(bindings)
	if err != nil {
		return audit.PendingEvent{}, err
	}
	semantic, err := crmreview.CRMSemanticDigest(bindings)
	if err != nil {
		return audit.PendingEvent{}, err
	}
	content, err := crmreview.ContentCommitment(doc)
	if err != nil {
		return audit.PendingEvent{}, err
	}
	input := generated.UpsertDocumentCRMMappingReviewParams{DocumentID: doc.ID, OrgID: actor.OrgID, ExpectedUpdatedAt: doc.UpdatedAt, HasMappings: len(a.observation.Mappings) != 0, BindingDigest: semantic, ContentCommitment: content, ReviewedBy: actor.UserID}
	if a.observation.snapshot != nil {
		identity := a.observation.snapshot.Identity
		input.ConnectionID = pgtype.UUID{Bytes: identity.ID, Valid: true}
		input.ConnectionGeneration = pgtype.Int8{Int64: identity.Generation, Valid: true}
		input.Origin = identity.Origin
		input.CrmTeamID = identity.CRMTeamID
		input.CrmUserID = identity.CRMUserID
	}
	if _, err = q.UpsertDocumentCRMMappingReview(ctx, input); errors.Is(err, pgx.ErrNoRows) {
		return audit.PendingEvent{}, errCRMDocumentChanged
	} else if err != nil {
		return audit.PendingEvent{}, err
	}
	response := a.source.response
	response.UpdatedAt = doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)
	response.BindingFingerprint = fingerprint
	if len(doc.HtmlSourceJson) != 0 {
		response.HTMLSourceCommitment, err = htmlsource.Commitment(doc)
		if err != nil {
			return audit.PendingEvent{}, err
		}
	}
	a.response = response
	// Values and provider payloads are omitted. Exact mapping/record/account and
	// body/value hashes retain lineage to this materialization without secrets.
	type appliedObservation struct {
		crmDocumentMapping
		Proof any `json:"proof"`
	}
	observations := make([]appliedObservation, 0, len(a.observation.Items))
	for _, item := range a.observation.Items {
		observations = append(observations, appliedObservation{item.crmDocumentMapping, item.CRMObservation})
	}
	return s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &doc.ID, Kind: "crm.variables.applied", Payload: map[string]any{
		"binding_fingerprint_before": a.source.response.BindingFingerprint, "binding_fingerprint_after": fingerprint, "mapping_digest": semantic, "content_commitment": content,
		"html_source_commitment": response.HTMLSourceCommitment, "html_materialization_revision": doc.HtmlCurrentMaterializationSequence.Int32,
		"pdf_sha256": toDocumentResponse(doc).PDFSHA256, "review_digest": a.observation.ReviewDigest, "has_mappings": input.HasMappings, "observations": observations,
		"assurance": "time-of-read", "human_confirmed": true, "content_changed": a.observation.ContentChanged,
	}})
}

func (s *Server) commitCRMDocumentValues(ctx context.Context, actor authoring.Actor, id uuid.UUID, admission *crmMappingAdmission) (*generated.Document, error) {
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	if err = admission.checkLocked(ctx, s, tx, actor, id); err != nil {
		return nil, err
	}
	guard, err := authoring.LockDraft(ctx, tx, actor, id)
	if err != nil {
		return nil, err
	}
	q := generated.New(tx)
	doc := guard.Document
	if admission.observation.ContentChanged {
		if doc.SourceKind != "blocks" || len(doc.HtmlSourceJson) != 0 {
			return nil, errCRMDocumentUnsupported
		}
		variables, err := json.Marshal(admission.observation.values)
		if err != nil {
			return nil, err
		}
		if _, err = q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: id, OrgID: actor.OrgID, BlocksJson: doc.BlocksJson, VariablesJson: variables}); err != nil {
			return nil, err
		}
	}
	// Always advance the parent edit witness, including mapping-only/unlink.
	updated, err := q.UpdateDraftDocumentDetailsV1(ctx, generated.UpdateDraftDocumentDetailsV1Params{ID: id, OrgID: actor.OrgID, Name: doc.Name, ExpiresAt: doc.ExpiresAt})
	if err != nil {
		return nil, err
	}
	if admission.observation.ContentChanged {
		if _, err = versions.New(q).Snapshot(ctx, versions.SnapshotInput{DocumentID: id, OrgID: actor.OrgID, Name: updated.Name, SourceKind: updated.SourceKind, BlocksJSON: updated.BlocksJson, VariablesJS: updated.VariablesJson, CreatedBy: &actor.UserID, Via: versions.ViaHuman, Summary: "Reviewed CRM information applied"}); err != nil {
			return nil, err
		}
	}
	pending, err := admission.persist(ctx, s, tx, actor, updated)
	if err != nil {
		return nil, err
	}
	if err = guard.Recheck(ctx); err != nil {
		return nil, err
	}
	if err = admission.checkDeadline(); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.Audit.Publish(pending)
	return updated, nil
}

func (s *Server) handleCRMDocumentApply(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, id, ok := s.crmDocumentActor(w, r)
	if !ok {
		return
	}
	var in struct {
		CRMMappingRequest
		ReviewedDigest string `json:"reviewed_digest"`
		Confirmed      bool   `json:"confirmed"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if decodeSignerJSON(r, &in) != nil || !in.Confirmed || !htmlPreviewSHA256(in.ReviewedDigest) {
		s.writeCRMDocumentError(w, errCRMDocumentInput)
		return
	}
	if err := in.CRMDocumentWitness.validate(actor); err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	if s.Pool == nil || s.Audit == nil || s.Versions == nil {
		s.writeCRMDocumentError(w, crmconnection.ErrNotConfigured)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	current, err := s.readCRMDocument(ctx, actor, id, &in.CRMDocumentWitness)
	if err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	observation, err := s.observeCRMDocument(ctx, current, in.Mappings)
	if err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	if !observation.CanApply || observation.ReviewDigest != in.ReviewedDigest {
		s.writeCRMDocumentError(w, errCRMDocumentChanged)
		return
	}
	admission := &crmMappingAdmission{source: current, witness: in.CRMDocumentWitness, observation: observation, now: time.Now}
	var updated *generated.Document
	var revision int32
	var pages int
	if observation.ContentChanged && len(current.doc.HtmlSourceJson) != 0 {
		if s.Storage == nil || s.Sign == nil || s.Sign.PDF == nil {
			s.writeCRMDocumentError(w, crmconnection.ErrNotConfigured)
			return
		}
		var release func()
		release, err = importguard.Shared.Acquire(actor.OrgID)
		if err != nil {
			w.Header().Set("Retry-After", "1")
			writeError(w, 429, "HTML document revision capacity exceeded")
			return
		}
		defer release()
		expected, _ := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
		input := htmlDocumentRevisionInput{ExpectedUpdatedAt: in.ExpectedUpdatedAt, ExpectedHTMLSourceCommitment: in.ExpectedHTMLSourceCommitment, Values: htmlStringMap(observation.values), Summary: "Reviewed CRM information applied"}
		updated, revision, pages, err = s.reviseHTMLDocumentWithCRM(ctx, actor, id, input, expected, admission)
	} else {
		updated, err = s.commitCRMDocumentValues(ctx, actor, id, admission)
	}
	if err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	writeJSON(w, 200, struct {
		crmDocumentResponseWitness
		Document                documentResponse `json:"document"`
		ContentChanged          bool             `json:"content_changed"`
		MappingReviewRequired   bool             `json:"mapping_review_required"`
		MaterializationRevision int32            `json:"materialization_revision,omitempty"`
		PageCount               int              `json:"page_count,omitempty"`
		ReviewRequired          bool             `json:"review_required,omitempty"`
		PlacementReset          bool             `json:"placement_reset,omitempty"`
	}{admission.response, toDocumentResponse(updated), observation.ContentChanged, false, revision, pages, revision != 0, revision != 0})
}
