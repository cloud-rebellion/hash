// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"sort"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/crmreview"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type CRMTemplatePopulationInput struct {
	CRMTemplateWitness
	Mappings       []crmDocumentMapping `json:"mappings"`
	ReviewedDigest string               `json:"reviewed_digest"`
	ReviewReceipt  string               `json:"review_receipt"`
	Confirmed      bool                 `json:"confirmed"`
}

// This state originates only from validated purpose-separated confirmation and
// an independent protected server read. Client proof DTOs cannot create it.
type crmTemplatePopulationAdmission struct {
	source      *crmTemplateContext
	witness     CRMTemplateWitness
	candidate   CRMTemplateCandidate
	receipt     crmTemplateReceipt
	observation *crmTemplateObservation
	now         func() time.Time
}

func crmTemplateCandidateFor(in htmlDocumentInput) CRMTemplateCandidate {
	return CRMTemplateCandidate{Name: in.Name, Values: maps.Clone(in.Values), Sections: maps.Clone(in.Sections), ExpiresAt: in.ExpiresAt}
}

func (s *Server) prepareCRMTemplatePopulation(ctx context.Context, r *http.Request, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput) (*crmTemplatePopulationAdmission, error) {
	population := in.CRMPopulation
	if population == nil {
		return nil, nil
	}
	if in.RequestID == uuid.Nil || !population.Confirmed || !htmlPreviewSHA256(population.ReviewedDigest) ||
		in.ExpectedTemplateVersion != population.ExpectedTemplateVersion || in.ExpectedTemplateContentSHA256 != population.ExpectedTemplateContentSHA256 {
		return nil, errCRMTemplateInput
	}
	if err := population.CRMTemplateWitness.validate(actor); err != nil {
		return nil, err
	}
	candidate := crmTemplateCandidateFor(in)
	if err := candidate.validate(time.Now()); err != nil {
		return nil, err
	}
	receipt, err := s.validateCRMTemplateReceipt(r, actor, templateID, population.CRMTemplateWitness, candidate, population.Mappings, population.ReviewedDigest, population.ReviewReceipt)
	if err != nil {
		return nil, err
	}
	current, err := s.readCRMTemplate(ctx, actor, templateID, in.ExpectedTemplateVersion, in.ExpectedTemplateContentSHA256, &population.CRMTemplateWitness)
	if err != nil {
		return nil, err
	}
	observation, err := s.observeCRMTemplate(ctx, current, candidate, population.Mappings)
	if err != nil {
		return nil, err
	}
	if !observation.CanCreate || observation.ReviewDigest != population.ReviewedDigest {
		return nil, errCRMTemplateChanged
	}
	admission := &crmTemplatePopulationAdmission{source: current, witness: population.CRMTemplateWitness, candidate: candidate,
		receipt: receipt, observation: observation, now: time.Now}
	var identity *crmconnection.Identity
	if observation.snapshot != nil {
		identity = &observation.snapshot.Identity
	}
	if err = s.recheckCRMTemplateObservation(ctx, actor, templateID, population.CRMTemplateWitness, identity, observation.observationAt); err != nil {
		return nil, err
	}
	if err = admission.checkDeadline(); err != nil {
		return nil, err
	}
	return admission, nil
}

func (a *crmTemplatePopulationAdmission) effectiveValues() map[string]string {
	if a == nil || a.observation == nil {
		return nil
	}
	return maps.Clone(a.observation.values)
}

func (a *crmTemplatePopulationAdmission) checkDeadline() error {
	if a == nil || a.source == nil || a.observation == nil || a.now == nil || !a.observation.CanCreate ||
		a.observation.ReviewDigest != a.receipt.ReviewDigest || a.observation.candidateSHA != a.receipt.CandidateSHA256 ||
		!crmTemplateSameWitness(a.witness, a.receipt.CRMTemplateWitness) || a.receipt.TemplateID != a.source.response.TemplateID || a.witness.matches(a.source) != nil {
		return errCRMTemplateChanged
	}
	now := a.now()
	if a.receipt.validate(now) != nil || crmObservationDeadline(a.observation.observationAt, now) != nil {
		return errCRMTemplateChanged
	}
	if a.receipt.HasMappings {
		if a.observation.snapshot == nil || len(a.observation.Mappings) == 0 || a.observation.snapshot.Identity.ID.String() != a.receipt.ExpectedConnectionID ||
			a.observation.snapshot.Identity.Generation <= 0 || a.observation.snapshot.Identity.Origin != a.receipt.Origin ||
			a.observation.snapshot.Identity.CRMTeamID != a.receipt.CRMTeamID || a.observation.snapshot.Identity.CRMUserID != a.receipt.CRMUserID ||
			a.observation.snapshot.Identity.OrgID != a.receipt.ExpectedOrgID {
			return errCRMTemplateChanged
		}
		generation, err := crmGeneration(a.receipt.ExpectedConnectionGeneration, false)
		if err != nil || a.observation.snapshot.Identity.Generation != generation ||
			!a.observation.snapshot.CompletedAt.Equal(a.observation.observationAt) {
			return errCRMTemplateChanged
		}
	} else if a.observation.snapshot != nil || len(a.observation.Mappings) != 0 {
		return errCRMTemplateChanged
	}
	return a.candidate.validate(now)
}

// The final mutation caller first holds the organization quota lock. Preparation
// rechecks use a short read transaction without a quota lock. This method locks
// the saved template/revision, member/original credential and connection;
// no external I/O runs here.
// Call both before creating rows and after every transactional audit.
func (a *crmTemplatePopulationAdmission) checkLocked(ctx context.Context, s *Server, tx pgx.Tx, actor authoring.Actor) error {
	if err := a.checkDeadline(); err != nil {
		return err
	}
	if actor.OrgID != a.witness.ExpectedOrgID || actor.UserID != a.witness.ExpectedUserID {
		return errCRMTemplateChanged
	}
	guard, current, err := s.lockCRMTemplate(ctx, tx, actor, a.source.response.TemplateID, a.witness.ExpectedTemplateVersion, a.witness.ExpectedTemplateContentSHA256)
	if err != nil {
		return err
	}
	if err = a.witness.matches(current); err != nil {
		return err
	}
	if !bytes.Equal(current.content.MasterJSON, a.source.content.MasterJSON) || !bytes.Equal(current.content.DefaultsJSON, a.source.content.DefaultsJSON) {
		return errCRMTemplateChanged
	}
	if a.observation.snapshot != nil && (current.connection == nil || current.connection.Status != "active" || crmIdentity(current.connection) != a.observation.snapshot.Identity) {
		return errCRMTemplateChanged
	}
	if err = guard.Recheck(ctx); err != nil {
		return err
	}
	return a.checkDeadline()
}

func (a *crmTemplatePopulationAdmission) validateDocument(doc *generated.Document, actor authoring.Actor) error {
	if err := a.checkDeadline(); err != nil {
		return err
	}
	if doc == nil || doc.OrgID != actor.OrgID || doc.SenderID != actor.UserID || doc.Status != "draft" || doc.Name != a.candidate.Name ||
		!doc.TemplateID.Valid || uuid.UUID(doc.TemplateID.Bytes) != a.source.response.TemplateID ||
		!doc.HtmlCurrentMaterializationID.Valid || !doc.HtmlCurrentMaterializationSequence.Valid || doc.HtmlCurrentMaterializationSequence.Int32 != 1 ||
		doc.HtmlReviewedBy.Valid || doc.HtmlReviewedAt.Valid || doc.HtmlReviewedMaterializationID.Valid || len(doc.HtmlReviewedPdfSha256) != 0 {
		return errCRMTemplateChanged
	}
	if a.candidate.ExpiresAt == "" {
		if doc.ExpiresAt.Valid {
			return errCRMTemplateChanged
		}
	} else {
		expires, err := time.Parse(time.RFC3339, a.candidate.ExpiresAt)
		if err != nil || !doc.ExpiresAt.Valid || !doc.ExpiresAt.Time.Equal(expires) {
			return errCRMTemplateChanged
		}
	}
	input, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		return errCRMTemplateChanged
	}
	// PostgreSQL JSONB may change object key order and spacing. Compare the
	// established canonical template, never raw stored JSON spelling.
	canonical, err := htmlmaster.CanonicalTemplate(input.MasterJSON, input.DefaultVarsJSON)
	if err != nil || canonical.SHA256 != a.source.content.SHA256 || input.TemplateID != a.source.response.TemplateID || input.TemplateVersion != a.source.response.TemplateVersion ||
		input.TemplateContentSHA256 != a.source.response.TemplateContentSHA256 || input.TemplateApprovedBy != a.source.response.TemplateApprovedBy ||
		!input.TemplateApprovedAt.Equal(a.source.revision.ApprovedAt.Time) || !bytes.Equal(canonical.MasterJSON, a.source.content.MasterJSON) ||
		!bytes.Equal(canonical.DefaultsJSON, a.source.content.DefaultsJSON) || !maps.Equal(input.Values, a.observation.values) || !maps.Equal(input.Sections, a.candidate.Sections) {
		return errCRMTemplateChanged
	}
	return nil
}

// Invoke after source/materialization/party/field projection, in the same final
// transaction as document creation, quota enforcement and the idempotency row.
func (a *crmTemplatePopulationAdmission) persist(ctx context.Context, s *Server, tx pgx.Tx, actor authoring.Actor, doc *generated.Document) (audit.PendingEvent, error) {
	if tx == nil || s == nil || s.Audit == nil {
		return audit.PendingEvent{}, errCRMTemplateChanged
	}
	if err := a.checkLocked(ctx, s, tx, actor); err != nil {
		return audit.PendingEvent{}, err
	}
	if err := a.validateDocument(doc, actor); err != nil {
		return audit.PendingEvent{}, err
	}
	q := generated.New(tx)
	bindings, err := q.ListCRMMappingBindingsForShare(ctx, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return audit.PendingEvent{}, err
	}
	if len(bindings) != 0 {
		return audit.PendingEvent{}, errCRMTemplateChanged
	}
	for _, m := range a.observation.Mappings {
		if _, err = q.UpsertVariableBinding(ctx, generated.UpsertVariableBindingParams{DocumentID: doc.ID, VariableName: m.Variable,
			SourceKind: m.SourceKind, SourceRef: m.SourceRef, SourcePath: m.SourcePath, Fallback: ""}); err != nil {
			return audit.PendingEvent{}, err
		}
	}
	bindings, err = q.ListCRMMappingBindingsForShare(ctx, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil || len(bindings) != len(a.observation.Mappings) {
		if err != nil {
			return audit.PendingEvent{}, err
		}
		return audit.PendingEvent{}, errCRMTemplateChanged
	}
	semantic, err := crmreview.CRMSemanticDigest(bindings)
	if err != nil {
		return audit.PendingEvent{}, err
	}
	content, err := crmreview.ContentCommitment(doc)
	if err != nil {
		return audit.PendingEvent{}, err
	}
	review := generated.UpsertDocumentCRMMappingReviewParams{DocumentID: doc.ID, OrgID: actor.OrgID, ExpectedUpdatedAt: doc.UpdatedAt,
		HasMappings: len(bindings) != 0, BindingDigest: semantic, ContentCommitment: content, ReviewedBy: actor.UserID}
	if a.observation.snapshot != nil {
		identity := a.observation.snapshot.Identity
		review.ConnectionID = pgtype.UUID{Bytes: identity.ID, Valid: true}
		review.ConnectionGeneration = pgtype.Int8{Int64: identity.Generation, Valid: true}
		review.Origin, review.CrmTeamID, review.CrmUserID = identity.Origin, identity.CRMTeamID, identity.CRMUserID
	}
	if _, err = q.UpsertDocumentCRMMappingReview(ctx, review); errors.Is(err, pgx.ErrNoRows) {
		return audit.PendingEvent{}, errCRMTemplateChanged
	} else if err != nil {
		return audit.PendingEvent{}, err
	}
	if err = a.checkDeadline(); err != nil {
		return audit.PendingEvent{}, err
	}
	type observation struct {
		crmDocumentMapping
		Proof *resolver.CRMValueObservation `json:"proof"`
	}
	proofs := make([]observation, 0, len(a.observation.Items))
	for _, item := range a.observation.Items {
		proofs = append(proofs, observation{item.crmDocumentMapping, item.CRMObservation})
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &doc.ID,
		Kind: "crm.template.population.created", Payload: map[string]any{
			"template_id": a.source.response.TemplateID, "template_version": a.source.response.TemplateVersion,
			"template_content_sha256": a.source.response.TemplateContentSHA256, "template_approved_by": a.source.response.TemplateApprovedBy,
			"template_approved_at": a.source.response.TemplateApprovedAt, "confirmation_purpose": crmTemplateReceiptPurpose,
			"confirmation_id": a.receipt.ReceiptID, "review_digest": a.receipt.ReviewDigest, "candidate_sha256": a.receipt.CandidateSHA256,
			"mapping_digest": semantic, "content_commitment": content, "has_mappings": review.HasMappings,
			"pdf_sha256": toDocumentResponse(doc).PDFSHA256, "html_materialization_revision": doc.HtmlCurrentMaterializationSequence.Int32,
			"observations": proofs, "assurance": "time-of-read", "human_confirmed": true,
		}})
	if err != nil {
		return audit.PendingEvent{}, errors.Join(errHTMLCreationAudit, err)
	}
	if err = a.checkLocked(ctx, s, tx, actor); err != nil {
		return audit.PendingEvent{}, err
	}
	return pending, nil
}

// Committed replay hashes the full semantic command without the transport
// authenticator or request UUID. Renewing a receipt does not change the command;
// a changed actor, approval, account, mapping, text or reviewed value does.
func crmTemplateCreateInputDigest(actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput) (string, error) {
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || templateID == uuid.Nil || in.ExpectedTemplateVersion <= 0 || !htmlPreviewSHA256(in.ExpectedTemplateContentSHA256) {
		return "", errCRMTemplateInput
	}
	if err := in.checkExpectedActor(actor); err != nil {
		return "", err
	}
	candidateSHA, err := crmTemplateCandidateDigest(crmTemplateCandidateFor(in))
	if err != nil {
		return "", err
	}
	var population any
	if in.CRMPopulation != nil {
		p := in.CRMPopulation
		if p.CRMTemplateWitness.validate(actor) != nil || p.ExpectedTemplateVersion != in.ExpectedTemplateVersion || p.ExpectedTemplateContentSHA256 != in.ExpectedTemplateContentSHA256 ||
			!p.Confirmed || !htmlPreviewSHA256(p.ReviewedDigest) || p.Mappings == nil || len(p.Mappings) > crmconnection.MaxRecordReferences {
			return "", errCRMTemplateInput
		}
		mappings := append([]crmDocumentMapping{}, p.Mappings...)
		sort.Slice(mappings, func(i, j int) bool { return mappings[i].Variable < mappings[j].Variable })
		seen := map[string]bool{}
		refs := map[string]string{}
		for _, m := range mappings {
			kind := resolver.SourceKind(m.SourceKind)
			if seen[m.Variable] || (kind != resolver.SourceCRMDeal && kind != resolver.SourceCRMContact && kind != resolver.SourceCRMCompany) ||
				resolver.ValidateBinding(m.Variable, kind, m.SourceRef, m.SourcePath, "") != nil {
				return "", errCRMTemplateInput
			}
			if previous, exists := refs[m.SourceKind]; exists && previous != m.SourceRef {
				return "", errCRMTemplateInput
			}
			seen[m.Variable], refs[m.SourceKind] = true, m.SourceRef
		}
		witness := p.CRMTemplateWitness
		approved, _ := time.Parse(time.RFC3339Nano, witness.ExpectedTemplateApprovedAt)
		witness.ExpectedTemplateApprovedAt = approved.UTC().Format(time.RFC3339Nano)
		population = struct {
			Witness        CRMTemplateWitness   `json:"witness"`
			Mappings       []crmDocumentMapping `json:"mappings"`
			ReviewedDigest string               `json:"reviewed_digest"`
			Confirmed      bool                 `json:"confirmed"`
		}{witness, mappings, p.ReviewedDigest, p.Confirmed}
	}
	canonical, err := json.Marshal(struct {
		OrgID          uuid.UUID `json:"org_id"`
		UserID         uuid.UUID `json:"user_id"`
		TemplateID     uuid.UUID `json:"template_id"`
		Version        int32     `json:"template_version"`
		ContentSHA     string    `json:"template_content_sha256"`
		CandidateSHA   string    `json:"candidate_sha256"`
		Population     any       `json:"crm_population"`
		ExpectedOrgID  uuid.UUID `json:"expected_org_id"`
		ExpectedUserID uuid.UUID `json:"expected_user_id"`
	}{actor.OrgID, actor.UserID, templateID, in.ExpectedTemplateVersion, in.ExpectedTemplateContentSHA256, candidateSHA, population, in.ExpectedOrgID, in.ExpectedUserID})
	if err != nil {
		return "", err
	}
	return crmScalarSHA("hash.html-template-document-command.v1\x00" + string(canonical)), nil
}
