// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"maps"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/jackc/pgx/v5"
)

// Private materialization seam. The interactive admission keeps its original
// purpose-separated confirmation constructor and audit bytes. API policy birth
// supplies a different, concrete protected native producer, never that receipt.
type htmlPopulationV1 interface {
	retainedInputValuesV1() map[string]string
	effectiveValues() map[string]string
	checkDeadline() error
	checkLocked(context.Context, *Server, pgx.Tx, authoring.Actor) error
	persist(context.Context, *Server, pgx.Tx, authoring.Actor, *generated.Document) (audit.PendingEvent, error)
}

func (a *crmTemplatePopulationAdmission) retainedInputValuesV1() map[string]string {
	if a == nil || a.observation == nil {
		return nil
	}
	return a.observation.values
}
func normalizeHTMLPopulationV1(p htmlPopulationV1) htmlPopulationV1 {
	switch v := p.(type) {
	case *crmTemplatePopulationAdmission:
		if v == nil {
			return nil
		}
	case *preSignCRMSourcePopulationV1:
		if v == nil {
			return nil
		}
	}
	return p
}

type preSignCRMSourcePopulationV1 struct {
	native    *pdfadmission.ApplicationPreSignCRMSourceV1
	admission auth.PreSignAPIAdmissionV1
	command   pdfadmission.PreSignAPISourceCommandV1
	template  presign.TemplatePin
	values    map[string]string
}

func (p *preSignCRMSourcePopulationV1) retainedInputValuesV1() map[string]string {
	if p == nil {
		return nil
	}
	return p.values
}
func (p *preSignCRMSourcePopulationV1) effectiveValues() map[string]string {
	if p == nil {
		return nil
	}
	return maps.Clone(p.values)
}
func (p *preSignCRMSourcePopulationV1) checkDeadline() error {
	if p == nil || p.native == nil {
		return errCRMTemplateChanged
	}
	return p.native.CheckDeadlineV1()
}
func (p *preSignCRMSourcePopulationV1) checkLocked(ctx context.Context, _ *Server, tx pgx.Tx, actor authoring.Actor) error {
	if p == nil || p.native == nil || actor.OrgID != p.admission.OrgID() || actor.UserID != p.admission.UserID() {
		return errCRMTemplateChanged
	}
	reader, err := htmlAuthoringReaderV1(tx)
	if err != nil {
		return err
	}
	return p.native.CheckLockedV1(ctx, reader)
}
func (p *preSignCRMSourcePopulationV1) persist(ctx context.Context, s *Server, tx pgx.Tx, actor authoring.Actor, doc *generated.Document) (audit.PendingEvent, error) {
	if s == nil || s.Audit == nil || p.checkLocked(ctx, s, tx, actor) != nil {
		return audit.PendingEvent{}, errCRMTemplateChanged
	}
	reader, err := htmlAuthoringReaderV1(tx)
	if err != nil {
		return audit.PendingEvent{}, err
	}
	semantic, err := p.native.PersistBindingsV1(ctx, reader, doc)
	if err != nil {
		return audit.PendingEvent{}, err
	}
	// An actual policy-authorized, time-of-read source observation. It neither
	// writes mapping-review state nor asserts human confirmation/assurance.
	event, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &doc.ID, Kind: "presign.source.crm.created", Payload: map[string]any{
		"request_id": p.command.RequestID, "executor_credential_id": p.admission.CredentialID(), "policy": p.command.Policy, "grant": p.command.Grant,
		"template_id": p.template.ID, "template_version": p.template.Version, "template_content_sha256": p.template.ContentSHA256,
		"crm_bindings_sha256": semantic, "authorization": "approved_data_policy", "assurance": "time-of-read",
	}})
	if err != nil {
		return audit.PendingEvent{}, err
	}
	if err = p.checkLocked(ctx, s, tx, actor); err != nil {
		return audit.PendingEvent{}, err
	}
	return event, nil
}
