// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WithStaffPreSignV1 keeps original native models through the actual HTTP
// writer. ErrNoRows means absent execution only; explicit malformed or sealing
// relations refuse, so a delegated document never falls back to its base PDF.
func (s *PreSignServiceV1) WithStaffPreSignV1(ctx context.Context, a presignregistry.ExecutionActorV1, document uuid.UUID, pdf bool, consume func(*generated.Document, *presignexecute.DocumentViewV1, []byte) error) error {
	if !s.validV1() || consume == nil {
		return presignregistry.ErrUnavailable
	}
	o, err := s.Send.newOwnedSendOperationV1(ctx, a.OrgID(), document)
	if err != nil {
		return err
	}
	defer o.closeConsumerV1()
	var work *pdfadmission.ApplicationHTMLSendWorkV1
	var models *pdfadmission.HTMLSendModelsV1
	var retained presignexecute.RetainedAssetsV1
	read := func(c context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		if _, err := q.GetOrgForOwnerMutation(c, a.OrgID()); err != nil {
			return err
		}
		u, err := p.work.ReadActorV1(c, a.UserID())
		if err != nil {
			return err
		}
		if err = a.AuthorizeRecoveryV1(c, tx, u); err != nil {
			return err
		}
		if _, err = p.work.StateV1(c); err != nil {
			return err
		}
		m, err := p.work.ReadModelsV1(c)
		if err != nil {
			return err
		}
		if err = p.work.AcquirePresignEvidenceV1(c); err != nil {
			return err
		}
		r, err := p.work.ReadRetainedPreSignV1(c)
		if err != nil {
			return err
		}
		if retained.Execution().Commitment() != "" && (retained.Execution().Commitment() != r.Execution().Commitment() || retained.Assets().Commitment() != r.Assets().Commitment()) {
			return presignexecute.ErrIntegrity
		}
		work = p.work
		models = m
		retained = r
		return a.AuthorizeRecoveryV1(c, tx, u)
	}
	if err = o.phaseV1(pdfadmission.HTMLPreSignReadV1, read); err != nil {
		return err
	}
	publication := retained.Publication().State
	if publication == "retaining" {
		publication = "sealing"
	}
	if models.Document.Status == "completed" {
		publication = "completed"
	}
	x := retained.Execution().Snapshot()
	view := &presignexecute.DocumentViewV1{SchemaVersion: 1, Execution: presignexecute.ExecutionReferenceV1{ID: x.ID, SHA256: retained.Execution().Commitment()}, Publication: publication, VisiblePDFSHA256: x.VisiblePDF.Artifact.SHA256, PageCount: x.VisiblePDF.Pages}
	if !pdf {
		return consume(models.Document, view, nil)
	}
	if publication == "sealing" {
		return presignregistry.ErrUnavailable
	}
	return work.WithStaffPreSignPDFV1(ctx, s.Storage, func(raw []byte) error {
		// Recheck the actual original session/user and exact retained cohort after
		// storage waits, before a single byte is delivered to the HTTP consumer.
		if err = o.phaseV1(pdfadmission.HTMLPreSignReadV1, read); err != nil {
			return err
		}
		if retained.Publication().State != "published" && retained.Publication().State != "expired" {
			return presignexecute.ErrIntegrity
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return consume(models.Document, view, raw)
	})
}

func IsPreSignAbsentV1(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
