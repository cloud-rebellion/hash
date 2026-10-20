// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Server) writeHTMLTemplateOwnedV1(r *http.Request, user, org, id uuid.UUID, in htmlTemplateInput, content htmlmaster.TemplateCommitment) (result *generated.Template, closeConsumer func(), failure error) {
	authorize, err := s.sessionDraftAuthorization(r, org, user)
	if err != nil {
		return nil, nil, err
	}
	if s.Audit == nil {
		return nil, nil, pdfadmission.ErrHTMLAuthoringReadV1
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	create := id == uuid.Nil
	if create {
		id = uuid.New()
	}
	o, err := s.openHTMLAuthoringV1(ctx, org, id)
	if err != nil {
		return nil, nil, err
	}
	var writer *pdfadmission.ApplicationHTMLTemplateWriterV1
	defer func() {
		_ = o.closeSQLV1(ctx)
		if result == nil {
			if writer != nil {
				writer.CloseConsumerV1()
			}
			o.closeConsumerV1(ctx)
		}
	}()
	var pending audit.PendingEvent
	err = o.session.WithTxV1(ctx, func(ctx context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		if !create {
			current, err := o.reader.ReadTemplateForUpdateExpectedV1(ctx, id, in.ExpectedVersion)
			if errors.Is(err, pdfadmission.ErrHTMLAuthoringChangedV1) {
				return errHTMLTemplateConflict
			}
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return errTemplateNotFound
				}
				return err
			}
			if current.SourceKind != "html" || current.Version != in.ExpectedVersion {
				return errHTMLTemplateConflict
			}
		}
		guard, err := lockHTMLAuthorV1(ctx, tx, authoring.Actor{OrgID: org, UserID: user, Authorize: authorize}, false)
		if err != nil {
			return err
		}
		writer, err = o.session.NewHTMLTemplateWriterV1(ctx, pdfadmission.HTMLTemplateWriterInputV1{Name: in.Name, Master: content.MasterJSON, Defaults: content.DefaultsJSON, ContentSHA256: content.SHA256, ActorID: user})
		if err != nil {
			return err
		}
		var reader *pdfadmission.ApplicationHTMLAuthoringReaderV1
		if !create {
			reader = o.reader
		}
		result, err = writer.PersistV1(ctx, reader)
		if err != nil {
			return err
		}
		kind := audit.KindTemplateUpdated
		if create {
			kind = audit.KindTemplateCreated
		}
		pending, err = s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: org, ActorUserID: &user, Kind: kind,
			Payload: map[string]any{"template_id": result.ID, "source_kind": "html", "version": result.Version, "content_sha256": content.SHA256, "approved": false}})
		if err != nil {
			return err
		}
		return guard.Recheck(ctx)
	})
	if err != nil {
		return nil, nil, err
	}
	if err = o.session.CommitV1(ctx); err != nil {
		return nil, nil, err
	}
	s.Audit.Publish(detachHTMLCreationEventIDsV1(pending))
	return result, func() { writer.CloseConsumerV1(); o.closeConsumerV1(ctx) }, nil
}

func (s *Server) approveHTMLTemplateOwnedV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, in htmlTemplateApprovalInput, digest []byte, preview htmlTemplatePreviewReceipt) (result *generated.HtmlTemplateRevision, closeConsumer func(), failure error) {
	if s.Audit == nil {
		return nil, nil, pdfadmission.ErrHTMLAuthoringReadV1
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, actor.OrgID, id)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = o.closeSQLV1(ctx)
		if result == nil {
			o.closeConsumerV1(ctx)
		}
	}()
	var pending audit.PendingEvent
	err = o.session.WithTxV1(ctx, func(ctx context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		q := generated.New(tx)
		// Preserve original owner org -> member -> template mutation order.
		guard, err := lockHTMLAuthorV1(ctx, tx, actor, true)
		if err != nil {
			return err
		}
		t, err := o.reader.ReadTemplateForUpdateV1(ctx, id)
		if err != nil {
			return err
		}
		if t.Version != in.ExpectedVersion || hex.EncodeToString(t.HtmlContentSha256) != in.ExpectedContentSHA256 {
			return errHTMLTemplateConflict
		}
		_, current, err := o.reader.ReadTemplateRevisionV1(ctx, id, in.ExpectedVersion)
		if err != nil {
			return err
		}
		if _, err = toHTMLTemplateDetailResponseOwnedV1(ctx, o.reader, t, current); err != nil {
			if errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
				return err
			}
			return errHTMLTemplateConflict
		}
		result = current
		if !current.ApprovedBy.Valid || !current.ApprovedAt.Valid {
			result, err = q.ApproveHTMLTemplateRevision(ctx, generated.ApproveHTMLTemplateRevisionParams{TemplateID: id, OrgID: actor.OrgID, ExpectedVersion: in.ExpectedVersion, ExpectedContentSha256: digest, ApprovedBy: actor.UserID})
			if err != nil {
				return err
			}
		}
		entry := audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, Kind: audit.KindTemplateUpdated, Payload: map[string]any{
			"template_id": id, "source_kind": "html", "version": result.Version, "content_sha256": in.ExpectedContentSHA256, "approved": true,
			"preview_id": preview.PreviewID, "preview_pdf_sha256": preview.PDFSHA256, "preview_materialization_sha256": preview.MaterializationSHA256,
			"preview_page_count": preview.PageCount, "previewed_by": preview.ReviewerID, "previewed_at": preview.IssuedAt}}
		if entry.OrgID != actor.OrgID || entry.ActorUserID == nil || *entry.ActorUserID != actor.UserID {
			return errors.New("owner mutation audit identity mismatch")
		}
		pending, err = s.Audit.LogTx(ctx, tx, entry)
		if err != nil {
			return err
		}
		return guard.Recheck(ctx)
	})
	if err != nil {
		return nil, nil, err
	}
	if err = o.session.CommitV1(ctx); err != nil {
		return nil, nil, err
	}
	s.Audit.Publish(detachHTMLCreationEventIDsV1(pending))
	return result, func() { o.closeConsumerV1(ctx) }, nil
}
