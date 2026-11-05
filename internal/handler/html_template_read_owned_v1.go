// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// The original transport supplies its live authorization, never a cookie
// substitute. Success retains native source/canonical work until the caller
// closes the consumer AFTER response serialization. SQL cleanup is joined
// before return; errors return neither a response nor a usable consumer.
func (s *Server) readHTMLTemplateDetailOwnedV1(parent context.Context, org, user, id uuid.UUID, authorize auth.TransactionAuthorization) (templateResponse, func(), error) {
	response, _, closeConsumer, err := s.readHTMLTemplateSelectionOwnedV1(parent, org, user, id, authorize, htmlTemplateReadSelectionV1{})
	return response, closeConsumer, err
}

type htmlTemplateReadSelectionV1 struct {
	Version               int32
	ExpectedContentSHA256 string
}
type htmlTemplateDesignSourceResponseV1 struct {
	TemplateID           uuid.UUID                     `json:"template_id"`
	OrgID                uuid.UUID                     `json:"org_id"`
	CurrentParentVersion int32                         `json:"current_parent_version"`
	CurrentParentName    string                        `json:"current_parent_name"`
	Version              int32                         `json:"version"`
	ContentSHA256        string                        `json:"content_sha256"`
	HTMLMasterJSON       json.RawMessage               `json:"html_master_json"`
	VariablesJSON        json.RawMessage               `json:"variables_json"`
	HTMLApproval         *htmlTemplateApprovalResponse `json:"html_approval"`
	CreatedBy            uuid.UUID                     `json:"created_by"`
	CreatedAt            string                        `json:"created_at"`
}

// Only already-owned native canonical output is projected. Current parent
// identity/label and the selected immutable source/approval stay distinct.
func htmlTemplateSelectedSourceV1(parent *generated.Template, revision *generated.HtmlTemplateRevision, content htmlmaster.TemplateCommitment) (htmlTemplateDesignSourceResponseV1, error) {
	var empty htmlTemplateDesignSourceResponseV1
	if parent == nil || revision == nil || parent.ID == uuid.Nil || parent.OrgID == uuid.Nil || parent.SourceKind != "html" || revision.TemplateID != parent.ID || revision.OrgID != parent.OrgID || revision.Version < 1 || revision.Version > parent.Version || len(revision.ContentSha256) != 32 || content.SHA256 != hex.EncodeToString(revision.ContentSha256) || len(content.MasterJSON) == 0 {
		return empty, errHTMLTemplateConflict
	}
	if revision.ApprovedBy.Valid != revision.ApprovedAt.Valid || (revision.ApprovedBy.Valid && (uuid.UUID(revision.ApprovedBy.Bytes) == uuid.Nil || revision.ApprovedAt.Time.IsZero() || revision.ApprovedAt.InfinityModifier != pgtype.Finite)) {
		return empty, errHTMLTemplateConflict
	}
	approval := &htmlTemplateApprovalResponse{Version: revision.Version, ContentSHA256: content.SHA256}
	if revision.ApprovedBy.Valid {
		approval.ApprovedBy = uuid.UUID(revision.ApprovedBy.Bytes).String()
		approval.ApprovedAt = revision.ApprovedAt.Time.UTC().Format(time.RFC3339Nano)
	}
	return htmlTemplateDesignSourceResponseV1{TemplateID: parent.ID, OrgID: parent.OrgID, CurrentParentVersion: parent.Version, CurrentParentName: parent.Name, Version: revision.Version, ContentSHA256: content.SHA256, HTMLMasterJSON: content.MasterJSON, VariablesJSON: content.DefaultsJSON, HTMLApproval: approval, CreatedBy: revision.CreatedBy, CreatedAt: revision.CreatedAt.Time.UTC().Format(time.RFC3339Nano)}, nil
}

func (s *Server) readHTMLTemplateSelectionOwnedV1(parent context.Context, org, user, id uuid.UUID, authorize auth.TransactionAuthorization, selection htmlTemplateReadSelectionV1) (response templateResponse, selected htmlTemplateDesignSourceResponseV1, closeConsumer func(), failure error) {
	if parent == nil || org == uuid.Nil || user == uuid.Nil || id == uuid.Nil || authorize == nil {
		return response, selected, nil, auth.ErrMutationPermissionRevoked
	}
	if selection.Version < 0 || (selection.Version == 0 && selection.ExpectedContentSHA256 != "") || (selection.Version > 0 && !htmlPreviewSHA256(selection.ExpectedContentSHA256)) {
		return response, selected, nil, errHTMLTemplateConflict
	}
	ctx, cancel := context.WithTimeout(parent, authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, org, id)
	if err != nil {
		return response, selected, nil, htmlTemplateReadFailureV1(err)
	}
	defer func() {
		failure = errors.Join(failure, o.closeSQLV1(ctx))
		if failure != nil {
			response = templateResponse{}
			selected = htmlTemplateDesignSourceResponseV1{}
			closeConsumer = nil
			o.closeConsumerV1(ctx)
			failure = htmlTemplateReadFailureV1(failure)
		}
	}()
	failure = o.session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		q := generated.New(db)
		tx := &htmlCreationPolicyTxV1{DBTX: db, reader: o.reader}
		// This locked scalar observation supplies the current version, never a
		// caller-provided size. Native reader admission precedes either body.
		header, err := q.GetHTMLAuthoringTemplateHeaderV1(call, generated.GetHTMLAuthoringTemplateHeaderV1Params{TemplateID: id, OrgID: org})
		if err != nil {
			return err
		}
		if err = o.reader.AcquireActorV1(call, org, user, false); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			return err
		}
		member, err := q.GetUserForShare(call, generated.GetUserForShareParams{ID: user, OrgID: org})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			return err
		}
		if member == nil || member.ID != user || member.OrgID != org {
			return auth.ErrMutationPermissionRevoked
		}
		switch auth.Role(member.Role) {
		case auth.RoleViewer, auth.RoleSender, auth.RoleOwner:
		default:
			return auth.ErrMutationPermissionRevoked
		}
		copy := *member
		if err = authorize(call, tx, &copy); err != nil {
			return err
		}
		var template *generated.Template
		var revision *generated.HtmlTemplateRevision
		if selection.Version > 0 {
			if selection.Version > header.Version {
				return errHTMLTemplateConflict
			}
			template, revision, err = o.reader.ReadRetainedTemplateRevisionExpectedV1(call, id, selection.Version, selection.ExpectedContentSHA256)
			if err != nil {
				return err
			}
			retained, e := o.reader.CanonicalRetainedTemplateV1(call, id, selection.Version)
			if e != nil {
				return e
			}
			selected, err = htmlTemplateSelectedSourceV1(template, revision, retained)
		} else {
			template, revision, err = o.reader.ReadTemplateRevisionV1(call, id, header.Version)
			if err != nil {
				return err
			}
			response, err = toHTMLTemplateDetailResponseOwnedV1(call, o.reader, template, revision)
			if err == nil {
				selected, err = htmlTemplateSelectedSourceV1(template, revision, htmlmaster.TemplateCommitment{MasterJSON: response.HTMLMasterJSON, DefaultsJSON: response.VariablesJSON, SHA256: response.ContentSHA256})
			}
		}
		if err != nil {
			return err
		}

		copy = *member
		return authorize(call, tx, &copy)
	})
	if failure != nil {
		return templateResponse{}, htmlTemplateDesignSourceResponseV1{}, nil, failure
	}
	closeConsumer = func() { o.closeConsumerV1(ctx) }
	return response, selected, closeConsumer, nil
}

func htmlTemplateReadFailureV1(err error) error {
	switch {
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		return auth.ErrMutationCredentialExpired
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		return auth.ErrMutationPermissionRevoked
	case errors.Is(err, pdfadmission.ErrHTMLAuthoringChangedV1), errors.Is(err, errHTMLTemplateConflict):
		return errHTMLTemplateConflict
	case errors.Is(err, pgx.ErrNoRows):
		return errTemplateNotFound
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		// SQL, parser and connection details may contain private values. Native
		// factory/registry state still retains any unresolved physical cleanup.
		return pdfadmission.ErrHTMLAuthoringReadV1
	}
}
