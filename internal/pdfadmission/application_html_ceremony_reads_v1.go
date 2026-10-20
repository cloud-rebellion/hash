// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"strings"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type HTMLCeremonyWorkflowAccessV1 struct {
	DocumentID, OrgID                           uuid.UUID
	UpdatedAt, SentAt, NoticeEpochAt, ExpiresAt pgtype.Timestamptz
	NoticeCommitted, ActiveCeremony, IsEnvelope bool
	ParentEnvelopeID                            pgtype.UUID
	PDFSHA256                                   []byte
	NoticeSchemaMatchesInput                    bool
}
type HTMLCeremonyParticipantPolicyV1 struct {
	DocumentID, OrgID                           uuid.UUID
	UpdatedAt, SentAt, NoticeEpochAt, ExpiresAt pgtype.Timestamptz
	Name, LawfulBasis, NoticeSchema             string
	NoticeCommitted                             bool
}

// The fixed access is real locked metadata only. It grants no actor or mutation
// permission, and missing rows remain a real NoRows boundary for its caller.
func (w *ApplicationHTMLCeremonyWorkflowV1) ReadAccessV1(call context.Context, schema string) (HTMLCeremonyWorkflowAccessV1, error) {
	if !w.validCallV1(call) || (schema != "" && schema != article13.SchemaV1) {
		return HTMLCeremonyWorkflowAccessV1{}, ErrHTMLCeremonyWorkflowV1
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return HTMLCeremonyWorkflowAccessV1{}, err
	}
	op := w.operation.state
	row, err := q.GetHTMLCeremonyWorkflowAccessV1(call, generated.GetHTMLCeremonyWorkflowAccessV1Params{DocumentID: op.document, OrgID: op.org, ExpectedNoticeSchema: schema})
	if err != nil {
		return HTMLCeremonyWorkflowAccessV1{}, err
	}
	if row == nil || row.ID != op.document || row.OrgID != op.org || row.PolicyRawTextBytes < 0 || (len(row.PdfSha256) != 0 && len(row.PdfSha256) != 32) {
		return HTMLCeremonyWorkflowAccessV1{}, ErrHTMLCeremonyWorkflowV1
	}
	copy := *row
	copy.PdfSha256 = bytes.Clone(row.PdfSha256)
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return HTMLCeremonyWorkflowAccessV1{}, ErrHTMLCeremonyWorkflowV1
	}
	if w.access != nil {
		w.mu.Unlock()
		return HTMLCeremonyWorkflowAccessV1{}, ErrHTMLCeremonyWorkflowV1
	}
	w.access = &copy
	w.mu.Unlock()
	return HTMLCeremonyWorkflowAccessV1{DocumentID: row.ID, OrgID: row.OrgID, UpdatedAt: row.UpdatedAt, SentAt: row.SentAt, NoticeEpochAt: row.Article13NoticeEpochAt,
		ExpiresAt: row.ExpiresAt, NoticeCommitted: row.Article13NoticeEpochV61Committed, ActiveCeremony: row.IsActiveCeremony, IsEnvelope: row.IsEnvelope,
		ParentEnvelopeID: row.ParentEnvelopeID, PDFSHA256: bytes.Clone(row.PdfSha256), NoticeSchemaMatchesInput: row.NoticeSchemaMatchesInput}, nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) ReadParticipantPolicyV1(call context.Context) (*HTMLCeremonyParticipantPolicyV1, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != htmlCeremonyParticipantChangeV1 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	header := w.access
	already := w.policy != nil
	w.mu.Unlock()
	if header == nil || already {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if err := w.retainHeaderBodyV1(call, header.PolicyRawTextBytes); err != nil {
		return nil, err
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	row, err := q.ReadHTMLCeremonyParticipantPolicyV1(call, generated.ReadHTMLCeremonyParticipantPolicyV1Params{DocumentID: header.ID, OrgID: header.OrgID,
		ExpectedUpdatedAt: header.UpdatedAt, ExpectedRawTextBytes: header.PolicyRawTextBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != header.ID || row.OrgID != header.OrgID || row.UpdatedAt != header.UpdatedAt || row.SentAt != header.SentAt ||
		row.Article13NoticeEpochAt != header.Article13NoticeEpochAt || row.ExpiresAt != header.ExpiresAt || row.Article13NoticeEpochV61Committed != header.Article13NoticeEpochV61Committed {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlAuthoringSumV1(int64(len(row.Name)), int64(len(row.LawfulBasis)), int64(len(row.Article13NoticeSchema)))
	if err != nil || actual != header.PolicyRawTextBytes {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	policy := HTMLCeremonyParticipantPolicyV1{DocumentID: row.ID, OrgID: row.OrgID, UpdatedAt: row.UpdatedAt, SentAt: row.SentAt,
		NoticeEpochAt: row.Article13NoticeEpochAt, ExpiresAt: row.ExpiresAt, Name: strings.Clone(row.Name), LawfulBasis: strings.Clone(row.LawfulBasis),
		NoticeSchema: strings.Clone(row.Article13NoticeSchema), NoticeCommitted: row.Article13NoticeEpochV61Committed}
	w.mu.Lock()
	w.policy = &policy
	w.mu.Unlock()
	copy := policy
	return &copy, nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) HasCapturedEvidenceV1(call context.Context) (bool, error) {
	q, err := w.queriesV1(call)
	if err != nil {
		return false, err
	}
	op := w.operation.state
	return q.HasCapturedHTMLCeremonyEvidenceV1(call, generated.HasCapturedHTMLCeremonyEvidenceV1Params{DocumentID: op.document, OrgID: op.org})
}

// The cheap actual CR lock/open decision can run inside the original actor
// callback before document cache/body refusal. No scalable result is exposed.
func (w *ApplicationHTMLCeremonyWorkflowV1) PreflightChangeV1(call context.Context, id uuid.UUID, preflight func(bool) error) error {
	if !w.validCallV1(call) || w.operation.state.workflow != HTMLCeremonyChangeDecisionV1 || id == uuid.Nil || preflight == nil {
		return ErrHTMLCeremonyWorkflowV1
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return err
	}
	op := w.operation.state
	header, err := q.GetHTMLChangeRequestReadHeaderV1(call, generated.GetHTMLChangeRequestReadHeaderV1Params{DocumentID: op.document, OrgID: op.org, ChangeRequestID: id})
	if err != nil {
		return err
	}
	if header == nil || header.ChangeRequestID != id || header.DocumentID != op.document || header.OrgID != op.org || header.RawTextBytes < 0 {
		return ErrHTMLCeremonyWorkflowV1
	}
	if err = preflight(header.IsOpen); err != nil {
		return err
	}
	w.mu.Lock()
	if w.closed || w.changeHeader != nil {
		w.mu.Unlock()
		return ErrHTMLCeremonyWorkflowV1
	}
	copy := *header
	w.changeHeader = &copy
	w.mu.Unlock()
	return nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) ReadChangeV1(call context.Context, id uuid.UUID) (*generated.ChangeRequest, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != HTMLCeremonyChangeDecisionV1 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	header := w.changeHeader
	already := w.change != nil
	w.mu.Unlock()
	if header == nil || header.ChangeRequestID != id || already {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if err := w.retainV1(call, header.RawTextBytes, 0); err != nil {
		return nil, err
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	row, err := q.ReadHTMLChangeRequestV1(call, generated.ReadHTMLChangeRequestV1Params{DocumentID: header.DocumentID, OrgID: header.OrgID, ChangeRequestID: id, ExpectedRawTextBytes: header.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != id || row.DocumentID != header.DocumentID {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlCeremonyChangeRawV1(row)
	if err != nil || actual != header.RawTextBytes {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	copy := *row
	w.change = &copy
	w.mu.Unlock()
	return row, nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) ReadApprovalOrgV1(call context.Context) (*generated.Org, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != HTMLCeremonyChangeDecisionV1 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	op := w.operation.state
	header, err := q.GetHTMLWorkflowOrgReadHeaderV1(call, generated.GetHTMLWorkflowOrgReadHeaderV1Params{DocumentID: op.document, OrgID: op.org})
	if err != nil {
		return nil, err
	}
	if header == nil || header.DocumentID != op.document || header.OrgID != op.org || header.RawTextBytes < 0 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if err = w.retainV1(call, header.RawTextBytes, 0); err != nil {
		return nil, err
	}
	org, err := q.ReadSignerControllerV1(call, generated.ReadSignerControllerV1Params{OrgID: op.org, ExpectedRawTextBytes: header.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if org == nil || org.ID != op.org {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlAuthoringSumV1(int64(len(org.Name)), int64(len(org.Plan)), int64(len(org.ChangeApprovalMode)))
	if err != nil || actual != header.RawTextBytes {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	return org, nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) ResolveChangeV1(call context.Context, approved bool) (*generated.ChangeRequest, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != HTMLCeremonyChangeDecisionV1 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	if w.change == nil || w.resolveAttempted {
		w.mu.Unlock()
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.resolveAttempted = true
	original := *w.change
	w.mu.Unlock()
	resolution := "denied"
	if approved {
		resolution = "approved"
	}
	old, err := htmlCeremonyChangeRawV1(&original)
	if err != nil {
		return nil, err
	}
	raw, err := htmlAuthoringSumV1(old, int64(len("resolved")), int64(len(resolution)))
	if err != nil {
		return nil, err
	}
	if err = w.retainV1(call, raw, 0); err != nil {
		return nil, err
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	row, err := q.ResolveChangeRequest(call, generated.ResolveChangeRequestParams{ID: original.ID, DocumentID: original.DocumentID, Resolution: pgtype.Text{String: resolution, Valid: true}})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != original.ID || row.DocumentID != original.DocumentID {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlCeremonyChangeRawV1(row)
	if err != nil || actual > raw {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	copy := *row
	w.change = &copy
	w.mu.Unlock()
	return row, nil
}
