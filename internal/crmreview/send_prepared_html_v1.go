// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package crmreview

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type PreparedHTMLSendReadsV1 interface {
	DocumentHasCRMBindings(context.Context, generated.DocumentHasCRMBindingsParams) (bool, error)
	ListCRMMappingBindingsForShare(context.Context, generated.ListCRMMappingBindingsForShareParams) ([]*generated.DocumentVariableBinding, error)
	GetDocumentCRMMappingReviewForShare(context.Context, generated.GetDocumentCRMMappingReviewForShareParams) (*generated.DocumentCrmMappingReview, error)
	GetCRMConnectionByOrgForShare(context.Context, uuid.UUID) (*generated.CrmConnection, error)
}

// This fixed pure continuation pauses ONLY where original ReviewMatches would
// call ContentCommitment. Prior review/binding/account reads and failures have
// already happened exactly once in their original order. The native owner can
// then fund/drive actual source validation before ResumeV1; no callback, caller
// digest, SQL/work admission or current-row authority is installed here.
type PreparedHTMLSendCheckV1 struct {
	self                       *PreparedHTMLSendCheckV1
	ctx                        context.Context
	q                          PreparedHTMLSendReadsV1
	document                   *generated.Document
	report                     []resolver.ResolveReport
	sorted                     []*generated.DocumentVariableBinding
	review                     *generated.DocumentCrmMappingReview
	now                        time.Time
	needsContent, done, closed bool
	failure                    error
}

func BeginPreparedHTMLSendCheckV1(ctx context.Context, q PreparedHTMLSendReadsV1, doc *generated.Document, reports []resolver.ResolveReport) (*PreparedHTMLSendCheckV1, error) {
	if q == nil {
		return nil, ErrReviewRequired
	}
	return beginPreparedHTMLSendCheckV1(ctx, q, doc, reports, time.Now())
}
func (s *PreparedHTMLSendCheckV1) NeedsContentV1() (bool, error) {
	if s == nil || s.self != s || s.closed {
		return false, ErrReviewRequired
	}
	return s.needsContent && !s.done, s.failure
}
func (s *PreparedHTMLSendCheckV1) ResumeV1(prepared *htmlsource.RevisionValidationV1) error {
	return s.resumeForSendV1(prepared, nil)
}
func (s *PreparedHTMLSendCheckV1) ResumeBlocksV1(prepared *htmlsource.RevisionValidationV1, admission blocks.ConditionalSendAdmissionV1) error {
	return s.resumeForSendV1(prepared, admission)
}
func (s *PreparedHTMLSendCheckV1) resumeForSendV1(prepared *htmlsource.RevisionValidationV1, admission blocks.ConditionalSendAdmissionV1) error {
	if s == nil || s.self != s || s.closed {
		return ErrReviewRequired
	}
	if s.done {
		return s.failure
	}
	s.done = true
	s.failure = ErrReviewRequired
	if s.needsContent {
		if prepared == nil || !prepared.MatchesDocumentV1(s.document) {
			return s.failure
		}
		var content string
		var err error
		if s.document.SourceKind == "blocks" && len(s.document.HtmlSourceJson) == 0 {
			content, err = ContentCommitmentForSendV1(s.document, admission)
		} else {
			content, err = prepared.CommitmentV1()
		}
		if err != nil || s.review == nil || s.review.ContentCommitment != content {
			return s.failure
		}
	}
	s.failure = s.resumeReportsV1()
	return s.failure
}
func (s *PreparedHTMLSendCheckV1) CloseV1() {
	if s == nil {
		return
	}
	s.closed = true
	s.ctx = nil
	s.q = nil
	s.document = nil
	s.report = nil
	s.sorted = nil
	s.review = nil
	s.failure = nil
}

func preparedHTMLReviewUntilContentV1(doc *generated.Document, bindings []*generated.DocumentVariableBinding, review *generated.DocumentCrmMappingReview, conn *generated.CrmConnection) (bool, bool, error) {
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil {
		return false, false, ErrInvalid
	}
	sorted, err := sortedBindings(bindings)
	if err != nil {
		return false, false, err
	}
	count := 0
	for _, row := range sorted {
		if row.DocumentID != doc.ID {
			return false, false, ErrInvalid
		}
		if crmKind(row.SourceKind) {
			count++
		}
	}
	if review == nil {
		return count == 0, false, nil
	}
	if !validReview(doc, review) {
		return false, false, ErrInvalid
	}
	digest, err := CRMSemanticDigest(sorted)
	if err != nil {
		return false, false, err
	}
	if count == 0 {
		return !review.HasMappings && review.BindingDigest == digest, false, nil
	}
	if !review.HasMappings || review.BindingDigest != digest || conn == nil || conn.OrgID != doc.OrgID || conn.Status != "active" ||
		conn.ID != uuid.UUID(review.ConnectionID.Bytes) || conn.Generation != review.ConnectionGeneration.Int64 || conn.Origin != review.Origin ||
		conn.CrmTeamID != review.CrmTeamID || conn.CrmUserID != review.CrmUserID {
		return false, false, nil
	}
	return true, true, nil
}
func beginPreparedHTMLSendCheckV1(ctx context.Context, q PreparedHTMLSendReadsV1, doc *generated.Document, reports []resolver.ResolveReport, now time.Time) (*PreparedHTMLSendCheckV1, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if q == nil || doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || doc.Status != "draft" {
		return nil, ErrReviewRequired
	}
	review, err := q.GetDocumentCRMMappingReviewForShare(ctx, generated.GetDocumentCRMMappingReviewForShareParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		review = nil
	} else if err != nil {
		return nil, err
	}
	hasCRM, err := q.DocumentHasCRMBindings(ctx, generated.DocumentHasCRMBindingsParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
	}
	// An exact full-ledger EXISTS, under the caller's parent lock, permits
	// ordinary manual documents of any existing ledger size. A retained mapped
	// review still cannot be bypassed by deleting every CRM binding.
	if !hasCRM && (review == nil || !review.HasMappings) {
		matches, err := ReviewMatches(doc, nil, review, nil)
		if err != nil || !matches {
			return nil, ErrReviewRequired
		}
		for _, entry := range reports {
			if crmKind(entry.SourceKind) || entry.CRMObservation != nil {
				return nil, ErrReviewRequired
			}
		}
		state := &PreparedHTMLSendCheckV1{done: true}
		state.self = state
		return state, ctx.Err()
	}
	bindings, err := q.ListCRMMappingBindingsForShare(ctx, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
	}
	sorted, err := sortedBindings(bindings)
	if err != nil {
		return nil, ErrReviewRequired
	}
	var conn *generated.CrmConnection
	if review != nil && review.HasMappings {
		conn, err = q.GetCRMConnectionByOrgForShare(ctx, doc.OrgID)
		if errors.Is(err, pgx.ErrNoRows) {
			conn = nil
		} else if err != nil {
			return nil, err
		}
	}

	matches, needsContent, err := preparedHTMLReviewUntilContentV1(doc, sorted, review, conn)
	if err != nil || !matches {
		return nil, ErrReviewRequired
	}
	state := &PreparedHTMLSendCheckV1{ctx: ctx, q: q, document: clonePreparedHTMLReviewDocumentV1(doc), report: resolver.CloneSendReportsV1(reports), sorted: clonePreparedHTMLReviewBindingsV1(sorted), now: now, needsContent: needsContent}
	state.self = state
	if review != nil {
		copy := *review
		state.review = &copy
	}
	if !needsContent {
		state.done = true
		state.failure = state.resumeReportsV1()
		if state.failure != nil {
			err := state.failure
			state.CloseV1()
			return nil, err
		}
	}
	return state, nil
}
func (s *PreparedHTMLSendCheckV1) resumeReportsV1() error {
	ctx, q, doc, reports, sorted, now := s.ctx, s.q, s.document, s.report, s.sorted, s.now
	crm := make(map[string]*generated.DocumentVariableBinding)
	for _, binding := range sorted {
		if crmKind(binding.SourceKind) {
			crm[binding.VariableName] = binding
		}
	}
	if len(crm) == 0 {
		for _, entry := range reports {
			if crmKind(entry.SourceKind) || entry.CRMObservation != nil {
				return ErrReviewRequired
			}
		}
		return ctx.Err()
	}
	values, err := blocks.ParseVariableValues(doc.VariablesJson)
	if err != nil {
		return ErrReviewRequired
	}
	seen := make(map[string]bool, len(crm))
	for _, entry := range reports {
		if !crmKind(entry.SourceKind) {
			if entry.CRMObservation != nil {
				return ErrReviewRequired
			}
			continue
		}
		binding := crm[entry.Variable]
		value, present := values[entry.Variable]
		if binding == nil || seen[entry.Variable] || !present || value != entry.Value || binding.SourceKind != entry.SourceKind || binding.SourceRef != entry.SourceRef || binding.SourcePath != entry.SourcePath ||
			resolver.ValidateFreshCRMReport(entry, doc.OrgID, doc.ID, now) != nil {
			return ErrReviewRequired
		}
		seen[entry.Variable] = true
	}
	if len(seen) != len(crm) {
		return ErrReviewRequired
	}
	if err := resolver.CheckCRMReports(ctx, q, doc.OrgID, reports); err != nil {
		return ErrReviewRequired
	}
	return ctx.Err()
}

func clonePreparedHTMLReviewBindingsV1(in []*generated.DocumentVariableBinding) []*generated.DocumentVariableBinding {
	if in == nil {
		return nil
	}
	out := make([]*generated.DocumentVariableBinding, len(in))
	for i, b := range in {
		if b != nil {
			copy := *b
			copy.VariableName = strings.Clone(b.VariableName)
			copy.SourceKind = strings.Clone(b.SourceKind)
			copy.SourceRef = strings.Clone(b.SourceRef)
			copy.SourcePath = strings.Clone(b.SourcePath)
			copy.Fallback = strings.Clone(b.Fallback)
			copy.LastValue = strings.Clone(b.LastValue)
			copy.LastError = strings.Clone(b.LastError)
			out[i] = &copy
		}
	}
	return out
}
func clonePreparedHTMLReviewDocumentV1(in *generated.Document) *generated.Document {
	if in == nil {
		return nil
	}
	out := *in
	out.Name = strings.Clone(in.Name)
	out.Status = strings.Clone(in.Status)
	out.RoutingMode = strings.Clone(in.RoutingMode)
	out.SourceKind = strings.Clone(in.SourceKind)
	out.BlocksJson = bytes.Clone(in.BlocksJson)
	out.VariablesJson = bytes.Clone(in.VariablesJson)
	out.RenderedPdfKey.String = strings.Clone(in.RenderedPdfKey.String)
	out.RenderedPdfSha = bytes.Clone(in.RenderedPdfSha)
	out.PdfStorageKey.String = strings.Clone(in.PdfStorageKey.String)
	out.PdfSha256 = bytes.Clone(in.PdfSha256)
	out.FinalPdfKey.String = strings.Clone(in.FinalPdfKey.String)
	out.FinalPdfSha = bytes.Clone(in.FinalPdfSha)
	out.AuditCertKey.String = strings.Clone(in.AuditCertKey.String)
	out.Metadata = bytes.Clone(in.Metadata)
	out.MetadataRedactionReport = bytes.Clone(in.MetadataRedactionReport)
	out.RoutingTier = strings.Clone(in.RoutingTier)
	out.BilingualTargetLang = strings.Clone(in.BilingualTargetLang)
	out.LawfulBasis = strings.Clone(in.LawfulBasis)
	out.DefaultLocale = strings.Clone(in.DefaultLocale)
	out.AuditPayloadKey.String = strings.Clone(in.AuditPayloadKey.String)
	out.AuditPayloadSha256 = bytes.Clone(in.AuditPayloadSha256)
	out.AuditSignatureKey.String = strings.Clone(in.AuditSignatureKey.String)
	out.AuditSignatureSha256 = bytes.Clone(in.AuditSignatureSha256)
	out.PdfStorageVersionID.String = strings.Clone(in.PdfStorageVersionID.String)
	out.RenderedPdfVersionID.String = strings.Clone(in.RenderedPdfVersionID.String)
	out.FinalPdfVersionID.String = strings.Clone(in.FinalPdfVersionID.String)
	out.AuditCertSha256 = bytes.Clone(in.AuditCertSha256)
	out.AuditCertVersionID.String = strings.Clone(in.AuditCertVersionID.String)
	out.AuditPayloadVersionID.String = strings.Clone(in.AuditPayloadVersionID.String)
	out.AuditSignatureVersionID.String = strings.Clone(in.AuditSignatureVersionID.String)
	out.Article13NoticeSchema = strings.Clone(in.Article13NoticeSchema)
	out.HtmlSourceJson = bytes.Clone(in.HtmlSourceJson)
	out.HtmlReviewedPdfSha256 = bytes.Clone(in.HtmlReviewedPdfSha256)
	out.HtmlCurrentSourceJson = bytes.Clone(in.HtmlCurrentSourceJson)
	out.HtmlEffectiveSourceCommitment.String = strings.Clone(in.HtmlEffectiveSourceCommitment.String)
	out.FitsIndexStorageKey.String = strings.Clone(in.FitsIndexStorageKey.String)
	out.FitsIndexVersionID.String = strings.Clone(in.FitsIndexVersionID.String)
	out.FitsIndexSha256 = bytes.Clone(in.FitsIndexSha256)
	out.ParticipantReportSchema = strings.Clone(in.ParticipantReportSchema)
	out.SigningAdmissionPolicy = strings.Clone(in.SigningAdmissionPolicy)
	return &out
}
