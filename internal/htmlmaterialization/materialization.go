// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package htmlmaterialization persists same-document HTML revisions. Callers
// own the parent transaction/lock, original authority, PDF I/O and compensation.
package htmlmaterialization

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrInvalid = errors.New("HTML materialization identity or history is inconsistent")

type Queries interface {
	GetCurrentHTMLDocumentMaterialization(context.Context, generated.GetCurrentHTMLDocumentMaterializationParams) (*generated.HtmlDocumentMaterialization, error)
	InsertHTMLDocumentMaterialization(context.Context, generated.InsertHTMLDocumentMaterializationParams) (*generated.HtmlDocumentMaterialization, error)
	ProjectHTMLDocumentMaterialization(context.Context, generated.ProjectHTMLDocumentMaterializationParams) (*generated.Document, error)
	CaptureHTMLMaterializationSnapshot(context.Context, generated.CaptureHTMLMaterializationSnapshotParams) (*generated.HtmlDocumentMaterializationSnapshot, error)
	ClearUnsignedHTMLMaterializationFields(context.Context, generated.ClearUnsignedHTMLMaterializationFieldsParams) (int64, error)
}

type AppendInput struct {
	SourceJSON        json.RawMessage
	PageCount         int32
	PreviousPageCount int32 // exact inspected old PDF pages, required for a legacy origin
	ActorID           uuid.UUID
	Summary           string
	// A nil report records unknown legacy provenance. It never inherits the
	// previous PDF's report when selecting a new materialization.
	MetadataRedactionReport json.RawMessage
}

// HistoricalDocument builds a read-only view of a retained artifact. It checks
// the row's normalized pins, commitment and immutable original design, and
// deliberately conveys no current human review or active ceremony authority.
func HistoricalDocument(origin *generated.Document, row *generated.HtmlDocumentMaterialization) (*generated.Document, error) {
	if origin == nil || row == nil || row.ID == uuid.Nil || row.DocumentID != origin.ID || row.OrgID != origin.OrgID {
		return nil, ErrInvalid
	}
	view := *origin
	view.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: row.ID, Valid: true}
	view.HtmlCurrentSourceJson = bytes.Clone(row.SourceJson)
	view.HtmlCurrentPageCount = pgtype.Int4{Int32: row.PageCount, Valid: true}
	view.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: row.Sequence, Valid: true}
	view.PdfStorageKey = pgtype.Text{String: row.PdfKey, Valid: true}
	view.PdfSha256 = bytes.Clone(row.PdfSha256)
	view.PdfStorageVersionID = pgtype.Text{String: row.PdfVersionID, Valid: true}
	view.MetadataRedactionReport = bytes.Clone(row.MetadataRedactionReport)
	if err := validateMaterializationReport(view.MetadataRedactionReport, row.PdfSha256, row.PageCount); err != nil {
		return nil, err
	}
	view.HtmlReviewedPdfSha256 = nil
	view.HtmlReviewedBy = pgtype.UUID{}
	view.HtmlReviewedAt = pgtype.Timestamptz{}
	view.HtmlReviewedMaterializationID = pgtype.UUID{}
	var fields struct {
		Values json.RawMessage `json:"values"`
	}
	if err := json.Unmarshal(row.SourceJson, &fields); err != nil {
		return nil, ErrInvalid
	}
	view.VariablesJson = bytes.Clone(fields.Values)
	commitment, err := htmlsource.Commitment(&view)
	if err != nil || hex.EncodeToString(row.SourceCommitment) != commitment {
		return nil, ErrInvalid
	}
	anchor, err := htmlsource.OriginCommitment(&view)
	if err != nil || hex.EncodeToString(row.OriginCommitment) != anchor {
		return nil, ErrInvalid
	}
	return &view, nil
}

// Current checks the normalized immutable row against the current projection.
// A nil result means the validated legacy origin has not yet been registered.
func Current(ctx context.Context, q Queries, doc *generated.Document) (*generated.HtmlDocumentMaterialization, error) {
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		return nil, err
	}
	if !doc.HtmlCurrentMaterializationID.Valid {
		return nil, nil
	}
	if q == nil {
		return nil, ErrInvalid
	}
	row, err := q.GetCurrentHTMLDocumentMaterialization(ctx, generated.GetCurrentHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, fmt.Errorf("current HTML materialization: %w", err)
	}
	if err := validateCurrentReadProjectionV1(doc, currentReadProjectionV1(row), commitment); err != nil {
		return nil, err
	}
	return row, nil
}

// RegisterOrigin records the unchanged original artifact. It preserves its
// exact review and fields; this is not a revision or a new signing ceremony.
func RegisterOrigin(ctx context.Context, q Queries, doc *generated.Document, pages int32, actor uuid.UUID) (*generated.Document, *generated.HtmlDocumentMaterialization, error) {
	if q == nil || doc == nil || actor == uuid.Nil || pages < 1 || pages > 500 || doc.Status != "draft" || !doc.UpdatedAt.Valid {
		return nil, nil, ErrInvalid
	}
	if doc.HtmlCurrentMaterializationID.Valid {
		row, err := Current(ctx, q, doc)
		return doc, row, err
	}
	if err := validateMaterializationReport(doc.MetadataRedactionReport, doc.PdfSha256, pages); err != nil {
		return nil, nil, err
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		return nil, nil, err
	}
	digest, _ := hex.DecodeString(commitment)
	changed, err := htmlsource.ChangedSections(doc)
	if err != nil {
		return nil, nil, err
	}
	row, err := q.InsertHTMLDocumentMaterialization(ctx, generated.InsertHTMLDocumentMaterializationParams{
		DocumentID: doc.ID, OrgID: doc.OrgID, Sequence: 1, OriginCommitment: digest, SourceJson: bytes.Clone(doc.HtmlSourceJson),
		SourceCommitment: digest, PdfKey: doc.PdfStorageKey.String, PdfSha256: bytes.Clone(doc.PdfSha256), PdfVersionID: doc.PdfStorageVersionID.String,
		PageCount: pages, Summary: "Original HTML materialization", ChangedSections: changed, CreatedBy: actor,
		MetadataRedactionReport: bytes.Clone(doc.MetadataRedactionReport),
	})
	if err != nil {
		return nil, nil, err
	}
	updated, err := q.ProjectHTMLDocumentMaterialization(ctx, generated.ProjectHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: doc.OrgID, ExpectedUpdatedAt: doc.UpdatedAt, MaterializationID: row.ID})
	return updated, row, err
}

// Append archives the old review/layout first, then clears only unsigned
// geometry and selects a fresh immutable PDF. It never commits or performs I/O.
func Append(ctx context.Context, q Queries, previous, candidate *generated.Document, in AppendInput) (*generated.Document, *generated.HtmlDocumentMaterialization, error) {
	if q == nil {
		return nil, nil, ErrInvalid
	}
	check, err := PrepareAppendValidationV1(previous, candidate, in)
	if err != nil {
		return nil, nil, err
	}
	commitment, err := htmlsource.Commitment(check)
	if err != nil {
		return nil, nil, err
	}
	beforeDigest, err := htmlsource.MaterializationDigest(previous)
	if err != nil {
		return nil, nil, err
	}
	afterDigest, err := htmlsource.MaterializationDigest(check)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	if beforeDigest == afterDigest {
		// Even identical rendered bytes require a fresh immutable intake tuple;
		// input presence is never permission to reuse the old reviewed artifact.
		if candidate.PdfStorageKey.String == previous.PdfStorageKey.String && candidate.PdfStorageVersionID.String == previous.PdfStorageVersionID.String {
			return nil, nil, ErrInvalid
		}
		input, err := htmlsource.InputForCurrent(check)
		if err != nil {
			return nil, nil, err
		}
		addition, err := htmlsource.IsOptionalEmptyAddition(previous, input)
		if err != nil {
			return nil, nil, err
		}
		if !addition {
			return nil, nil, ErrInvalid
		}
	}
	changed, err := htmlsource.ChangedSections(check)
	if err != nil {
		return nil, nil, err
	}
	current := previous
	parent, err := Current(ctx, q, current)
	if err != nil {
		return nil, nil, err
	}
	if parent == nil {
		current, parent, err = RegisterOrigin(ctx, q, current, in.PreviousPageCount, in.ActorID)
		if err != nil {
			return nil, nil, err
		}
	}
	if parent.Sequence == int32(^uint32(0)>>1) {
		return nil, nil, ErrInvalid
	}
	oldCommitment, err := htmlsource.Commitment(current)
	if err != nil {
		return nil, nil, err
	}
	oldDigest, _ := hex.DecodeString(oldCommitment)
	if _, err := q.CaptureHTMLMaterializationSnapshot(ctx, generated.CaptureHTMLMaterializationSnapshotParams{
		DocumentID: current.ID, OrgID: current.OrgID, ExpectedUpdatedAt: current.UpdatedAt, Kind: "draft_superseded", SourceCommitment: oldDigest,
		CreatedBy: pgtype.UUID{Bytes: in.ActorID, Valid: true},
	}); err != nil {
		return nil, nil, err
	}
	origin, _ := htmlsource.OriginCommitment(current)
	originDigest, _ := hex.DecodeString(origin)
	digest, _ := hex.DecodeString(commitment)
	row, err := q.InsertHTMLDocumentMaterialization(ctx, generated.InsertHTMLDocumentMaterializationParams{
		DocumentID: current.ID, OrgID: current.OrgID, Sequence: parent.Sequence + 1, ParentID: pgtype.UUID{Bytes: parent.ID, Valid: true},
		ParentCommitment: bytes.Clone(parent.SourceCommitment), OriginCommitment: originDigest, SourceJson: bytes.Clone(in.SourceJSON), SourceCommitment: digest,
		PdfKey: candidate.PdfStorageKey.String, PdfSha256: bytes.Clone(candidate.PdfSha256), PdfVersionID: candidate.PdfStorageVersionID.String,
		PageCount: in.PageCount, Summary: in.Summary, ChangedSections: changed, CreatedBy: in.ActorID,
		MetadataRedactionReport: bytes.Clone(in.MetadataRedactionReport),
	})
	if err != nil {
		return nil, nil, err
	}
	if _, err := q.ClearUnsignedHTMLMaterializationFields(ctx, generated.ClearUnsignedHTMLMaterializationFieldsParams{DocumentID: current.ID, OrgID: current.OrgID, ExpectedUpdatedAt: current.UpdatedAt}); err != nil {
		return nil, nil, err
	}
	updated, err := q.ProjectHTMLDocumentMaterialization(ctx, generated.ProjectHTMLDocumentMaterializationParams{DocumentID: current.ID, OrgID: current.OrgID, ExpectedUpdatedAt: current.UpdatedAt, MaterializationID: row.ID})
	if err != nil {
		return nil, nil, err
	}
	if _, err := Current(ctx, q, updated); err != nil {
		return nil, nil, err
	}
	return updated, row, nil
}

// CaptureRetiredCeremony must run under the same parent lock BEFORE Revise
// clears status/sent_at/recipient credentials. Legacy sources are unchanged.
func CaptureRetiredCeremony(ctx context.Context, q Queries, doc *generated.Document, actor uuid.UUID) error {
	if doc == nil || q == nil {
		return ErrInvalid
	}
	if len(doc.HtmlSourceJson) == 0 {
		return nil
	}
	if doc.Status != "changes_requested" {
		return ErrInvalid
	}
	if err := htmlsource.Validate(doc, true); err != nil {
		return err
	}
	if _, err := Current(ctx, q, doc); err != nil {
		return err
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		return err
	}
	digest, _ := hex.DecodeString(commitment)
	var creator pgtype.UUID
	if actor != uuid.Nil {
		creator = pgtype.UUID{Bytes: actor, Valid: true}
	}
	_, err = q.CaptureHTMLMaterializationSnapshot(ctx, generated.CaptureHTMLMaterializationSnapshotParams{
		DocumentID: doc.ID, OrgID: doc.OrgID, ExpectedUpdatedAt: doc.UpdatedAt, Kind: "ceremony_retired", SourceCommitment: digest, CreatedBy: creator,
	})
	return err
}
