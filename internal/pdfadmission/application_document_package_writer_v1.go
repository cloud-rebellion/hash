// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrDocumentPackageWriteV1 = errors.New("pdfadmission: attachment selection refused")

// The result is committed; retain it and reconcile cleanup, never replay.
var ErrDocumentPackageCommittedCleanupV1 = errors.New("pdfadmission: attachment committed; cleanup reconciliation required")

// Intent contains presentation choices only. Source/PDF/report pins and costs
// always come from the genuine native snapshots and exact measured objects.
type DocumentPackageAttachmentIntentV1 struct {
	Ordinal         int16
	Title, Category string
}
type DocumentPackageAttachmentResultV1 struct {
	PackageID        uuid.UUID `json:"package_id"`
	MemberDocumentID uuid.UUID `json:"member_document_id"`
	Ordinal          int16     `json:"ordinal"`
	Generation       int64     `json:"generation,string"`
	UpdatedAt        time.Time `json:"updated_at"`
	EventID          uuid.UUID `json:"event_id"`
}
type applicationDocumentPackageWriteIntentV1 struct {
	ordinal                             int16
	title, category, ip, ua, sourceKind string
	source, origin, reportSHA           [sha256.Size]byte
	materialization                     pgtype.UUID
	sequence                            pgtype.Int4
}

func documentPackageWriteLabelV1(s string, cap int, optional bool) bool {
	if optional && s == "" {
		return true
	}
	if len(s) < 1 || len(s) > cap || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}
func (s *applicationDocumentPackageOperationStateV1) prepareAttachmentV1(in DocumentPackageAttachmentIntentV1, ip, ua string) error {
	if s.draft == nil || s.draft.count >= documentpackage.MaxAnnexesV1 ||
		in.Ordinal < 1 || in.Ordinal > documentpackage.MaxAnnexesV1 ||
		!documentPackageWriteLabelV1(in.Title, documentpackage.MaxTitleBytesV1, false) ||
		!documentPackageWriteLabelV1(in.Category, documentpackage.MaxCategoryBytesV1, true) ||
		len(ip) > 64 || len(ua) > 1024 || !utf8.ValidString(ip) || !utf8.ValidString(ua) {
		return ErrDocumentPackageWriteV1
	}
	if s.draft.present && s.draft.header.DraftGeneration == math.MaxInt64 {
		return ErrDocumentPackageWriteV1
	}
	for i := 0; i < s.draft.count; i++ {
		if s.draft.rows[i].Ordinal == in.Ordinal {
			return ErrDocumentPackageWriteV1
		}
	}
	if s.snapshots[1] == nil || s.snapshots[1].document == nil || s.stages[0].selection == nil {
		return ErrDocumentPackageWriteV1
	}
	d := s.snapshots[1].document
	if len(d.MetadataRedactionReport) < 1 || len(d.MetadataRedactionReport) > 65536 {
		return ErrDocumentPackageWriteV1
	}
	coordinator, err := s.coordinatorV1()
	if err != nil {
		return err
	}
	// Covers typed state, detached choices, UUID/hex scratch and fixed audit map
	// production. Native final SQL and detached audit consumers remain additive.
	raw := 4*int64(unsafe.Sizeof(applicationDocumentPackageWriteIntentV1{})) + 65536 +
		8*int64(len(in.Title)+len(in.Category)+len(ip)+len(ua))
	loan, err := coordinator.TryAcquireV1(s.ctx, s.org, workguard.VectorV1{ParentBytes: raw})
	if err != nil {
		return err
	}
	s.selectionLoan = loan
	w := &applicationDocumentPackageWriteIntentV1{ordinal: in.Ordinal, title: strings.Clone(in.Title),
		category: strings.Clone(in.Category), ip: strings.Clone(ip), ua: strings.Clone(ua),
		sourceKind: documentpackage.SourcePDFImportV1, reportSHA: sha256.Sum256(d.MetadataRedactionReport)}
	if len(d.HtmlSourceJson) > 0 {
		source := s.stages[0].selection.state.sources[1]
		if source == nil || source.validation == nil {
			return ErrDocumentPackageWriteV1
		}
		current, e := source.validation.CommitmentV1()
		if e != nil {
			return e
		}
		origin, e := source.validation.OriginCommitmentV1()
		if e != nil {
			return e
		}
		if len(current) != 64 || len(origin) != 64 {
			return ErrDocumentPackageWriteV1
		}
		if _, e = hex.Decode(w.source[:], []byte(current)); e != nil {
			return e
		}
		if _, e = hex.Decode(w.origin[:], []byte(origin)); e != nil {
			return e
		}
		w.sourceKind = documentpackage.SourceHTMLOriginV1
		if d.HtmlCurrentMaterializationID.Valid {
			w.sourceKind = documentpackage.SourceHTMLRevisionV1
			w.materialization = d.HtmlCurrentMaterializationID
			w.sequence = d.HtmlCurrentMaterializationSequence
		}
	}
	s.selection = w
	return s.ctx.Err()
}

// SelectAttachmentV1 is a fixed one-attempt write after ReadSourcesV1. It checks
// all intent/count/ordinal/generation constraints before any provider work,
// measures root/candidate/every frozen member, and uses fresh original policy.
// appendAudit can only consume the fixed native event; no DBTX or caller pins
// cross this boundary. A missing/closed/unappended event always rolls back.
func (h *ApplicationDocumentPackageOperationV1) SelectAttachmentV1(policy DocumentPackageSourcePolicyV1,
	in DocumentPackageAttachmentIntentV1, ip, ua string,
	appendAudit func(context.Context, *ApplicationHTMLAuditEventConsumerV1) error) (out DocumentPackageAttachmentResultV1, failure error) {
	if h == nil || h.state == nil || policy == nil || appendAudit == nil {
		return out, ErrDocumentPackageWriteV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return out, err
	}
	defer s.finishV1()
	s.mu.Lock()
	if !s.initialRead || s.selectionAttempted || s.measureAttempted || s.finalAttempted {
		s.mu.Unlock()
		return out, ErrDocumentPackageWriteV1
	}
	s.selectionAttempted = true
	s.mu.Unlock()
	if err := s.prepareAttachmentV1(in, ip, ua); err != nil {
		return out, err
	}
	if err := h.measurePDFsV1(true); err != nil {
		return out, err
	}
	var event *ApplicationHTMLAuditEventConsumerV1
	committed := false
	defer func() {
		if !committed && event != nil {
			event.CloseConsumerV1()
		}
	}()
	var result DocumentPackageAttachmentResultV1
	err := h.withVerifiedSourcesV1(policy, true, func(call context.Context, db generated.DBTX, owner *ApplicationDocumentPackageSelectionV1) error {
		w := s.selection
		d := s.snapshots[1].document
		// All pointers remain privately borrowed. Actual native SQL consumer owns
		// driver bind/trigger report serialization overlaps through physical retire.
		raw := int64(16384) + 4*int64(len(d.MetadataRedactionReport)+len(d.PdfStorageKey.String)+
			len(d.PdfStorageVersionID.String)+len(w.title)+len(w.category))
		closeSQL, e := owner.state.actor.acquireOwnedRetainedBodyV1(call, raw, 8*raw+16384)
		if e != nil {
			return e
		}
		owner.state.mu.Lock()
		owner.state.closes = append(owner.state.closes, closeSQL)
		owner.state.mu.Unlock()
		q := generated.New(db)
		packageID := s.draft.header.ID
		before := s.snapshots[0].document.UpdatedAt
		generation := s.draft.header.DraftGeneration
		if !s.draft.present {
			packageID = uuid.New()
			p, e := q.CreateDocumentPackageV1(call, generated.CreateDocumentPackageV1Params{
				PackageID: packageID, DocumentID: s.ids[0], OrgID: s.org, CreatedBy: s.actor, ExpectedUpdatedAt: before})
			if e != nil {
				return e
			}
			if p == nil || p.ID != packageID || p.DocumentID != s.ids[0] || p.OrgID != s.org ||
				p.CreatedBy != s.actor || p.DraftGeneration != 1 {
				return ErrDocumentPackageWriteV1
			}
			clock, e := q.GetDocumentPackageMutationClockV1(call, generated.GetDocumentPackageMutationClockV1Params{
				PackageID: packageID, DocumentID: s.ids[0], OrgID: s.org})
			if e != nil {
				return e
			}
			if clock == nil || clock.PackageID != packageID || clock.DocumentID != s.ids[0] || clock.OrgID != s.org ||
				clock.DraftGeneration != 1 || !applicationStampV1(clock.UpdatedAt) || !clock.UpdatedAt.Time.After(before.Time) {
				return ErrDocumentPackageWriteV1
			}
			before, generation = clock.UpdatedAt, clock.DraftGeneration
		}
		params := generated.InsertOwnedDocumentAttachmentV1Params{PackageID: packageID, DocumentID: s.ids[0],
			OrgID: s.org, ExpectedGeneration: generation, ExpectedUpdatedAt: before, MemberDocumentID: s.ids[1],
			Ordinal: w.ordinal, Title: w.title, Category: w.category, PdfKey: d.PdfStorageKey.String,
			PdfVersionID: d.PdfStorageVersionID.String, PdfSha256: d.PdfSha256,
			PdfBytes: s.measured[1].Bytes, PdfPages: s.measured[1].Pages, SourceKind: w.sourceKind,
			MaterializationID: w.materialization, MaterializationSequence: w.sequence,
			PdfIntakeReport: d.MetadataRedactionReport, PdfIntakeReportSha256: w.reportSHA[:]}
		if w.sourceKind != documentpackage.SourcePDFImportV1 {
			params.SourceCommitment = w.source[:]
			params.OriginCommitment = w.origin[:]
		}
		member, e := q.InsertOwnedDocumentAttachmentV1(call, params)
		if e != nil {
			return e
		}
		if member != s.ids[1] {
			return ErrDocumentPackageWriteV1
		}
		clock, e := q.GetDocumentPackageMutationClockV1(call, generated.GetDocumentPackageMutationClockV1Params{
			PackageID: packageID, DocumentID: s.ids[0], OrgID: s.org})
		if e != nil {
			return e
		}
		if clock == nil || clock.PackageID != packageID || clock.DocumentID != s.ids[0] || clock.OrgID != s.org ||
			generation == math.MaxInt64 || clock.DraftGeneration != generation+1 ||
			!applicationStampV1(clock.UpdatedAt) || !clock.UpdatedAt.Time.After(before.Time) {
			return ErrDocumentPackageWriteV1
		}
		payload := map[string]any{"schema": "hash-attachment-selection-v1", "package_id": packageID.String(),
			"member_document_id": s.ids[1].String(), "ordinal": int(w.ordinal), "title": w.title, "category": w.category,
			"draft_generation": strconv.FormatInt(clock.DraftGeneration, 10),
			"pdf_sha256":       hex.EncodeToString(d.PdfSha256), "pdf_bytes": s.measured[1].Bytes, "pdf_pages": int(s.measured[1].Pages),
			"pdf_intake_report_sha256": hex.EncodeToString(w.reportSHA[:]), "source_kind": w.sourceKind}
		if w.sourceKind != documentpackage.SourcePDFImportV1 {
			payload["source_commitment"] = hex.EncodeToString(w.source[:])
			payload["origin_commitment"] = hex.EncodeToString(w.origin[:])
			if w.materialization.Valid {
				payload["materialization_id"] = uuid.UUID(w.materialization.Bytes).String()
				payload["materialization_sequence"] = int(w.sequence.Int32)
			}
		}
		event, e = owner.state.session.NewHTMLAuditEventV1(call, HTMLAuditDocumentAttachmentAddedV1, s.org, s.ids[0],
			pgtype.UUID{}, pgtype.UUID{Bytes: s.actor, Valid: true}, HTMLAuditDocumentAttachmentAddedV1.KindV1(), w.ip, w.ua, payload)
		if e != nil {
			return e
		}
		if e = appendAudit(call, event); e != nil {
			return e
		}
		event.mu.Lock()
		appended := event.used && event.attempted && event.eventID != uuid.Nil && !event.closed
		id := event.eventID
		event.mu.Unlock()
		if !appended {
			return ErrDocumentPackageWriteV1
		}
		result = DocumentPackageAttachmentResultV1{PackageID: packageID, MemberDocumentID: s.ids[1], Ordinal: w.ordinal,
			Generation: clock.DraftGeneration, UpdatedAt: clock.UpdatedAt.Time, EventID: id}
		return call.Err()
	})
	// Physical cleanup is independent of an acknowledged COMMIT. Preserve
	// committed identity/publication authority even when its cleanup join errs.
	if h.CommitAcknowledgedV1() {
		committed = true
		if err != nil {
			return result, errors.Join(ErrDocumentPackageCommittedCleanupV1, err)
		}
		return result, nil
	}
	return out, errors.Join(ErrDocumentPackageWriteV1, err)
}
