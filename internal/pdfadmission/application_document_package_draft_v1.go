// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrDocumentPackageDraftV1 = errors.New("pdfadmission: frozen package draft unavailable")
var ErrDocumentPackagePrivacyChangingV1 = errors.New("pdfadmission: package member privacy review changing")
var ErrDocumentPackagePendingPrivacyV1 = errors.New("pdfadmission: package member has pending privacy review")

// These are caller observations only, never row/size/permission authority.
// Zero/zero explicitly expects no existing package header.
type DocumentPackageDraftExpectedV1 struct {
	PackageID  uuid.UUID
	Generation int64
}

// No exposed application model aliases this snapshot. Both SQLC scan output
// and these detached values are funded before the ordered body query. Sources
// of selected members are deliberately neither joined nor document-locked.
type applicationDocumentPackageDraftSnapshotV1 struct {
	present bool
	header  generated.DocumentPackagesV1
	sizes   generated.GetDocumentPackageDraftSizesV1Row
	rows    [documentpackage.MaxAnnexesV1]generated.DocumentAttachmentDraftsV1
	count   int
}

// The operation holds this actual consumer pin across physical SQL retirement.
// A policy retaining/closing its selection shell cannot release the draft loans
// while the operation still uses frozen reports. This is private ownership,
// never a caller-provided release flag or an independent resource receipt.
func (w *ApplicationDocumentPackageSelectionV1) borrowDraftV1(ctx context.Context) (*applicationDocumentPackageDraftSnapshotV1, func(), error) {
	if w == nil || w.state == nil || !applicationContextV1(ctx) {
		return nil, nil, ErrDocumentPackageDraftV1
	}
	s := w.state
	s.mu.Lock()
	if s.closed.Load() || s.retired || !s.sourcesValidated || s.draft == nil {
		s.mu.Unlock()
		return nil, nil, ErrDocumentPackageDraftV1
	}
	s.active++
	draft := s.draft
	s.mu.Unlock()
	var once sync.Once
	return draft, func() { once.Do(s.finishV1) }, nil
}

func documentPackageDraftRowRawV1(a *generated.DocumentAttachmentDraftsV1) (int64, error) {
	if a == nil {
		return 0, ErrDocumentPackageDraftV1
	}
	return htmlAuthoringSumV1(int64(len(a.Title)), int64(len(a.Category)), int64(len(a.PdfKey)), int64(len(a.PdfVersionID)), int64(len(a.PdfSha256)), int64(len(a.SourceKind)), int64(len(a.SourceCommitment)), int64(len(a.OriginCommitment)), int64(len(a.PdfIntakeReportSha256)))
}
func documentPackageDraftCloneV1(a *generated.DocumentAttachmentDraftsV1) generated.DocumentAttachmentDraftsV1 {
	c := *a
	c.Title = strings.Clone(a.Title)
	c.Category = strings.Clone(a.Category)
	c.PdfKey = strings.Clone(a.PdfKey)
	c.PdfVersionID = strings.Clone(a.PdfVersionID)
	c.SourceKind = strings.Clone(a.SourceKind)
	c.PdfSha256 = bytes.Clone(a.PdfSha256)
	c.SourceCommitment = bytes.Clone(a.SourceCommitment)
	c.OriginCommitment = bytes.Clone(a.OriginCommitment)
	c.PdfIntakeReport = bytes.Clone(a.PdfIntakeReport)
	c.PdfIntakeReportSha256 = bytes.Clone(a.PdfIntakeReportSha256)
	return c
}

func documentPackageDraftBodyCostV1(h *generated.GetDocumentPackageDraftSizesV1Row) (raw, wire int64, err error) {
	if h == nil || h.MemberCount < 0 || h.MemberCount > documentpackage.MaxAnnexesV1 || h.RawTextBytes < 0 || h.RawTextBytes > h.MemberCount*4096 || h.ReportBytes < 0 || h.ReportBytes > h.MemberCount*65536 || h.MissingReports != 0 || h.PdfBytes < 0 || h.PdfBytes > documentpackage.MaxPDFBytesV1 || h.PdfPages < 0 || h.PdfPages > int64(documentpackage.MaxPDFPagesV1) {
		return 0, 0, ErrDocumentPackageDraftV1
	}
	dynamic, e := htmlAuthoringSumV1(h.RawTextBytes, h.ReportBytes)
	if e != nil {
		return 0, 0, e
	}
	// SQLC's LIMIT17 sentinel may grow pointer arrays through1,2,4,8,16,32.
	// Include all63 slots,17 complete native rows and the fixed private clone.
	raw = 4*int64(unsafe.Sizeof(applicationDocumentPackageDraftSnapshotV1{})) + 4*(63*int64(unsafe.Sizeof((*generated.DocumentAttachmentDraftsV1)(nil)))+17*int64(unsafe.Sizeof(generated.DocumentAttachmentDraftsV1{}))) + 4*int64(unsafe.Sizeof(generated.ListDocumentAttachmentDraftsV1Params{}))
	if !htmlInputAddV1(&raw, dynamic, 4) {
		return 0, 0, ErrDocumentPackageDraftV1
	}
	// Text bytea is at most twice its binary datum size. Fixed allowance covers
	// every remaining UUID, numeric/time field and native/PostgreSQL row frame.
	wire = 17 * 1024
	if !htmlInputAddV1(&wire, dynamic, 2) {
		return 0, 0, ErrDocumentPackageDraftV1
	}
	return raw, wire, nil
}

// ReadDraftV1 follows the genuine paired source policy. It derives all costs,
// locks and stored pins itself, retains its real loans across SQL retirement,
// and accepts neither DBTX nor rows/proofs supplied by the caller.
func (w *ApplicationDocumentPackageSelectionV1) ReadDraftV1(call context.Context, expected DocumentPackageDraftExpectedV1) error {
	if w == nil || w.state == nil || expected.Generation < 0 || (expected.PackageID == uuid.Nil) != (expected.Generation == 0) {
		return ErrDocumentPackageDraftV1
	}
	s := w.state
	if err := s.beginV1(call); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.draftAttempted || !s.sourcesValidated || s.readActor == uuid.Nil {
		s.mu.Unlock()
		return ErrDocumentPackageDraftV1
	}
	s.draftAttempted = true
	s.mu.Unlock()
	fixed := 4*int64(unsafe.Sizeof(applicationDocumentPackageDraftSnapshotV1{})) + 4*int64(unsafe.Sizeof(generated.GetDocumentPackageDraftSizesV1Row{})) + 4*int64(unsafe.Sizeof(generated.DocumentPackagesV1{})) + 4096 + 4*(63*int64(unsafe.Sizeof((*generated.ListDocumentPackageDraftSubjectsV1Row)(nil)))+17*int64(unsafe.Sizeof(generated.ListDocumentPackageDraftSubjectsV1Row{})))
	close, err := s.actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, close)
	q := generated.New(&applicationOwnedDBTXV1{session: s.session.state})
	snap := new(applicationDocumentPackageDraftSnapshotV1)
	nested, err := q.HasDocumentPackageDraftMembersV1(call, generated.HasDocumentPackageDraftMembersV1Params{DocumentID: s.ids[1], OrgID: s.session.state.org})
	if err != nil {
		return err
	}
	if nested {
		return ErrDocumentPackageDraftV1
	}
	var ids [documentpackage.MaxAnnexesV1 + 2]uuid.UUID
	ids[0], ids[1] = s.ids[0], s.ids[1]
	p, err := q.LockDocumentPackageByRootV1(call, generated.LockDocumentPackageByRootV1Params{DocumentID: s.ids[0], OrgID: s.session.state.org})
	if errors.Is(err, pgx.ErrNoRows) {
		if expected.PackageID != uuid.Nil {
			return ErrDocumentPackageSourceChangedV1
		}
		if err = s.fenceDraftPrivacyV1(call, ids, 2); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if p == nil || p.ID == uuid.Nil || p.DocumentID != s.ids[0] || p.OrgID != s.session.state.org || p.CreatedBy == uuid.Nil || !applicationStampV1(p.CreatedAt) || p.DraftGeneration < 1 {
			return ErrDocumentPackageDraftV1
		}
		if p.ID != expected.PackageID || p.DraftGeneration != expected.Generation {
			return ErrDocumentPackageSourceChangedV1
		}
		if p.DraftGeneration == math.MaxInt64 {
			return ErrDocumentPackageDraftV1
		}
		h, err := q.GetDocumentPackageDraftSizesV1(call, generated.GetDocumentPackageDraftSizesV1Params{PackageID: p.ID, DocumentID: p.DocumentID, OrgID: p.OrgID, ExpectedGeneration: p.DraftGeneration})
		if err != nil {
			return err
		}
		if h == nil || h.PackageID != p.ID || h.DocumentID != p.DocumentID || h.OrgID != p.OrgID || h.DraftGeneration != p.DraftGeneration {
			return ErrDocumentPackageDraftV1
		}
		if h.MemberCount < 0 || h.MemberCount > documentpackage.MaxAnnexesV1 {
			return ErrDocumentPackageDraftV1
		}
		subjects, err := q.ListDocumentPackageDraftSubjectsV1(call, generated.ListDocumentPackageDraftSubjectsV1Params{PackageID: p.ID, DocumentID: p.DocumentID, OrgID: p.OrgID, ExpectedGeneration: p.DraftGeneration})
		if err != nil {
			return err
		}
		if int64(len(subjects)) != h.MemberCount || len(subjects) > documentpackage.MaxAnnexesV1 {
			return ErrDocumentPackageDraftV1
		}
		var previousSubject int16
		for i, subject := range subjects {
			if subject == nil || subject.MemberDocumentID == uuid.Nil || subject.MemberDocumentID == s.ids[0] || subject.MemberDocumentID == s.ids[1] || subject.Ordinal <= previousSubject || subject.Ordinal > 16 {
				return ErrDocumentPackageDraftV1
			}
			for j := 0; j < i; j++ {
				if subjects[j].MemberDocumentID == subject.MemberDocumentID {
					return ErrDocumentPackageDraftV1
				}
			}
			ids[i+2] = subject.MemberDocumentID
			previousSubject = subject.Ordinal
		}
		if err = s.fenceDraftPrivacyV1(call, ids, 2+len(subjects)); err != nil {
			return err
		}
		raw, wire, err := documentPackageDraftBodyCostV1(h)
		if err != nil {
			return err
		}
		close, err := s.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
		if err != nil {
			return err
		}
		s.closes = append(s.closes, close)
		rows, err := q.ListDocumentAttachmentDraftsV1(call, generated.ListDocumentAttachmentDraftsV1Params{PackageID: p.ID, OrgID: p.OrgID, ExpectedGeneration: p.DraftGeneration})
		if err != nil {
			return err
		}
		if int64(len(rows)) != h.MemberCount || len(rows) > documentpackage.MaxAnnexesV1 {
			return ErrDocumentPackageDraftV1
		}
		var rawSum, reportSum, pdfBytes, pdfPages int64
		var previous int16
		for i, a := range rows {
			if a == nil || a.PackageID != p.ID || a.OrgID != p.OrgID || a.MemberDocumentID == uuid.Nil || a.MemberDocumentID == s.ids[0] || a.MemberDocumentID == s.ids[1] || a.Ordinal <= previous || a.Ordinal > 16 || a.MemberDocumentID != subjects[i].MemberDocumentID || a.Ordinal != subjects[i].Ordinal || !applicationStampV1(a.CreatedAt) || len(a.PdfSha256) != 32 || len(a.PdfIntakeReport) < 1 || len(a.PdfIntakeReport) > 65536 || len(a.PdfIntakeReportSha256) != 32 || a.PdfBytes < 1 || a.PdfPages < 1 {
				return ErrDocumentPackageDraftV1
			}
			for j := 0; j < i; j++ {
				b := rows[j]
				if b.MemberDocumentID == a.MemberDocumentID || (b.PdfKey == a.PdfKey && b.PdfVersionID == a.PdfVersionID) {
					return ErrDocumentPackageDraftV1
				}
			}
			for _, source := range s.sources {
				if source == nil || source.snapshot == nil || source.snapshot.document == nil {
					return ErrDocumentPackageDraftV1
				}
				d := source.snapshot.document
				if d.PdfStorageKey.Valid && d.PdfStorageVersionID.Valid && d.PdfStorageKey.String == a.PdfKey && d.PdfStorageVersionID.String == a.PdfVersionID {
					return ErrDocumentPackageDraftV1
				}
			}
			digest := sha256.Sum256(a.PdfIntakeReport)
			if !bytes.Equal(digest[:], a.PdfIntakeReportSha256) {
				return ErrDocumentPackageDraftV1
			}
			n, err := documentPackageDraftRowRawV1(a)
			if err != nil || !htmlInputAddV1(&rawSum, n, 1) || !htmlInputAddV1(&reportSum, int64(len(a.PdfIntakeReport)), 1) || !htmlInputAddV1(&pdfBytes, a.PdfBytes, 1) || !htmlInputAddV1(&pdfPages, int64(a.PdfPages), 1) {
				return ErrDocumentPackageDraftV1
			}
			snap.rows[i] = documentPackageDraftCloneV1(a)
			previous = a.Ordinal
		}
		if rawSum != h.RawTextBytes || reportSum != h.ReportBytes || pdfBytes != h.PdfBytes || pdfPages != h.PdfPages {
			return ErrDocumentPackageDraftV1
		}
		snap.present = true
		snap.header = *p
		snap.sizes = *h
		snap.count = len(rows)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() || call.Err() != nil {
		return ErrDocumentPackageDraftV1
	}
	s.draft = snap
	return nil
}

// Only UUID/scalar subject inventory precedes this barrier. The full retained
// report body and its private clone are read after every fresh pending check.
func (s *applicationDocumentPackageSelectionStateV1) fenceDraftPrivacyV1(call context.Context, ids [documentpackage.MaxAnnexesV1 + 2]uuid.UUID, count int) error {
	if count < 2 || count > len(ids) {
		return ErrDocumentPackageDraftV1
	}
	return fenceDocumentPackageSubjectsV1(call, s.session, ids, count)
}

func fenceDocumentPackageSubjectsV1(call context.Context, session *ApplicationSessionV1, ids [documentpackage.MaxAnnexesV1 + 2]uuid.UUID, count int) error {
	if session == nil || session.state == nil || count < 1 || count > len(ids) {
		return ErrDocumentPackageDraftV1
	}
	q := generated.New(&applicationOwnedDBTXV1{session: session.state})
	// M72 still serializes global pending requests. M102 supplies a separate
	// linked-request barrier for immutable member IDs without live source locks.
	orgFence, err := q.TryCollabArchivePrivacyFence(call, session.state.org)
	if err != nil {
		return err
	}
	if !orgFence {
		return ErrDocumentPackagePrivacyChangingV1
	}
	slices.SortFunc(ids[:count], func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	for _, id := range ids[:count] {
		ok, err := q.TryDocumentPackageMemberPrivacyFenceV1(call, generated.TryDocumentPackageMemberPrivacyFenceV1Params{OrgID: session.state.org, DocumentID: id})
		if err != nil {
			return err
		}
		if !ok {
			return ErrDocumentPackagePrivacyChangingV1
		}
	}
	// Separate fresh SQL snapshots after ALL barriers; never reuse a CTE snapshot
	// from before a potentially contended lock or infer safety from a row count.
	for _, id := range ids[:count] {
		pending, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: id, OrgID: session.state.org})
		if err != nil {
			return err
		}
		if pending {
			return ErrDocumentPackagePendingPrivacyV1
		}
	}

	return call.Err()
}
