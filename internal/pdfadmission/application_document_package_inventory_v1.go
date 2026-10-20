// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

type DocumentPackageInventoryMemberV1 struct {
	DocumentID   uuid.UUID `json:"document_id"`
	Ordinal      int16     `json:"ordinal"`
	Title        string    `json:"title"`
	Category     string    `json:"category"`
	PDFVersionID string    `json:"pdf_version_id"`
	PDFSHA256    string    `json:"pdf_sha256"`
	PDFBytes     int64     `json:"pdf_bytes"`
	PDFPages     int32     `json:"pdf_pages"`
}
type DocumentPackageInventoryV1 struct {
	Schema              string                             `json:"schema"`
	DocumentID          uuid.UUID                          `json:"document_id"`
	UpdatedAt           time.Time                          `json:"updated_at"`
	PackageID           string                             `json:"package_id"`
	Generation          string                             `json:"generation"`
	RequiresReselection bool                               `json:"requires_reselection"`
	Members             []DocumentPackageInventoryMemberV1 `json:"members"`
}

// The actual single-root reader and its locked staff policy precede this
// bounded metadata view. It grants no eligibility/selection/Send authority.
// Caller retains THIS reader through response's actual last use.
func (r *ApplicationHTMLRevisionReaderV1) ReadDocumentPackageInventoryV1(call context.Context) (out DocumentPackageInventoryV1, failure error) {
	if r == nil || r.self != r {
		return out, ErrDocumentPackageDraftV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(call) || !r.bodyComplete || r.snapshot == nil || r.snapshot.document == nil || r.packageBinding != nil || r.packageInventoryRead {
		return out, ErrDocumentPackageDraftV1
	}
	r.packageInventoryRead = true
	d := r.snapshot.document
	if d.SourceKind != "pdf" || d.IsEnvelope || d.ParentEnvelopeID.Valid || d.DeletedAt.Valid || d.Status != "draft" {
		return out, ErrDocumentPackageDraftV1
	}
	fixed := int64(65536) + 4*int64(unsafe.Sizeof(DocumentPackageInventoryV1{})) + 4*int64(unsafe.Sizeof(generated.DocumentPackagesV1{})) +
		4*int64(unsafe.Sizeof(generated.GetDocumentPackageDraftSizesV1Row{})) + 4*(63*int64(unsafe.Sizeof((*generated.ListDocumentPackageDraftSubjectsV1Row)(nil)))+17*int64(unsafe.Sizeof(generated.ListDocumentPackageDraftSubjectsV1Row{})))
	close, e := r.authoring.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if e != nil {
		return out, e
	}
	r.closeConsumers = append(r.closeConsumers, close)
	out = DocumentPackageInventoryV1{Schema: "hash-document-attachments-v1", DocumentID: d.ID, UpdatedAt: d.UpdatedAt.Time, Generation: "0", Members: []DocumentPackageInventoryMemberV1{}}
	p, e := r.queries.LockDocumentPackageByRootV1(call, generated.LockDocumentPackageByRootV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	var ids [documentpackage.MaxAnnexesV1 + 2]uuid.UUID
	ids[0] = d.ID
	if errors.Is(e, pgx.ErrNoRows) {
		return out, fenceDocumentPackageSubjectsV1(call, r.session, ids, 1)
	}
	if e != nil {
		return out, e
	}
	if p == nil || p.ID == uuid.Nil || p.DocumentID != d.ID || p.OrgID != d.OrgID || p.DraftGeneration < 1 {
		return out, ErrDocumentPackageDraftV1
	}
	sizes, e := r.queries.GetDocumentPackageDraftSizesV1(call, generated.GetDocumentPackageDraftSizesV1Params{PackageID: p.ID, DocumentID: d.ID, OrgID: d.OrgID, ExpectedGeneration: p.DraftGeneration})
	if e != nil {
		return out, e
	}
	if sizes == nil || sizes.PackageID != p.ID || sizes.DocumentID != d.ID || sizes.OrgID != d.OrgID || sizes.DraftGeneration != p.DraftGeneration ||
		sizes.MemberCount < 0 || sizes.MemberCount > 16 || sizes.RawTextBytes < 0 || sizes.RawTextBytes > sizes.MemberCount*4096 ||
		sizes.MissingReports < 0 || sizes.MissingReports > sizes.MemberCount {
		return out, ErrDocumentPackageDraftV1
	}
	subjects, e := r.queries.ListDocumentPackageDraftSubjectsV1(call, generated.ListDocumentPackageDraftSubjectsV1Params{PackageID: p.ID, DocumentID: d.ID, OrgID: d.OrgID, ExpectedGeneration: p.DraftGeneration})
	if e != nil {
		return out, e
	}
	if len(subjects) != int(sizes.MemberCount) {
		return out, ErrDocumentPackageDraftV1
	}
	previous := int16(0)
	for i, s := range subjects {
		if s == nil || s.MemberDocumentID == uuid.Nil || s.MemberDocumentID == d.ID || s.Ordinal <= previous || s.Ordinal > 16 {
			return out, ErrDocumentPackageDraftV1
		}
		for j := 0; j <= i; j++ {
			if ids[j] == s.MemberDocumentID {
				return out, ErrDocumentPackageDraftV1
			}
		}
		ids[i+1] = s.MemberDocumentID
		previous = s.Ordinal
	}
	if e = fenceDocumentPackageSubjectsV1(call, r.session, ids, len(subjects)+1); e != nil {
		return out, e
	}
	// No internal report body is read or serialized. Existing legacy missing
	// proof can be listed for repair without claiming it is selection-eligible.
	raw := 4*(63*int64(unsafe.Sizeof((*generated.ListDocumentPackageAttachmentMetadataV1Row)(nil)))+
		17*int64(unsafe.Sizeof(generated.ListDocumentPackageAttachmentMetadataV1Row{}))+
		17*int64(unsafe.Sizeof(DocumentPackageInventoryMemberV1{}))) + 16*sizes.RawTextBytes + 65536
	wire := 17*1024 + 8*sizes.RawTextBytes
	close, e = r.authoring.acquireOwnedRetainedBodyV1(call, raw, wire)
	if e != nil {
		return out, e
	}
	r.closeConsumers = append(r.closeConsumers, close)
	rows, e := r.queries.ListDocumentPackageAttachmentMetadataV1(call, generated.ListDocumentPackageAttachmentMetadataV1Params{PackageID: p.ID, DocumentID: d.ID, OrgID: d.OrgID, ExpectedGeneration: p.DraftGeneration})
	if e != nil {
		return out, e
	}
	if len(rows) != len(subjects) {
		return out, ErrDocumentPackageDraftV1
	}
	out.PackageID = p.ID.String()
	out.Generation = strconv.FormatInt(p.DraftGeneration, 10)
	out.RequiresReselection = sizes.MissingReports > 0
	out.Members = make([]DocumentPackageInventoryMemberV1, len(rows))
	for i, a := range rows {
		if a == nil || a.MemberDocumentID != subjects[i].MemberDocumentID || a.Ordinal != subjects[i].Ordinal || len(a.PdfSha256) != 32 ||
			!documentPackageWriteLabelV1(a.Title, 512, false) || !documentPackageWriteLabelV1(a.Category, 128, true) || len(a.PdfVersionID) < 1 || len(a.PdfVersionID) > 1024 ||
			a.PdfBytes < 1 || a.PdfBytes > documentpackage.MaxPDFBytesV1 || a.PdfPages < 1 || a.PdfPages > documentpackage.MaxPDFPagesV1 {
			return DocumentPackageInventoryV1{}, ErrDocumentPackageDraftV1
		}
		out.Members[i] = DocumentPackageInventoryMemberV1{DocumentID: a.MemberDocumentID, Ordinal: a.Ordinal, Title: strings.Clone(a.Title),
			Category: strings.Clone(a.Category), PDFVersionID: strings.Clone(a.PdfVersionID), PDFSHA256: hex.EncodeToString(a.PdfSha256), PDFBytes: a.PdfBytes, PDFPages: a.PdfPages}
	}
	return out, call.Err()
}
