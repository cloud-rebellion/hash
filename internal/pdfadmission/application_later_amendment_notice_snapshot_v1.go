// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"strings"
	"unsafe"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/noticeaccess"
	"github.com/bright-interaction/hash/internal/workguard"
)

// Fixed native metadata only: no source document/current projection, provider
// handle, SQL permit or caller-declared resource cost survives this handoff.
// Engine preparation has independently verified exact declared objects first.
// Parent-only credit covers these detached immutable comparison bytes; the
// second native transaction pays its own original SQL/body/output staging.
func laterNoticeSnapshotResourcesV1(in noticeaccess.InputV1, request amendments.IssueNoticeV1, pins []byte) (int64, error) {
	if len(in.FileSetBytes) < 2 || len(in.FileSetBytes) > noticeaccess.MaxFileSetBytesV1 || len(pins) < 2 || len(pins) > 32768 || len(in.FileSet.Files) < 1 || len(in.FileSet.Files) > noticeaccess.MaxFilesV1 || len(in.RecipientEmails) < 1 || len(in.RecipientEmails) > 32 || len(request.RecipientEmails) != len(in.RecipientEmails) || len(in.Subject) > 256 || len(in.Text) > 16384 || len(in.ReplyTo) > 254 || len(in.FromName) > 512 || len(request.Subject) > 256 || len(request.Text) > 16384 || len(request.ExpectedHeadRevision) > 32 {
		return 0, amendments.ErrUnavailableV1
	}
	parts := []int64{int64(len(in.FileSetBytes)), int64(len(pins)), int64(len(in.Subject)), int64(len(in.Text)), int64(len(in.ReplyTo)), int64(len(in.FromName)), int64(len(in.FileSet.Schema)), int64(len(in.FileSet.SourceCommitmentSHA256)), int64(len(in.FileSet.PackageGeneration)), int64(len(request.Subject)), int64(len(request.Text)), int64(len(request.ExpectedHeadRevision))}
	for _, audience := range [][]string{in.RecipientEmails, request.RecipientEmails} {
		for _, email := range audience {
			if len(email) > 254 {
				return 0, amendments.ErrUnavailableV1
			}
			parts = append(parts, int64(len(email)))
		}
	}
	for _, f := range in.FileSet.Files {
		if len(f.Title) > 512 || len(f.Key) > 1024 || len(f.VersionID) > 1024 || len(f.SHA256) > 64 || len(f.IntakeReportSHA256) > 64 {
			return 0, amendments.ErrUnavailableV1
		}
		parts = append(parts, int64(len(f.Title)), int64(len(f.Key)), int64(len(f.VersionID)), int64(len(f.SHA256)), int64(len(f.IntakeReportSHA256)))
	}
	// Eightfold allocator/old+new clone/SQL-comparison scratch allowance plus
	// exact typed containers and fixed small ownership/closure bookkeeping.
	raw, err := htmlAuthoringSumV1(parts...)
	if err != nil || raw > 1<<20 {
		return 0, amendments.ErrUnavailableV1
	}
	typed := int64(unsafe.Sizeof(ApplicationLaterAmendmentNoticeV1{})) + int64(unsafe.Sizeof(noticeaccess.InputV1{})) + int64(unsafe.Sizeof(amendments.IssueNoticeV1{})) + 2*int64(unsafe.Sizeof(workguard.GrantV1{})) +
		int64(len(in.FileSet.Files))*int64(unsafe.Sizeof(amendments.FileV1{})) + int64(len(in.RecipientEmails)+len(request.RecipientEmails))*int64(unsafe.Sizeof(""))
	return 65536 + 8*(raw+typed), nil
}

// Called only after the private actual snapshot paid its own retained grant.
// Detach every variable-sized field, even the original request/reply identity
// and exact opaque VersionId bytes. No normalization changes committed pins.
func laterNoticeCloneSnapshotV1(in noticeaccess.InputV1, request amendments.IssueNoticeV1, pins []byte) (noticeaccess.InputV1, amendments.IssueNoticeV1, []byte) {
	out := in
	out.FileSetBytes = bytes.Clone(in.FileSetBytes)
	out.Subject = strings.Clone(in.Subject)
	out.Text = strings.Clone(in.Text)
	out.ReplyTo = strings.Clone(in.ReplyTo)
	out.FromName = strings.Clone(in.FromName)
	out.RecipientEmails = make([]string, len(in.RecipientEmails))
	for i, email := range in.RecipientEmails {
		out.RecipientEmails[i] = strings.Clone(email)
	}
	out.FileSet.Schema = strings.Clone(in.FileSet.Schema)
	out.FileSet.SourceCommitmentSHA256 = strings.Clone(in.FileSet.SourceCommitmentSHA256)
	out.FileSet.PackageGeneration = strings.Clone(in.FileSet.PackageGeneration)
	if in.FileSet.PackageID != nil {
		id := *in.FileSet.PackageID
		out.FileSet.PackageID = &id
	}
	out.FileSet.Files = make([]amendments.FileV1, len(in.FileSet.Files))
	for i, file := range in.FileSet.Files {
		out.FileSet.Files[i] = file
		out.FileSet.Files[i].Title = strings.Clone(file.Title)
		out.FileSet.Files[i].Key = strings.Clone(file.Key)
		out.FileSet.Files[i].VersionID = strings.Clone(file.VersionID)
		out.FileSet.Files[i].SHA256 = strings.Clone(file.SHA256)
		out.FileSet.Files[i].IntakeReportSHA256 = strings.Clone(file.IntakeReportSHA256)
	}
	clonedRequest := request
	clonedRequest.ExpectedHeadRevision = strings.Clone(request.ExpectedHeadRevision)
	clonedRequest.Subject = strings.Clone(request.Subject)
	clonedRequest.Text = strings.Clone(request.Text)
	clonedRequest.RecipientEmails = make([]string, len(request.RecipientEmails))
	for i, email := range request.RecipientEmails {
		clonedRequest.RecipientEmails[i] = strings.Clone(email)
	}
	return out, clonedRequest, bytes.Clone(pins)
}
