// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/packageauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func documentAttachmentPreviewExpectedV1(raw string) (out pdfadmission.DocumentPackagePreviewExpectedV1, e error) {
	e = pdfadmission.ErrDocumentPackageInputV1
	if len(raw) < 1 || len(raw) > 1024 {
		return
	}
	q, err := url.ParseQuery(raw)
	if err != nil || len(q) != 3 {
		return
	}
	for key, values := range q {
		if len(values) != 1 || (key != "expected_updated_at" && key != "expected_package_id" && key != "expected_generation") {
			return
		}
	}
	stamp := q.Get("expected_updated_at")
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != stamp {
		return
	}
	id, err := uuid.Parse(q.Get("expected_package_id"))
	if err != nil || id == uuid.Nil || id.String() != q.Get("expected_package_id") {
		return
	}
	gen, err := strconv.ParseInt(q.Get("expected_generation"), 10, 64)
	if err != nil || gen < 1 || strconv.FormatInt(gen, 10) != q.Get("expected_generation") {
		return
	}
	return pdfadmission.DocumentPackagePreviewExpectedV1{UpdatedAt: at, PackageID: id, Generation: gen}, nil
}
func (s *Server) handleDocumentAttachmentPreviewV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	root, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	member, ok := parseUUIDParam(w, r, "member_id")
	if !ok {
		return
	}
	if root == uuid.Nil || member == uuid.Nil || root == member {
		writeError(w, http.StatusBadRequest, "select a distinct contract attachment")
		return
	}
	expected, e := documentAttachmentPreviewExpectedV1(r.URL.RawQuery)
	if e != nil {
		writeError(w, http.StatusBadRequest, "use the exact current attachment observation")
		return
	}
	if s.HTMLCreationSessions == nil || s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "attachment processing is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, e := s.sessionDraftAuthorization(r, sess.OrgID, sess.UserID)
	if e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	result, e := packageauthoring.PreviewV1(ctx, packageauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Storage: s.Storage}, authoring.Actor{OrgID: sess.OrgID, UserID: sess.UserID, Authorize: authorize}, root, member, expected)
	if result != nil {
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			if e := result.CloseV1(cleanup); e != nil {
				slog.Warn("Hash attachment preview cleanup requires reconciliation", "error_type", fmt.Sprintf("%T", e))
			}
		}()
	}
	if e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	wrote := false
	e = result.WithPDFV1(func(m pdfadmission.DocumentPackagePreviewMetadataV1, body []byte) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		h := w.Header()
		h.Set("Content-Type", "application/pdf")
		h.Set("Content-Disposition", "inline; filename=selected-attachment.pdf")
		h.Set("Content-Length", strconv.FormatInt(m.PDFBytes, 10))
		setDocumentPreviewHeaders(w, false)
		h.Set("X-Hash-Document-Id", m.DocumentID.String())
		h.Set("X-Hash-Document-Updated-At", m.UpdatedAt.UTC().Format(time.RFC3339Nano))
		h.Set("X-Hash-Package-Id", m.PackageID.String())
		h.Set("X-Hash-Package-Generation", m.Generation)
		h.Set("X-Hash-Member-Document-Id", m.MemberDocumentID.String())
		h.Set("X-Hash-PDF-Version", base64.RawURLEncoding.EncodeToString([]byte(m.PDFVersionID)))
		h.Set("X-Hash-PDF-SHA256", m.PDFSHA256)
		h.Set("X-Hash-PDF-Bytes", strconv.FormatInt(m.PDFBytes, 10))
		h.Set("X-Hash-PDF-Pages", strconv.FormatInt(int64(m.PDFPages), 10))
		wrote = true
		_, e := w.Write(body)
		return e
	})
	if e != nil && !wrote {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
	}
}
