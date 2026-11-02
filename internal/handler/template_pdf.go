// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/pdftemplateauthoring"
	"github.com/google/uuid"
)

// A thumbnail is an immutable PDF read, never a new render. The caller pins the
// visible template revision and digest; the stored VersionId is server-owned.
type templatePDFPinV1 struct {
	ID, OrgID            uuid.UUID
	Version              int32
	Key, StorageVersion  string
	SHA256               [sha256.Size]byte
	CreatedAt, UpdatedAt time.Time
}

func parseTemplatePDFExpectationV1(query url.Values) (int32, [sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	versions, hashes := query["version"], query["sha256"]
	if len(query) != 2 || len(versions) != 1 || len(hashes) != 1 {
		return 0, digest, false
	}
	version, err := strconv.ParseInt(versions[0], 10, 32)
	if err != nil || version < 1 || strconv.FormatInt(version, 10) != versions[0] || len(hashes[0]) != sha256.Size*2 || strings.ToLower(hashes[0]) != hashes[0] {
		return 0, digest, false
	}
	decoded, err := hex.DecodeString(hashes[0])
	if err != nil {
		return 0, digest, false
	}
	copy(digest[:], decoded)
	return int32(version), digest, true
}

func templatePDFPinForV1(template *generated.Template, org, id uuid.UUID) (templatePDFPinV1, bool) {
	var pin templatePDFPinV1
	if template == nil || template.ID != id || template.OrgID != org || template.SourceKind != "pdf" || template.ArchivedAt.Valid || template.Version < 1 ||
		!template.PdfStorageKey.Valid || template.PdfStorageKey.String == "" || !template.PdfStorageVersionID.Valid || template.PdfStorageVersionID.String == "" ||
		!template.EvidenceVersionPinRequired || len(template.PdfSha256) != sha256.Size || !template.CreatedAt.Valid || !template.UpdatedAt.Valid {
		return pin, false
	}
	pin = templatePDFPinV1{ID: id, OrgID: org, Version: template.Version,
		Key: strings.Clone(template.PdfStorageKey.String), StorageVersion: strings.Clone(template.PdfStorageVersionID.String),
		CreatedAt: template.CreatedAt.Time, UpdatedAt: template.UpdatedAt.Time}
	copy(pin.SHA256[:], template.PdfSha256)
	return pin, true
}

func (s *Server) readTemplatePDFPinV1(ctx context.Context, actor pdftemplateauthoring.ReadActorV1, id uuid.UUID) (templatePDFPinV1, error) {
	result, err := pdftemplateauthoring.ReadV1(ctx, s.HTMLCreationSessions, actor, id)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		return templatePDFPinV1{}, err
	}
	if result != nil {
		if pin, ok := templatePDFPinForV1(result.Template, actor.OrgID, id); ok {
			return pin, nil
		}
	}
	return templatePDFPinV1{}, errTemplatePDFUnavailableV1
}

var errTemplatePDFUnavailableV1 = errors.New("PDF template source unavailable")
var errTemplatePDFChangedV1 = errors.New("PDF template source changed")

func (s *Server) writeTemplatePDFReadErrorV1(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pdftemplateauthoring.ErrTemplateNotFoundV1), errors.Is(err, pdfadmission.ErrPDFTemplateSourceKindV1):
		writeError(w, http.StatusNotFound, "template not found")
	case errors.Is(err, auth.ErrMutationPermissionRevoked), errors.Is(err, auth.ErrMutationCredentialExpired):
		s.writeDraftAuthoringError(w, "read template PDF", err)
	default:
		writeError(w, http.StatusServiceUnavailable, "PDF template temporarily unavailable")
	}
}

func (s *Server) handleGetTemplatePDF(w http.ResponseWriter, r *http.Request) {
	// Error responses must not be cached either. The normal session middleware
	// and native authorization still run on every request, including repeat reads.
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	version, digest, valid := parseTemplatePDFExpectationV1(query)
	if err != nil || !valid {
		writeError(w, http.StatusBadRequest, "exact template version and sha256 are required")
		return
	}
	authorize, ok := s.sessionMutationAuthorization(w, r, u)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	actor := pdftemplateauthoring.ReadActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}
	initialRead, err := pdftemplateauthoring.ReadV1(ctx, s.HTMLCreationSessions, actor, id)
	if initialRead != nil {
		defer initialRead.CloseConsumerV1()
	}
	if err != nil {
		s.writeTemplatePDFReadErrorV1(w, err)
		return
	}
	initial, valid := templatePDFPinForV1(initialRead.Template, u.OrgID, id)
	if !valid {
		s.writeTemplatePDFReadErrorV1(w, errTemplatePDFUnavailableV1)
		return
	}
	if initial.Version != version || initial.SHA256 != digest {
		writeError(w, http.StatusPreconditionFailed, "template PDF changed; refresh the template")
		return
	}
	if s.Storage == nil {
		s.writeTemplatePDFReadErrorV1(w, errTemplatePDFUnavailableV1)
		return
	}
	// The genuine native source owns retained metadata after its physical SQL
	// session has retired. Its same-process Factory/coordinator admits the fixed
	// body ceiling and actual local provider IO BEFORE dispatch; native storage
	// retains all grants through real cleanup and this HTTP consumer.
	wrote := false
	err = initialRead.WithPDFBodyV1(ctx, s.Storage, func(body []byte) error {
		current, err := s.readTemplatePDFPinV1(ctx, actor, id)
		if err != nil {
			return err
		}
		if current != initial {
			return errTemplatePDFChangedV1
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		setDocumentPreviewHeaders(w, false)
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "inline")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("ETag", `"`+hex.EncodeToString(initial.SHA256[:])+`"`)
		w.Header().Set("X-Hash-Template-Id", initial.ID.String())
		w.Header().Set("X-Hash-Template-Version", strconv.FormatInt(int64(initial.Version), 10))
		w.Header().Set("X-Hash-PDF-SHA256", hex.EncodeToString(initial.SHA256[:]))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		wrote = true
		_, err = w.Write(body)
		return err
	})
	if err != nil && !wrote {
		if errors.Is(err, errTemplatePDFChangedV1) {
			writeError(w, http.StatusPreconditionFailed, "template PDF changed; refresh the template")
			return
		}
		s.writeTemplatePDFReadErrorV1(w, err)
	}
}
