// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	brandcatalog "github.com/bright-interaction/hash/internal/branding/catalog"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) brandCatalogServiceV1() *brandcatalog.ServiceV1 {
	if s.BrandCatalog != nil {
		return s.BrandCatalog
	}
	return brandcatalog.NewServiceV1(s.Pool, s.Audit, s.Storage)
}
func (s *Server) brandCatalogActorV1(w http.ResponseWriter, r *http.Request, write bool) (authoring.Actor, bool) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return authoring.Actor{}, false
	}
	if write && !s.requireFeature(w, r, u.OrgID, "branding") {
		return authoring.Actor{}, false
	}
	var actor authoring.Actor
	var e error
	if _, token := auth.TokenScopesFromContext(r.Context()); token {
		scope := "read"
		if write {
			scope = "write:authoring"
		}
		if _, valid := automationDocumentActor(w, r, scope); !valid {
			return authoring.Actor{}, false
		}
		actor.OrgID, actor.UserID = u.OrgID, u.UserID
		actor.Authorize, e = auth.APIKeyTransactionAuthorization(r.Context(), uuid.Nil, scope)
	} else {
		actor, e = s.sessionOwnerActor(r, u)
	}
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return authoring.Actor{}, false
	}
	return actor, true
}
func (s *Server) writeBrandCatalogErrorV1(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, brandcatalog.ErrInputV1):
		writeError(w, 400, "Invalid brand profile, asset, selection, or contrast pair.")
	case errors.Is(e, brandcatalog.ErrNotFoundV1):
		writeError(w, 404, "Brand catalog item not found.")
	case errors.Is(e, brandcatalog.ErrConflictV1):
		writeError(w, 409, "Brand catalog changed. Reload before saving or retrying this request.")
	case errors.Is(e, malwarescan.ErrDetected), errors.Is(e, malwarescan.ErrUnavailable):
		writeScanError(w, e)
	default:
		if status, known := draftAuthoringErrorStatus(e); known {
			writeError(w, status, "Brand catalog authorization changed.")
		} else {
			writeError(w, 503, "Brand catalog unavailable. Inspect current state before repeating an uncertain save.")
		}
	}
}
func catalogPageV1(r *http.Request) (int, uuid.UUID, error) {
	n := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 || v > 50 {
			return 0, uuid.Nil, brandcatalog.ErrInputV1
		}
		n = v
	}
	after := uuid.Nil
	if s := r.URL.Query().Get("after"); s != "" {
		var e error
		after, e = uuid.Parse(s)
		if e != nil {
			return 0, uuid.Nil, brandcatalog.ErrInputV1
		}
	}
	return n, after, nil
}
func catalogIDV1(r *http.Request, key string) (uuid.UUID, error) {
	id, e := uuid.Parse(chi.URLParam(r, key))
	if e != nil || id == uuid.Nil {
		return uuid.Nil, brandcatalog.ErrInputV1
	}
	return id, nil
}
func catalogRevisionV1(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	n, e := strconv.ParseInt(raw, 10, 64)
	if e != nil || n < 0 {
		return 0, brandcatalog.ErrInputV1
	}
	return n, nil
}
func decodeCatalogV1(w http.ResponseWriter, r *http.Request, out any, max int) error {
	r.Body = http.MaxBytesReader(w, r.Body, int64(max))
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		return brandcatalog.ErrInputV1
	}
	return brandcatalog.DecodeJSONV1(raw, out, max)
}
func (s *Server) handleListBrandProfilesV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, false)
	if !ok {
		return
	}
	n, after, e := catalogPageV1(r)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	out, e := s.brandCatalogServiceV1().ListProfilesV1(r.Context(), a, n, after)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"profiles": out})
}
func (s *Server) handleGetBrandProfileV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, false)
	if !ok {
		return
	}
	id, e := catalogIDV1(r, "profileID")
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	rev, e := catalogRevisionV1(r.URL.Query().Get("revision"))
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	out, e := s.brandCatalogServiceV1().GetProfileV1(r.Context(), a, id, rev)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleCreateBrandProfileV1(w http.ResponseWriter, r *http.Request) {
	s.saveBrandProfileV1(w, r, true)
}
func (s *Server) handleReviseBrandProfileV1(w http.ResponseWriter, r *http.Request) {
	s.saveBrandProfileV1(w, r, false)
}
func (s *Server) saveBrandProfileV1(w http.ResponseWriter, r *http.Request, create bool) {
	a, ok := s.brandCatalogActorV1(w, r, true)
	if !ok {
		return
	}
	id := uuid.Nil
	var e error
	if !create {
		id, e = catalogIDV1(r, "profileID")
		if e != nil {
			s.writeBrandCatalogErrorV1(w, e)
			return
		}
	}
	var in brandcatalog.ProfileInputV1
	if e = decodeCatalogV1(w, r, &in, 64<<10); e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	if create && in.ExpectedRevision != 0 || !create && in.ExpectedRevision < 1 {
		s.writeBrandCatalogErrorV1(w, brandcatalog.ErrInputV1)
		return
	}
	out, e := s.brandCatalogServiceV1().SaveProfileV1(r.Context(), a, id, in)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	status := 200
	if create {
		status = 201
	}
	writeJSON(w, status, out)
}
func (s *Server) handleListBrandProfileRevisionsV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, false)
	if !ok {
		return
	}
	id, e := catalogIDV1(r, "profileID")
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	n, _, e := catalogPageV1(r)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	before, e := catalogRevisionV1(r.URL.Query().Get("before"))
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	out, e := s.brandCatalogServiceV1().ListProfileRevisionsV1(r.Context(), a, id, before, n)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"revisions": out})
}
func (s *Server) handleGetBrandDefaultV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, false)
	if !ok {
		return
	}
	out, e := s.brandCatalogServiceV1().GetDefaultV1(r.Context(), a)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleSelectBrandDefaultV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, true)
	if !ok {
		return
	}
	var in struct {
		brandcatalog.ProfileRefV1
		ExpectedSelectionRevision *int64 `json:"expected_selection_revision"`
	}
	if e := decodeCatalogV1(w, r, &in, 2048); e != nil || in.ExpectedSelectionRevision == nil {
		s.writeBrandCatalogErrorV1(w, brandcatalog.ErrInputV1)
		return
	}
	out, e := s.brandCatalogServiceV1().SelectDefaultV1(r.Context(), a, in.ProfileRefV1, *in.ExpectedSelectionRevision)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleListBrandAssetsV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, false)
	if !ok {
		return
	}
	n, after, e := catalogPageV1(r)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	out, e := s.brandCatalogServiceV1().ListAssetsV1(r.Context(), a, n, after)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"assets": out})
}
func (s *Server) handleGetBrandAssetV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, false)
	if !ok {
		return
	}
	id, e := catalogIDV1(r, "assetID")
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	rev, e := catalogRevisionV1(r.URL.Query().Get("revision"))
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	out, e := s.brandCatalogServiceV1().GetAssetV1(r.Context(), a, id, rev)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleUploadBrandAssetV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, true)
	if !ok {
		return
	}
	ctx, release, e := brandcatalog.AcquireInputV1(r.Context(), a.OrgID)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	defer release()
	r = r.WithContext(ctx)
	var in brandcatalog.AssetUploadV1
	if e = decodeCatalogV1(w, r, &in, 14<<20); e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	out, e := s.brandCatalogServiceV1().UploadAssetV1(ctx, a, in)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) handleListBrandAssetRevisionsV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, false)
	if !ok {
		return
	}
	id, e := catalogIDV1(r, "assetID")
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	n, _, e := catalogPageV1(r)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	before, e := catalogRevisionV1(r.URL.Query().Get("before"))
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	out, e := s.brandCatalogServiceV1().ListAssetRevisionsV1(r.Context(), a, id, before, n)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"revisions": out})
}
func (s *Server) handleGetBrandUploadStatusV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, false)
	if !ok {
		return
	}
	id, e := catalogIDV1(r, "requestID")
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	out, e := s.brandCatalogServiceV1().GetUploadStatusV1(r.Context(), a, id)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleGetBrandAssetContentV1(w http.ResponseWriter, r *http.Request) {
	a, ok := s.brandCatalogActorV1(w, r, false)
	if !ok {
		return
	}
	id, e := catalogIDV1(r, "assetID")
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	rev, e := catalogRevisionV1(chi.URLParam(r, "revision"))
	if e != nil || rev < 1 {
		s.writeBrandCatalogErrorV1(w, brandcatalog.ErrInputV1)
		return
	}
	representation := r.URL.Query().Get("representation")
	if representation == "" {
		representation = "original"
	}
	body, object, close, e := s.brandCatalogServiceV1().ReadAssetContentV1(r.Context(), a, id, rev, representation)
	if e != nil {
		s.writeBrandCatalogErrorV1(w, e)
		return
	}
	defer close()
	ext := "png"
	if object.MediaType == "image/svg+xml" {
		ext = "svg"
	}
	w.Header().Set("Content-Type", object.MediaType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"brand-%s-r%d.%s\"", id, rev, ext))
	w.Header().Set("ETag", "\""+object.SHA256+"\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(200)
	_, _ = w.Write(body)
}
