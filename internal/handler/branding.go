// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
)

// brandingInput is the wire shape for upsert. All fields optional; any
// missing field preserves the current value, or the system default for a new row.
type brandingInput struct {
	PrimaryHex     string `json:"primary_hex"`
	AccentHex      string `json:"accent_hex"`
	SurfaceHex     string `json:"surface_hex"`
	TextHex        string `json:"text_hex"`
	MutedHex       string `json:"muted_hex"`
	LogoURL        string `json:"logo_url"`
	LogoAlt        string `json:"logo_alt"`
	FontHeading    string `json:"font_heading"`
	FontBody       string `json:"font_body"`
	SignatureColor string `json:"signature_color"`
}

// validateHexFields normalises every supplied hex field; on error
// returns the field name and the human-readable failure.
func (b *brandingInput) validateHexFields() (string, error) {
	checks := []struct {
		name string
		val  *string
	}{
		{"primary_hex", &b.PrimaryHex},
		{"accent_hex", &b.AccentHex},
		{"surface_hex", &b.SurfaceHex},
		{"text_hex", &b.TextHex},
		{"muted_hex", &b.MutedHex},
		{"signature_color", &b.SignatureColor},
	}
	for _, c := range checks {
		if *c.val == "" {
			continue
		}
		norm := branding.NormaliseHex(*c.val)
		if norm == "" {
			return c.name, fmt.Errorf("%s must be a 3- or 6-char hex colour", c.name)
		}
		*c.val = norm
	}
	return "", nil
}

// GET /api/v1/branding
func (s *Server) handleGetOrgBranding(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	b, err := s.resolveOrgBranding(r.Context(), sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// PUT /api/v1/branding
func (s *Server) handleUpsertOrgBranding(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	// Custom branding is a paid-plan feature.
	if !s.requireFeature(w, r, sess.OrgID, "branding") {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var in brandingInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if field, err := in.validateHexFields(); err != nil {
		writeError(w, http.StatusBadRequest, field+": "+err.Error())
		return
	}
	for _, font := range []struct {
		name  string
		value *string
	}{
		{"font_heading", &in.FontHeading}, {"font_body", &in.FontBody},
	} {
		if *font.value != "" {
			normalized, err := branding.NormaliseFontFamily(*font.value)
			if err != nil {
				writeError(w, http.StatusBadRequest, font.name+": "+err.Error())
				return
			}
			*font.value = normalized
		}
	}
	in.LogoURL = strings.TrimSpace(in.LogoURL)
	if err := branding.ValidateLogoURLForEnvironment(s.Environment, in.LogoURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, err := s.sessionOwnerActor(r, sess)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize branding update", err)
		return
	}
	row, err := authoring.CommitOwnerMutation(r.Context(), s.Pool, s.Audit, actor,
		func(ctx context.Context, q *generated.Queries) (*generated.OrgBranding, error) {
			base := branding.DefaultBranding()
			current, err := q.GetOrgBranding(ctx, sess.OrgID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			if err == nil {
				base = brandingFromOrgRow(current)
			}
			merged := mergeBrandingInput(base, in)
			merged.LogoURL = strings.TrimSpace(merged.LogoURL)
			if err := branding.ValidateLogoURLForEnvironment(s.Environment, merged.LogoURL); err != nil {
				return nil, fmt.Errorf("%w: %s", errOwnerMutationInput, err)
			}
			merged.FontHeading, err = branding.NormaliseFontFamily(merged.FontHeading)
			if err != nil {
				return nil, fmt.Errorf("%w: font_heading: %s", errOwnerMutationInput, err)
			}
			merged.FontBody, err = branding.NormaliseFontFamily(merged.FontBody)
			if err != nil {
				return nil, fmt.Errorf("%w: font_body: %s", errOwnerMutationInput, err)
			}
			return q.UpsertOrgBranding(ctx, generated.UpsertOrgBrandingParams{
				OrgID: sess.OrgID, PrimaryHex: merged.PrimaryHex, AccentHex: merged.AccentHex,
				SurfaceHex: merged.SurfaceHex, TextHex: merged.TextHex, MutedHex: merged.MutedHex,
				LogoUrl: merged.LogoURL, LogoAlt: merged.LogoAlt, FontHeading: merged.FontHeading,
				FontBody: merged.FontBody, SignatureColor: merged.SignatureColor,
			})
		},
		func(*generated.OrgBranding) audit.Entry {
			return audit.Entry{
				OrgID: sess.OrgID, ActorUserID: &sess.UserID, Kind: audit.KindDocumentUpdated,
				IP: firstIPFromHeader(r), UserAgent: r.UserAgent(),
				Payload: map[string]any{"via": "rest", "tool": "upsert_org_branding"},
			}
		},
	)
	if err != nil {
		if errors.Is(err, errOwnerMutationInput) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeDraftAuthoringError(w, "update branding", err)
		return
	}
	writeJSON(w, http.StatusOK, brandingFromOrgRow(row))
}

// POST /api/v1/branding/extract  (multipart logo upload)
//
// Returns a suggested primary + accent palette from a logo's dominant
// colours. Does NOT persist the logo; callers display the suggestion in
// the settings UI and only PUT /branding if the user accepts.
func (s *Server) handleExtractBrandingPalette(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	release, err := importguard.Shared.Acquire(sess.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	defer release()

	r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
	defer cleanupMultipart(r)
	if err := r.ParseMultipartForm(multipartFileMemory); err != nil {
		writeError(w, http.StatusBadRequest, "expected multipart form: "+err.Error())
		return
	}
	file, _, err := r.FormFile("logo")
	if err != nil {
		writeError(w, http.StatusBadRequest, "logo file required")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "logo read failed")
		return
	}
	if err := malwarescan.ScanActive(r.Context(), raw); err != nil {
		writeScanError(w, err)
		return
	}
	primary, accent, ok2 := branding.ExtractPaletteFromLogo(bytes.NewReader(raw))
	if !ok2 {
		writeError(w, http.StatusBadRequest, "logo could not be decoded (expected jpeg or png)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"primary_hex": primary,
		"accent_hex":  accent,
	})
}

// POST /api/v1/branding/logo  (multipart upload, persists to MinIO)
func (s *Server) handleUploadBrandingLogo(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if strings.EqualFold(strings.TrimSpace(s.Environment), "production") {
		writeError(w, http.StatusConflict, branding.ErrProductionLogoUnsupported.Error())
		return
	}
	if s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "storage not configured")
		return
	}
	release, err := importguard.Shared.Acquire(sess.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	defer release()

	r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
	defer cleanupMultipart(r)
	if err := r.ParseMultipartForm(multipartFileMemory); err != nil {
		writeError(w, http.StatusBadRequest, "expected multipart form: "+err.Error())
		return
	}
	file, header, err := r.FormFile("logo")
	if err != nil {
		writeError(w, http.StatusBadRequest, "logo file required")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4*1024*1024))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	ext := strings.ToLower(extOf(header.Filename))
	if ext != ".png" && ext != ".jpg" && ext != ".jpeg" && ext != ".svg" {
		writeError(w, http.StatusBadRequest, "logo must be png, jpg, or svg")
		return
	}
	actor, err := s.sessionOwnerActor(r, sess)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize logo upload", err)
		return
	}
	// Unique asset identities keep a rejected edit from replacing the logo
	// already used by another document. Legacy stable URLs remain readable.
	assetID := uuid.New()
	key := fmt.Sprintf("branding/%s/%s%s", sess.OrgID.String(), assetID, ext)
	ctype := contentTypeOf(ext)
	var stored storage.StoredObject
	committed := false
	defer func() {
		if committed || stored.VersionID == "" {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		if err := s.Storage.DeleteVersion(cleanupCtx, key, stored.VersionID, stored.SHA256[:]); err != nil {
			// Compensation failure must remain visible to operators; never delete
			// another object merely because exact-version cleanup was refused.
			slog.Error("logo upload compensation failed", "org_id", sess.OrgID, "key", key, "error", err)
		}
	}()
	_, err = authoring.CommitOwnerMutation(r.Context(), s.Pool, s.Audit, actor,
		func(ctx context.Context, _ *generated.Queries) (uuid.UUID, error) {
			cleaned, err := sanitize.CleanWithContext(ctx, "logo", ctype, raw)
			if err != nil {
				if errors.Is(err, malwarescan.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return uuid.Nil, err
				}
				return uuid.Nil, fmt.Errorf("%w: sanitize logo: %s", errOwnerMutationInput, err)
			}
			stored, err = s.Storage.PutVersioned(ctx, key, ctype, cleaned.Bytes)
			return assetID, err
		},
		func(uuid.UUID) audit.Entry {
			return audit.Entry{OrgID: sess.OrgID, ActorUserID: &sess.UserID, Kind: "branding.logo_uploaded", IP: clientIP(r),
				Payload: map[string]any{"asset_id": assetID, "content_type": ctype}}
		},
	)
	if err != nil {
		if errors.Is(err, malwarescan.ErrUnavailable) {
			writeScanError(w, err)
			return
		}
		if errors.Is(err, errOwnerMutationInput) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeDraftAuthoringError(w, "upload branding logo", err)
		return
	}
	committed = true
	logoURL := strings.TrimRight(s.PublicURL, "/") + "/branding/logo/" + sess.OrgID.String() + "-" + assetID.String() + ext
	writeJSON(w, http.StatusOK, map[string]any{"logo_url": logoURL, "key": key})

}

// GET /branding/logo/{org_id}{ext}  (public, no auth)
//
// Streams a logo back from MinIO so the signer page and the Gotenberg
// renderer can fetch it with a stable URL. The ext segment lets the
// browser cache by content type without us having to commit to a single
// mime; we resolve the actual key from MinIO directly.
func (s *Server) handleGetBrandingLogo(w http.ResponseWriter, r *http.Request) {
	if s.Storage == nil {
		writeError(w, http.StatusNotFound, "logo not found")
		return
	}
	param := chi.URLParam(r, "filename")
	dot := strings.LastIndex(param, ".")
	if dot < 0 || len(param) <= dot+1 {
		writeError(w, http.StatusBadRequest, "filename must include extension")
		return
	}
	idPart := param[:dot]
	assetPart := ""
	if len(idPart) == 73 && idPart[36] == '-' {
		assetPart, idPart = idPart[37:], idPart[:36]
		if _, err := uuid.Parse(assetPart); err != nil {
			writeError(w, http.StatusBadRequest, "invalid logo asset id")
			return
		}
	}
	extPart := strings.ToLower(param[dot:])
	orgID, err := uuid.Parse(idPart)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id in filename")
		return
	}
	if extPart != ".png" && extPart != ".jpg" && extPart != ".jpeg" && extPart != ".svg" {
		writeError(w, http.StatusBadRequest, "unsupported logo extension")
		return
	}
	key := fmt.Sprintf("branding/%s/logo%s", orgID.String(), extPart)
	if assetPart != "" {
		key = fmt.Sprintf("branding/%s/%s%s", orgID.String(), assetPart, extPart)
	}
	raw, err := s.Storage.Get(r.Context(), key)
	if err != nil {
		writeError(w, http.StatusNotFound, "logo not found")
		return
	}
	w.Header().Set("Content-Type", contentTypeOf(extPart))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(raw)
}

func extOf(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	return name[i:]
}

func contentTypeOf(ext string) string {
	switch ext {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".svg":
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

// resolveOrgBranding returns the resolved Branding for the given org or
// default if no row exists. Used by render paths via Server.resolveBrandingForDoc.
func (s *Server) resolveOrgBranding(ctx context.Context, orgID uuid.UUID) (branding.Branding, error) {
	if s.BrandingResolver == nil {
		return branding.DefaultBranding(), nil
	}
	return s.BrandingResolver.Resolve(ctx, orgID, uuid.Nil)
}

// resolveBrandingForDoc returns the branding for a specific document,
// honouring the per-doc override if present.
func (s *Server) resolveBrandingForDoc(ctx context.Context, doc *generated.Document) (branding.Branding, error) {
	if s.BrandingResolver == nil || doc == nil {
		return branding.DefaultBranding(), nil
	}
	return s.BrandingResolver.Resolve(ctx, doc.OrgID, doc.ID)
}

// mergeBrandingInput overlays caller-supplied non-empty fields onto the
// default, so missing fields don't blank out the existing palette.
func mergeBrandingInput(b branding.Branding, in brandingInput) branding.Branding {
	if in.PrimaryHex != "" {
		b.PrimaryHex = in.PrimaryHex
	}
	if in.AccentHex != "" {
		b.AccentHex = in.AccentHex
	}
	if in.SurfaceHex != "" {
		b.SurfaceHex = in.SurfaceHex
	}
	if in.TextHex != "" {
		b.TextHex = in.TextHex
	}
	if in.MutedHex != "" {
		b.MutedHex = in.MutedHex
	}
	if in.LogoURL != "" {
		b.LogoURL = in.LogoURL
	}
	if in.LogoAlt != "" {
		b.LogoAlt = in.LogoAlt
	}
	if in.FontHeading != "" {
		b.FontHeading = in.FontHeading
	}
	if in.FontBody != "" {
		b.FontBody = in.FontBody
	}
	if in.SignatureColor != "" {
		b.SignatureColor = in.SignatureColor
	}
	return b
}

func brandingFromOrgRow(row *generated.OrgBranding) branding.Branding {
	return branding.Branding{
		PrimaryHex:     row.PrimaryHex,
		AccentHex:      row.AccentHex,
		SurfaceHex:     row.SurfaceHex,
		TextHex:        row.TextHex,
		MutedHex:       row.MutedHex,
		LogoURL:        row.LogoUrl,
		LogoAlt:        row.LogoAlt,
		FontHeading:    row.FontHeading,
		FontBody:       row.FontBody,
		SignatureColor: row.SignatureColor,
	}
}

// guards (kept so unused imports don't pile up while we develop)
var (
	_ = errors.New
	_ = pgx.ErrNoRows
	_ = pgtype.Text{}
	_ = chi.URLParam
)
