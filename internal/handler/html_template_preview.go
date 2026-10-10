// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
)

const htmlTemplatePreviewTimeout = 15 * time.Second

type htmlTemplatePreviewInput struct {
	ExpectedVersion       int32         `json:"expected_version"`
	ExpectedContentSHA256 string        `json:"expected_content_sha256"`
	Values                htmlStringMap `json:"values,omitempty"`
}

// Samples affect this preview only. The exact saved defaults and section prose
// stay in the template commitment; a preview never writes documents or objects.
func materializeHTMLTemplatePreview(content htmlmaster.TemplateCommitment, samples htmlStringMap) (htmlmaster.Result, error) {
	master, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		return htmlmaster.Result{}, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return htmlmaster.Result{}, err
	}
	values := map[string]string{}
	if err := json.Unmarshal(content.DefaultsJSON, &values); err != nil || values == nil {
		return htmlmaster.Result{}, errHTMLTemplateConflict
	}
	for name, value := range samples {
		values[name] = value
	}
	return compiled.Materialize(htmlmaster.Input{Values: values})
}

// Check saved and retained content under a short read transaction, then release
// all locks before scanner, renderer or parser work. Repeat after that work so a
// changed/archived design or revoked session never releases PDF bytes or proof.
func (s *Server) loadHTMLTemplatePreview(ctx context.Context, actor authoring.Actor, id uuid.UUID, version int32, digest string) (htmlmaster.TemplateCommitment, error) {
	var empty htmlmaster.TemplateCommitment
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return empty, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := generated.New(tx)
	template, err := q.GetHTMLTemplateForShare(ctx, generated.GetHTMLTemplateForShareParams{ID: id, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, errTemplateNotFound
	}
	if err != nil {
		return empty, err
	}
	if template.Version != version || hex.EncodeToString(template.HtmlContentSha256) != digest {
		return empty, errHTMLTemplateConflict
	}
	revision, err := q.GetHTMLTemplateRevisionForShare(ctx, generated.GetHTMLTemplateRevisionForShareParams{TemplateID: id, OrgID: actor.OrgID, Version: version})
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, errHTMLTemplateConflict
	}
	if err != nil {
		return empty, err
	}
	response, err := toHTMLTemplateDetailResponse(template, revision)
	if err != nil || response.ContentSHA256 != digest {
		return empty, errHTMLTemplateConflict
	}
	guard, err := authoring.LockAuthor(ctx, tx, actor)
	if err != nil {
		return empty, err
	}
	if err := guard.Recheck(ctx); err != nil {
		return empty, err
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, err
	}
	return htmlmaster.TemplateCommitment{MasterJSON: response.HTMLMasterJSON, DefaultsJSON: response.VariablesJSON, SHA256: digest}, nil
}

func (s *Server) checkHTMLTemplatePreviewAuthor(ctx context.Context, actor authoring.Actor) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockAuthor(ctx, tx, actor)
	if err != nil {
		return err
	}
	if err := guard.Recheck(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) handlePreviewHTMLTemplate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), htmlTemplatePreviewTimeout)
	defer cancel()
	u, ok := requireSessionUser(w, ctx)
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML template preview", err)
		return
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		s.writeDraftAuthoringError(w, "authorize HTML template preview", errHTMLTemplatePreviewReceipt)
		return
	}
	if s.Pool == nil || s.Cookies == nil || s.Sign == nil || s.Sign.PDF == nil {
		writeError(w, http.StatusServiceUnavailable, "HTML template preview dependencies unavailable")
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "HTML template preview capacity exceeded")
		return
	}
	defer release()
	var in htmlTemplatePreviewInput
	if err := decodeSignerJSON(r, &in); err != nil || in.ExpectedVersion <= 0 || !htmlPreviewSHA256(in.ExpectedContentSHA256) {
		writeError(w, http.StatusBadRequest, "saved template version, lowercase content SHA-256 and declared string values are required")
		return
	}
	actor := authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}
	content, err := s.loadHTMLTemplatePreview(ctx, actor, id, in.ExpectedVersion, in.ExpectedContentSHA256)
	if err != nil {
		s.writeHTMLTemplateError(w, "load HTML template preview", err)
		return
	}
	if err := scanHTMLMaster(ctx, content.MasterJSON); err != nil {
		writeScanError(w, err)
		return
	}
	rendered, err := materializeHTMLTemplatePreview(content, in.Values)
	if err != nil {
		s.writeHTMLTemplateError(w, "materialize HTML template preview", err)
		return
	}
	// Scanning and materialization may wait; never start Chromium with an already
	// expired/revoked original credential even though its output would be refused.
	if err := s.checkHTMLTemplatePreviewAuthor(ctx, actor); err != nil {
		s.writeHTMLTemplateError(w, "authorize HTML template preview render", err)
		return
	}
	pdf, err := s.Sign.PDF.HTMLToPDF(ctx, rendered.HTML, render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms"})
	if err != nil {
		// Provider diagnostics can echo submitted text. Do not log or return them.
		writeError(w, http.StatusServiceUnavailable, "HTML template preview rendering unavailable")
		return
	}
	if len(pdf) == 0 || len(pdf) > sanitize.MaxPDFBytes {
		writeError(w, http.StatusBadRequest, "rendered template preview could not be accepted")
		return
	}
	cleaned, err := sanitize.CleanWithContext(ctx, "html-template-preview", "application/pdf", pdf)
	if err != nil {
		if writePDFWorkerError(w, err) {
			return
		}
		if errors.Is(err, malwarescan.ErrDetected) || errors.Is(err, malwarescan.ErrUnavailable) {
			writeScanError(w, err)
			return
		}
		writeError(w, http.StatusBadRequest, "rendered template preview could not be accepted")
		return
	}
	pages, err := sanitize.PageCountWithContext(ctx, cleaned.Bytes)
	if err != nil || cleaned.Report.UnsupportedT || len(cleaned.Bytes) == 0 || len(cleaned.Bytes) > sanitize.MaxPDFBytes || pages <= 0 || pages > sanitize.MaxPDFPages {
		if writePDFWorkerError(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "rendered template preview could not be accepted")
		return
	}
	pdfDigest := sha256.Sum256(cleaned.Bytes)
	now := time.Now().UTC()
	receipt := htmlTemplatePreviewReceipt{SchemaVersion: 1, PreviewID: uuid.New(), OrgID: u.OrgID, ReviewerID: u.UserID,
		TemplateID: id, Version: in.ExpectedVersion, TemplateContentSHA256: content.SHA256,
		MaterializationSHA256: rendered.ContentDigest, PDFSHA256: hex.EncodeToString(pdfDigest[:]), PageCount: pages,
		SessionSHA256: htmlPreviewSessionSHA256(cookie.Value), IssuedAt: now, ExpiresAt: now.Add(htmlTemplatePreviewTTL)}
	token, err := s.mintHTMLTemplatePreviewReceipt(receipt)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "HTML template preview proof unavailable")
		return
	}
	if _, err := s.loadHTMLTemplatePreview(ctx, actor, id, in.ExpectedVersion, in.ExpectedContentSHA256); err != nil {
		s.writeHTMLTemplateError(w, "recheck HTML template preview", err)
		return
	}
	if err := receipt.validate(time.Now()); err != nil || ctx.Err() != nil {
		writeError(w, http.StatusServiceUnavailable, "HTML template preview expired before completion")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/pdf")
	h.Set("Content-Disposition", "inline")
	h.Set("Content-Length", strconv.Itoa(len(cleaned.Bytes)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Hash-Template-Id", id.String())
	h.Set("X-Hash-Template-Version", strconv.FormatInt(int64(in.ExpectedVersion), 10))
	h.Set("X-Hash-Template-Content-SHA256", content.SHA256)
	h.Set("X-Hash-Materialization-SHA256", rendered.ContentDigest)
	h.Set("X-Hash-PDF-SHA256", receipt.PDFSHA256)
	h.Set("X-Hash-PDF-Pages", strconv.Itoa(pages))
	h.Set("X-Hash-Preview-Receipt", token)
	h.Set("X-Hash-Preview-Expires-At", receipt.ExpiresAt.UTC().Format(time.RFC3339Nano))
	setDocumentPreviewHeaders(w, false)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cleaned.Bytes)
}
