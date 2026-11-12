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
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
)

const htmlTemplatePreviewTimeout = 15 * time.Second

type htmlTemplatePreviewInput struct {
	ExpectedVersion       int32         `json:"expected_version"`
	ExpectedContentSHA256 string        `json:"expected_content_sha256"`
	Values                htmlStringMap `json:"values,omitempty"`
	Sections              htmlStringMap `json:"sections,omitempty"`
}

// Samples affect this preview only. The exact saved defaults and section prose
// stay in the template commitment; a preview never writes documents or objects.
func materializeHTMLTemplatePreview(content htmlmaster.TemplateCommitment, samples htmlStringMap, sectionSamples ...htmlStringMap) (htmlmaster.Result, error) {
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
	var sections map[string]string
	if len(sectionSamples) > 0 {
		sections = sectionSamples[0]
	}
	return compiled.Materialize(htmlmaster.Input{Values: values, Sections: sections})
}

// Check saved and retained content under a short read transaction, then release
// all locks before scanner, renderer or parser work. Repeat after that work so a
// changed/archived design or revoked session never releases PDF bytes or proof.
func (s *Server) loadHTMLTemplatePreview(ctx context.Context, actor authoring.Actor, id uuid.UUID, version int32, digest string, values, sections map[string]string) (result htmlmaster.TemplateCommitment, closeConsumer func(), failure error) {
	return s.readHTMLTemplatePreviewV1(ctx, actor, id, version, digest, values, sections, false)
}

// The final check compares saved source and live authority only. Its discarded
// result cannot fund another materialization; the original content owner stays
// retained until the caller finishes serializing the exact PDF and its proof.
func (s *Server) recheckHTMLTemplatePreview(ctx context.Context, actor authoring.Actor, id uuid.UUID, version int32, digest string) (closeConsumer func(), failure error) {
	_, closeConsumer, failure = s.readHTMLTemplatePreviewV1(ctx, actor, id, version, digest, nil, nil, true)
	return closeConsumer, failure
}

func (s *Server) readHTMLTemplatePreviewV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, version int32, digest string, values, sections map[string]string, recheckOnly bool) (result htmlmaster.TemplateCommitment, closeConsumer func(), failure error) {
	o, err := s.openHTMLAuthoringV1(ctx, actor.OrgID, id)
	if err != nil {
		return result, nil, err
	}
	defer func() {
		_ = o.closeSQLV1(ctx)
		if closeConsumer == nil {
			o.closeConsumerV1(ctx)
		}
	}()
	err = o.session.WithTxV1(ctx, func(ctx context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		if err := o.reader.AcquireStringMapsV1(ctx, values, sections); err != nil {
			return err
		}
		template, revision, err := o.reader.ReadTemplateRevisionExpectedV1(ctx, id, version, digest)
		if errors.Is(err, pdfadmission.ErrHTMLAuthoringChangedV1) {
			return errHTMLTemplateConflict
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return errTemplateNotFound
		}
		if err != nil {
			return err
		}
		if template.Version != version || hex.EncodeToString(template.HtmlContentSha256) != digest {
			return errHTMLTemplateConflict
		}
		var response templateResponse
		if recheckOnly {
			current, readErr := o.reader.CanonicalCurrentTemplateV1(ctx, template.ID, template.Version)
			if readErr != nil {
				return readErr
			}
			retained, readErr := o.reader.CanonicalRetainedTemplateRecheckV1(ctx, revision.TemplateID, revision.Version)
			if readErr != nil {
				return readErr
			}
			response, err = toHTMLTemplateDetailCanonicalV1(template, revision, current, retained)
		} else {
			response, err = toHTMLTemplateDetailResponseOwnedV1(ctx, o.reader, template, revision)
		}
		if errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
			return err
		}
		if err != nil || response.ContentSHA256 != digest {
			return errHTMLTemplateConflict
		}
		guard, err := lockHTMLAuthorV1(ctx, tx, actor, false)
		if err != nil {
			return err
		}
		if err = guard.Recheck(ctx); err != nil {
			return err
		}
		result = htmlmaster.TemplateCommitment{MasterJSON: response.HTMLMasterJSON, DefaultsJSON: response.VariablesJSON, SHA256: digest}
		return nil
	})
	if err != nil {
		return htmlmaster.TemplateCommitment{}, nil, err
	}
	if err = o.session.CommitV1(ctx); err != nil {
		return htmlmaster.TemplateCommitment{}, nil, err
	}
	return result, func() { o.closeConsumerV1(ctx) }, nil
}

func (s *Server) checkHTMLTemplatePreviewAuthor(ctx context.Context, actor authoring.Actor) error {
	o, err := s.openHTMLAuthoringV1(ctx, actor.OrgID, actor.UserID)
	if err != nil {
		return err
	}
	defer o.closeConsumerV1(ctx)
	defer func() { _ = o.closeSQLV1(ctx) }()
	err = o.session.WithTxV1(ctx, func(ctx context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		guard, err := lockHTMLAuthorV1(ctx, tx, actor, false)
		if err != nil {
			return err
		}
		return guard.Recheck(ctx)
	})
	if err != nil {
		return err
	}
	return o.session.CommitV1(ctx)
}

func (s *Server) handlePreviewHTMLTemplate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), htmlTemplatePreviewTimeout)
	defer cancel()
	u, ok := requireSessionUser(w, ctx)
	if !ok {
		return
	}
	if !s.requireHTMLAuthoringRuntimeV1(w) {
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
	r, closeInput, inputOK := s.beginHTMLAuthoringInputV1(w, r, u.OrgID, pdfadmission.HTMLTemplatePreviewInputV1)
	if !inputOK {
		return
	}
	defer closeInput()
	var in htmlTemplatePreviewInput
	decodeErr := decodeSignerJSON(r, &in)
	if writeHTMLAuthoringInputFailureV1(w, decodeErr) {
		return
	}
	if decodeErr != nil || in.ExpectedVersion <= 0 || !htmlPreviewSHA256(in.ExpectedContentSHA256) {
		writeError(w, http.StatusBadRequest, "saved template version, lowercase content SHA-256 and declared string values are required")
		return
	}
	actor := authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}
	content, closeConsumer, err := s.loadHTMLTemplatePreview(ctx, actor, id, in.ExpectedVersion, in.ExpectedContentSHA256, in.Values, in.Sections)
	if err != nil {
		s.writeHTMLTemplateError(w, "load HTML template preview", err)
		return
	}
	defer closeConsumer()
	cleaned, pages, materializationSHA, err := s.renderHTMLTemplatePDFV1(ctx, actor, content, in)
	if err != nil {
		if errors.Is(err, errHTMLTemplatePreviewRenderV1) {
			writeError(w, http.StatusServiceUnavailable, errHTMLTemplatePreviewRenderV1.Error())
		} else if !writePDFWorkerError(w, err) {
			if errors.Is(err, malwarescan.ErrDetected) || errors.Is(err, malwarescan.ErrUnavailable) {
				writeScanError(w, err)
			} else if errors.Is(err, errHTMLTemplatePreviewInvalidV1) {
				writeError(w, http.StatusBadRequest, errHTMLTemplatePreviewInvalidV1.Error())
			} else {
				s.writeHTMLTemplateError(w, "render HTML template preview", err)
			}
		}
		return
	}
	pdfDigest := sha256.Sum256(cleaned.Bytes)
	now := time.Now().UTC()
	receipt := htmlTemplatePreviewReceipt{SchemaVersion: 1, PreviewID: uuid.New(), OrgID: u.OrgID, ReviewerID: u.UserID,
		TemplateID: id, Version: in.ExpectedVersion, TemplateContentSHA256: content.SHA256,
		MaterializationSHA256: materializationSHA, PDFSHA256: hex.EncodeToString(pdfDigest[:]), PageCount: pages,
		SessionSHA256: htmlPreviewSessionSHA256(cookie.Value), IssuedAt: now, ExpiresAt: now.Add(htmlTemplatePreviewTTL)}
	token, err := s.mintHTMLTemplatePreviewReceipt(receipt)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "HTML template preview proof unavailable")
		return
	}
	closeRecheck, err := s.recheckHTMLTemplatePreview(ctx, actor, id, in.ExpectedVersion, in.ExpectedContentSHA256)
	if err != nil {
		s.writeHTMLTemplateError(w, "recheck HTML template preview", err)
		return
	}
	closeRecheck()
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
	h.Set("X-Hash-Materialization-SHA256", materializationSHA)
	h.Set("X-Hash-PDF-SHA256", receipt.PDFSHA256)
	h.Set("X-Hash-PDF-Pages", strconv.Itoa(pages))
	h.Set("X-Hash-Preview-Receipt", token)
	h.Set("X-Hash-Preview-Expires-At", receipt.ExpiresAt.UTC().Format(time.RFC3339Nano))
	setDocumentPreviewHeaders(w, false)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cleaned.Bytes)
}

var errHTMLTemplatePreviewRenderV1 = errors.New("HTML template preview rendering unavailable")
var errHTMLTemplatePreviewInvalidV1 = errors.New("rendered template preview could not be accepted")
var errHTMLTemplatePreviewOutputLimitV1 = errors.New("rendered template preview exceeds byte policy")

// The two transports share rendering, production PDF sanitization, signing-page
// composition and the original credential check. The caller retains content's
// native owner until the exact PDF response has been serialized.
func (s *Server) renderHTMLTemplatePDFV1(ctx context.Context, actor authoring.Actor, content htmlmaster.TemplateCommitment, in htmlTemplatePreviewInput) (cleaned sanitize.Result, pages int, materializationSHA string, failure error) {
	if err := scanHTMLMaster(ctx, content.MasterJSON); err != nil {
		return cleaned, 0, "", err
	}
	rendered, err := materializeHTMLTemplatePreview(content, in.Values, in.Sections)
	if err != nil {
		return cleaned, 0, "", err
	}
	if err = s.checkHTMLTemplatePreviewAuthor(ctx, actor); err != nil {
		return cleaned, 0, "", err
	}
	pdf, err := s.Sign.PDF.HTMLToPDF(ctx, rendered.HTML, render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms"})
	if err != nil {
		if errors.Is(err, render.ErrPDFResponseTooLarge) {
			return cleaned, 0, "", errors.Join(errHTMLTemplatePreviewRenderV1, render.ErrPDFResponseTooLarge)
		}
		return cleaned, 0, "", errHTMLTemplatePreviewRenderV1
	}
	if len(pdf) == 0 {
		return cleaned, 0, "", errHTMLTemplatePreviewInvalidV1
	}
	if len(pdf) > sanitize.MaxPDFBytes {
		return cleaned, 0, "", errors.Join(errHTMLTemplatePreviewInvalidV1, errHTMLTemplatePreviewOutputLimitV1)
	}
	master, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		return cleaned, 0, "", err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return cleaned, 0, "", err
	}
	if compiled.SigningPagePolicy() != nil {
		values := map[string]string{}
		if err = json.Unmarshal(content.DefaultsJSON, &values); err != nil {
			return cleaned, 0, "", errHTMLTemplatePreviewInvalidV1
		}
		for name, value := range in.Values {
			values[name] = value
		}
		composed, e := s.composeHTMLSigningPage(ctx, compiled, htmlmaster.Input{Values: values, Sections: in.Sections}, pdf)
		err = e
		if err == nil {
			cleaned = composed.Result
			pages = composed.Composition.FinalPages
		}
	} else {
		cleaned, err = sanitize.CleanWithContext(ctx, "html-template-preview", "application/pdf", pdf)
	}
	if err != nil {
		return cleaned, 0, "", errors.Join(errHTMLTemplatePreviewInvalidV1, err)
	}
	if pages == 0 {
		pages, err = sanitize.PageCountWithContext(ctx, cleaned.Bytes)
	}
	if err != nil || cleaned.Report.UnsupportedT || len(cleaned.Bytes) == 0 || len(cleaned.Bytes) > sanitize.MaxPDFBytes || pages <= 0 || pages > sanitize.MaxPDFPages {
		return cleaned, 0, "", errors.Join(errHTMLTemplatePreviewInvalidV1, err)
	}
	return cleaned, pages, rendered.ContentDigest, nil
}
