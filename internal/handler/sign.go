// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
)

// Magic-link signer handlers. No session auth; the URL token IS the auth.
//
// Routes:
//   GET  /sign/{token}                 → recipient + document context (JSON)
//   GET  /sign/{token}/document        → rendered HTML preview (browser display)
//   POST /sign/{token}/view            → idempotent view-tracking ping
//   POST /sign/{token}/sign            → finalize signature
//   POST /sign/{token}/decline         → decline with reason

type signerContextResponse struct {
	DocumentID        uuid.UUID `json:"document_id"`
	DocumentName      string    `json:"document_name"`
	Status            string    `json:"status"`
	SourceKind        string    `json:"source_kind"`
	RequiresSignature bool      `json:"requires_signature"`
	RoutingTier       string    `json:"routing_tier"`
	Recipient         struct {
		ID     uuid.UUID `json:"id"`
		Email  string    `json:"email"`
		Name   string    `json:"name"`
		Role   string    `json:"role"`
		Status string    `json:"status"`
		Locale string    `json:"locale"`
	} `json:"recipient"`
	Fonts          []string              `json:"fonts"`
	PDFObservation *signerPDFObservation `json:"pdf_observation,omitempty"`

	// Privacy is the GDPR Article 13 transparency payload the signer
	// page renders inline. Surfacing it here (rather than only on a
	// remote /legal/privacy page) means the recipient sees who is
	// processing their data at the moment of collection, not buried
	// in a footer link.
	Privacy signerPrivacyNotice `json:"privacy"`
}

type signerPrivacyNotice struct {
	Controller        string                   `json:"controller"`         // sender org name frozen at send
	ControllerContact string                   `json:"controller_contact"` // sending controller contact frozen at send
	Processor         string                   `json:"processor"`          // Hash instance owner
	ProcessorEmail    string                   `json:"processor_email"`    // DPO contact
	PurposeSummary    string                   `json:"purpose_summary"`
	LegalBasis        string                   `json:"legal_basis"` // document-specific controller selection
	RetentionYears    int                      `json:"retention_years"`
	JurisdictionDP    string                   `json:"jurisdiction_dp"` // supervisory authority
	PolicyURL         string                   `json:"policy_url"`
	DSREndpoint       string                   `json:"dsr_endpoint"`  // POST /sign/{token}/dsr
	NoticeDigest      string                   `json:"notice_digest"` // changes whenever material notice/ceremony context changes
	Copy              sign.Article13NoticeCopy `json:"copy"`
}

// signerNoticeDigestHeader carries the exact server-authored notice digest on
// each participant mutation. It is evidence metadata rather than a credential;
// the URL token remains the sole bearer secret.
const signerNoticeDigestHeader = "X-Hash-Notice-Digest"

// requireSignerNoticeAcknowledgement closes the direct-POST bypass around the
// signer page's Article 13 gate. The canonical server digest (not the untrusted
// header value) and its canonical snapshot are returned for binding into the
// resulting durable audit evidence.
func (s *Server) requireSignerNoticeAcknowledgement(w http.ResponseWriter, r *http.Request, rc *sign.RecipientContext) (sign.Article13NoticeEvidence, bool) {
	notice, err := s.signerPrivacyNotice(r, rc)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		return sign.Article13NoticeEvidence{}, false
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		return sign.Article13NoticeEvidence{}, false
	}
	digest := evidence.Digest
	values := r.Header.Values(signerNoticeDigestHeader)
	if digest == "" || digest != notice.NoticeDigest || len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(digest)) != 1 {
		writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		return sign.Article13NoticeEvidence{}, false
	}
	return evidence, true
}

func bindSignerNoticeAuditPayload(notice sign.Article13NoticeEvidence, payload map[string]any) (map[string]any, error) {
	if payload == nil {
		payload = make(map[string]any)
	}
	if err := notice.BindAuditPayload(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// handleSignerRoot serves GET /sign/{token}. A browser navigating to the magic
// link wants the SPA signer ceremony page (HTML); the SPA itself then fetches the
// same URL for the JSON context. Both hit this bare path (the SPA calls
// fetch(`/sign/${token}`)), and StripSlashes collapses the trailing slash, so the
// API route would otherwise shadow the page and the signer would see raw JSON.
// Branch on the request: a top-level document navigation gets the SPA shell, an
// XHR/fetch (or any non-browser client) gets the JSON context.
func (s *Server) handleSignerRoot(w http.ResponseWriter, r *http.Request) {
	if s.Frontend != nil && isDocumentNavigation(r) {
		s.Frontend.ServeHTTP(w, r)
		return
	}
	s.handleSignerContext(w, r)
}

// isDocumentNavigation reports whether the request is a top-level browser page
// navigation (vs an XHR/fetch). Prefers the Sec-Fetch-Dest hint (sent by all
// modern browsers); falls back to the Accept header. The SPA's fetch() sends
// Accept: */* and Sec-Fetch-Dest: empty, so it is correctly treated as an API call.
func isDocumentNavigation(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document":
		return true
	case "empty", "cors", "websocket":
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (s *Server) handleSignerContext(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	out := signerContextResponse{
		DocumentID:        rc.Document.ID,
		DocumentName:      rc.Document.Name,
		Status:            rc.Document.Status,
		SourceKind:        rc.Document.SourceKind,
		RequiresSignature: rc.Document.RequiresSignature,
		RoutingTier:       rc.Document.RoutingTier,
		Fonts:             []string{"Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple"},
	}
	out.Recipient.ID = rc.Recipient.ID
	out.Recipient.Email = rc.Recipient.Email
	out.Recipient.Name = rc.Recipient.Name
	out.Recipient.Role = rc.Recipient.Role
	out.Recipient.Status = rc.Recipient.Status
	out.Recipient.Locale = rc.Recipient.Locale
	observation, err := s.captureSignerReadObservation(r, rc)
	if err != nil {
		writeSignerReadError(w, err)
		return
	}
	if err := s.recheckSignerRead(r, rc, observation); err != nil {
		writeSignerReadError(w, err)
		return
	}
	out.Privacy = observation.notice
	out.PDFObservation = observation.pdf
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) signerPrivacyNotice(r *http.Request, rc *sign.RecipientContext) (signerPrivacyNotice, error) {
	if rc == nil || rc.Recipient == nil || rc.Document == nil || rc.ControllerOrg == nil ||
		rc.ControllerOrg.ID != rc.Document.OrgID {
		return signerPrivacyNotice{}, sign.ErrSignerControllerUnavailable
	}
	confirmation := rc.LawfulBasisConfirmation
	if confirmation == nil || !confirmation.ConfirmedAt.Valid ||
		confirmation.DocumentID != rc.Document.ID || confirmation.OrgID != rc.Document.OrgID ||
		strings.TrimSpace(confirmation.LawfulBasis) != strings.TrimSpace(rc.Document.LawfulBasis) ||
		strings.TrimSpace(confirmation.ControllerName) == "" ||
		strings.TrimSpace(confirmation.ControllerContact) == "" {
		return signerPrivacyNotice{}, sign.ErrSignerLawfulBasisUnavailable
	}
	controller := strings.TrimSpace(confirmation.ControllerName)
	controllerContact := strings.TrimSpace(confirmation.ControllerContact)
	legalBasis, err := article13.LegalBasisDisclosureV1(rc.Document.LawfulBasis)
	if err != nil {
		return signerPrivacyNotice{}, err
	}
	operator := strings.TrimSpace(s.OperatorName)
	privacyContact := strings.TrimSpace(s.PrivacyContact)
	supervisoryAuthority := strings.TrimSpace(s.SupervisoryAuthority)
	policyURL := strings.TrimSpace(s.PrivacyPolicyURL)
	if operator == "" || privacyContact == "" || supervisoryAuthority == "" || policyURL == "" {
		return signerPrivacyNotice{}, errors.New("signer privacy disclosure instance identity is unavailable")
	}
	if !rc.Document.SentAt.Valid || rc.Document.SentAt.Time.IsZero() {
		return signerPrivacyNotice{}, sign.ErrSignerLawfulBasisUnavailable
	}
	notice := signerPrivacyNotice{
		Controller:        controller,
		ControllerContact: controllerContact,
		Processor:         operator,
		ProcessorEmail:    privacyContact,
		// The signer SPA is intentionally English-only until every legal string
		// has received counsel-reviewed translations. Keep the server-authored
		// disclosure in that same language so the ceremony cannot mix locales.
		PurposeSummary: article13.PurposeSummaryV1(rc.Document.Name),
		LegalBasis:     legalBasis,
		RetentionYears: article13.RetentionYearsV1,
		JurisdictionDP: supervisoryAuthority,
		PolicyURL:      policyURL,
		DSREndpoint:    "/sign/" + chi.URLParam(r, "token") + "/dsr",
	}
	notice.Copy = article13.RenderedCopyV1(rc.Document.Name)
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		return signerPrivacyNotice{}, errors.New("signer privacy disclosure digest is unavailable")
	}
	notice.NoticeDigest = evidence.Digest
	return notice, nil
}

func signerArticle13NoticeEvidence(rc *sign.RecipientContext, notice signerPrivacyNotice) (sign.Article13NoticeEvidence, error) {
	if rc == nil || rc.Document == nil || rc.Recipient == nil {
		return sign.Article13NoticeEvidence{}, sign.ErrInvalidNoticeEvidence
	}
	snapshot, err := article13.NewSnapshotForSchema(rc.Document.Article13NoticeSchema, article13.Input{
		DocumentID: rc.Document.ID, OrgID: rc.Document.OrgID, RecipientID: rc.Recipient.ID,
		SentAt:     rc.Document.SentAt.Time,
		Controller: notice.Controller, ControllerContact: notice.ControllerContact,
		Processor: notice.Processor, ProcessorContact: notice.ProcessorEmail,
		PurposeSummary: notice.PurposeSummary, LegalBasisDisclosure: notice.LegalBasis,
		RetentionYears: notice.RetentionYears, SupervisoryAuthority: notice.JurisdictionDP,
		PolicyURL: notice.PolicyURL, DSRCapability: article13.DSRCapabilitySignerRequest,
		Copy: notice.Copy,
	})
	if err != nil {
		return sign.Article13NoticeEvidence{}, err
	}
	return article13.NewEvidence(snapshot)
}

func (s *Server) handleSignerDocument(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	if rc.Document.SourceKind != "blocks" {
		writeError(w, http.StatusBadRequest, "pdf-source documents not yet renderable inline")
		return
	}
	observation, err := s.captureSignerReadObservation(r, rc)
	if err != nil {
		writeSignerReadError(w, err)
		return
	}
	// Reuse the same renderer the sender preview uses, so the signer sees
	// exactly what the sender approved (variables + conditionals applied).
	html, err := s.Sign.RenderForSigner(r.Context(), rc)
	if err != nil {
		writeInternalErrorMsg(w, "render preview", err)
		return
	}
	if err := s.recheckSignerRead(r, rc, observation); err != nil {
		writeSignerReadError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

func (s *Server) handleSignerView(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrErrorV1(w, r, pdfadmission.SignerReadDiagnosticViewV1)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	if err := s.Sign.MarkViewed(r.Context(), rc, sign.ParticipantResponseEvidence{
		IP: clientIP(r), UserAgent: r.UserAgent(), Notice: noticeEvidence,
	}); err != nil {
		if errors.Is(err, sign.ErrInvalidNoticeEvidence) {
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
			return
		}
		if errors.Is(err, sign.ErrDocumentNotSignable) {
			writeError(w, http.StatusConflict, "this document is no longer active")
			return
		}
		if errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) || errors.Is(err, sign.ErrMagicLinkExpired) {
			if errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) {
				s.Sign.LogSignerViewRefusalV1(r.Context(), rc)
			}
			writeSignerReadError(w, err)
			return
		}
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "viewed"})
}

type signerSignInput struct {
	PackageResponse *documentpackage.ResponseV1 `json:"package_response,omitempty"`
	TypedName       string                      `json:"typed_name"`
	Font            string                      `json:"font"`
}

type signerSignResponse struct {
	Status           string `json:"status"`
	Completed        bool   `json:"completed"`
	FinalPDFURL      string `json:"final_pdf_url,omitempty"`
	AuditCertURL     string `json:"audit_cert_url,omitempty"`
	PackagePortalURL string `json:"package_portal_url,omitempty"`
}

func (s *Server) handleSignerSign(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	var in signerSignInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.Sign.Sign(r.Context(), rc, sign.SignInput{
		PackageResponse: in.PackageResponse,
		TypedName:       in.TypedName,
		Font:            in.Font,
		IP:              clientIP(r),
		UserAgent:       r.UserAgent(),
		Notice:          noticeEvidence,
	})
	if err != nil {
		switch {
		case errors.Is(err, sign.ErrMagicLinkExpired):
			writeError(w, http.StatusGone, "magic link expired")
		case errors.Is(err, sign.ErrPackageResponseRequiredV1):
			writeError(w, http.StatusPreconditionRequired, "review and explicitly consent to the current complete contract package")
		case errors.Is(err, sign.ErrPackageResponseChangedV1):
			writeError(w, http.StatusPreconditionFailed, "the contract package changed; reload and review it before continuing")
		case errors.Is(err, documentpackage.ErrResponseV1):
			writeError(w, http.StatusBadRequest, "invalid whole-package consent")
		case errors.Is(err, sign.ErrPackageResponseUnavailableV1):
			writeError(w, http.StatusServiceUnavailable, "package response is temporarily unavailable")
		case errors.Is(err, sign.ErrInvalidNoticeEvidence):
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		case errors.Is(err, sign.ErrSigningAdmissionUnavailableV1):
			writeError(w, http.StatusServiceUnavailable, "signing is temporarily unavailable")
		case errors.Is(err, sign.ErrParticipantReportCapacityV1):
			writeError(w, http.StatusConflict, "this negotiation's evidence report has reached Hash's size limit; contact the sender before continuing")
		case errors.Is(err, sign.ErrSignatureTierUnavailable):
			writeError(w, http.StatusConflict, "AES and QES signing are temporarily unavailable; this document cannot be completed through the SES endpoint")
		case errors.Is(err, sign.ErrAlreadySigned):
			writeError(w, http.StatusConflict, "you have already signed this document")
		case errors.Is(err, sign.ErrSignaturePreparationChanged):
			writeError(w, http.StatusConflict, "the document or signature placement changed; reload it before signing")
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting signatures")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	out := signerSignResponse{
		Status:           res.Status,
		Completed:        res.Completed,
		FinalPDFURL:      res.FinalPDFURL,
		AuditCertURL:     res.AuditCertURL,
		PackagePortalURL: res.PackagePortalURL,
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSignerAccept records a recipient's acknowledgement (accept) of a
// no-signature document. The audit event is the record; no signature is captured.
type signerAcceptInput struct {
	PackageResponse *documentpackage.ResponseV1 `json:"package_response,omitempty"`
}

func (s *Server) handleSignerAccept(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	var in signerAcceptInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.Sign.Accept(r.Context(), rc, sign.ParticipantResponseEvidence{
		IP: clientIP(r), UserAgent: r.UserAgent(), Notice: noticeEvidence, PackageResponse: in.PackageResponse,
	})
	if err != nil {
		switch {
		case errors.Is(err, sign.ErrMagicLinkExpired):
			writeError(w, http.StatusGone, "magic link expired")
		case errors.Is(err, sign.ErrPackageResponseRequiredV1):
			writeError(w, http.StatusPreconditionRequired, "review and explicitly consent to the current complete contract package")
		case errors.Is(err, sign.ErrPackageResponseChangedV1):
			writeError(w, http.StatusPreconditionFailed, "the contract package changed; reload and review it before continuing")
		case errors.Is(err, documentpackage.ErrResponseV1):
			writeError(w, http.StatusBadRequest, "invalid whole-package consent")
		case errors.Is(err, sign.ErrPackageResponseUnavailableV1):
			writeError(w, http.StatusServiceUnavailable, "package response is temporarily unavailable")
		case errors.Is(err, sign.ErrInvalidNoticeEvidence):
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		case errors.Is(err, sign.ErrSigningAdmissionUnavailableV1):
			writeError(w, http.StatusServiceUnavailable, "acknowledgement is temporarily unavailable")
		case errors.Is(err, sign.ErrParticipantReportCapacityV1):
			writeError(w, http.StatusConflict, "this negotiation's evidence report has reached Hash's size limit; contact the sender before continuing")
		case errors.Is(err, sign.ErrSignatureTierUnavailable):
			writeError(w, http.StatusConflict, "AES and QES response flows are temporarily unavailable")
		case errors.Is(err, sign.ErrAlreadyAccepted):
			writeError(w, http.StatusConflict, "you have already accepted this document")
		case errors.Is(err, sign.ErrNotAcknowledgement):
			writeError(w, http.StatusBadRequest, "this document requires a signature")
		case errors.Is(err, sign.ErrRecipientNotEligibleForResponse):
			writeError(w, http.StatusForbidden, "this recipient role cannot acknowledge the document")
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting responses")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	out := signerSignResponse{Status: res.Status, Completed: res.Completed, FinalPDFURL: res.FinalPDFURL, AuditCertURL: res.AuditCertURL, PackagePortalURL: res.PackagePortalURL}
	writeJSON(w, http.StatusOK, out)
}

type signerDeclineInput struct {
	Reason string `json:"reason"`
}

func (s *Server) handleSignerDecline(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	var in signerDeclineInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Sign.Decline(r.Context(), rc, in.Reason, sign.ParticipantResponseEvidence{
		IP: clientIP(r), UserAgent: r.UserAgent(), Notice: noticeEvidence,
	}); err != nil {
		switch {
		case errors.Is(err, sign.ErrInvalidNoticeEvidence):
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		case errors.Is(err, sign.ErrEnvelopeTransitionUnsupported):
			writeError(w, http.StatusConflict, "declining an envelope is not supported; ask the sender to void the envelope")
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting changes")
		case errors.Is(err, sign.ErrAlreadySigned):
			writeError(w, http.StatusConflict, "you have already signed this document")
		case errors.Is(err, sign.ErrAlreadyAccepted):
			writeError(w, http.StatusConflict, "you have already acknowledged this document")
		case errors.Is(err, sign.ErrRecipientNotEligibleForResponse):
			writeError(w, http.StatusForbidden, "this recipient role cannot decline the document")
		default:
			writeInternalError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "declined"})
}

type signerRequestChangesInput struct {
	Message  string `json:"message"`
	BlockID  string `json:"block_id"`
	Quote    string `json:"quote"`
	Context  string `json:"context"`
	Proposed string `json:"proposed"`
}

func (s *Server) handleSignerRequestChanges(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	var in signerRequestChangesInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Sign.RequestChanges(r.Context(), rc, sign.ChangeRequestInput{
		Message:   in.Message,
		BlockID:   in.BlockID,
		Quote:     in.Quote,
		Context:   in.Context,
		Proposed:  in.Proposed,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		Notice:    noticeEvidence,
	}); err != nil {
		switch {
		case errors.Is(err, sign.ErrInvalidNoticeEvidence):
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		case errors.Is(err, sign.ErrEnvelopeTransitionUnsupported):
			writeError(w, http.StatusConflict, "change requests are not supported for envelopes")
		case errors.Is(err, sign.ErrRevisionWouldDestroyEvidence):
			writeError(w, http.StatusConflict, "changes cannot be requested after a legal response has been captured")
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting changes")
		case errors.Is(err, sign.ErrSigningAdmissionUnavailableV1):
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusServiceUnavailable, "change requests temporarily unavailable")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "changes_requested"})
}

func (s *Server) handleSignerListComments(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrErrorV1(w, r, pdfadmission.SignerReadDiagnosticCommentsV1)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	observed, err := s.captureSignerReadObservation(r, rc)
	if err != nil {
		writeSignerReadError(w, err)
		return
	}
	page, err := s.Sign.SignerCommentPageV1(r.Context(), rc, r.URL.RawQuery, func(fresh *sign.RecipientContext) error {
		return s.validateSignerReadObservation(r, rc, observed, fresh)
	})
	if err != nil {
		s.writeCommentPageErrorV1(w, err)
		return
	}
	defer page.CloseConsumerV1()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page.JSON)
}

func (s *Server) handleSignerCreateComment(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	input, err := s.Sign.NewSignerCommentHTTPInputV1(r.Context(), rc)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeSignerReadError(w, errors.Join(sign.ErrSigningAdmissionUnavailableV1, err))
		return
	}
	defer input.CloseConsumerV1()
	raw, finishDecode, err := input.ReadSignerJSONV1(r.Context(), r.Body)
	if err != nil {
		if errors.Is(err, pdfadmission.ErrCommentInputV1) {
			w.Header().Set("Retry-After", "1")
			writeSignerReadError(w, errors.Join(sign.ErrSigningAdmissionUnavailableV1, err))
		} else {
			writeError(w, http.StatusBadRequest, "invalid json")
		}
		return
	}
	defer finishDecode()
	var in createCommentInput
	if err = decodeSignerJSONBytesV1(raw, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err = input.CaptureSignerBodyV1(r.Context(), in.Body); err != nil {
		w.Header().Set("Retry-After", "1")
		writeSignerReadError(w, errors.Join(sign.ErrSigningAdmissionUnavailableV1, err))
		return
	}
	c, err := s.Sign.SignerCommentOwnedV1(rc, input, sign.ParticipantResponseEvidence{IP: clientIP(r), UserAgent: r.UserAgent(), Notice: noticeEvidence})
	if err != nil {
		switch {
		case errors.Is(err, sign.ErrInvalidNoticeEvidence):
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		case errors.Is(err, sign.ErrDocumentNotSignable), errors.Is(err, sign.ErrDocumentNotCommentable):
			writeError(w, http.StatusConflict, "this document is not accepting comments")
		case errors.Is(err, sign.ErrInvalidCommentBody):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, sign.ErrSigningAdmissionUnavailableV1):
			w.Header().Set("Retry-After", "1")
			writeSignerReadError(w, err)
		case errors.Is(err, sign.ErrMagicLinkExpired):
			writeSignerReadError(w, err)
		default:
			writeInternalErrorMsg(w, "post signer comment", err)
		}
		return
	}
	defer c.CloseConsumerV1()
	writeJSON(w, http.StatusCreated, toCommentResponse(c.DocumentComment))
}

// Completed artifact routes share the rotated read-only credential and the
// download rate limits. Certificate access additionally binds its own pins.
func (s *Server) handleSignerFinalPDF(w http.ResponseWriter, r *http.Request) {
	s.handleCompletedArtifactDownloadV1(w, r, false)
}

func (s *Server) handleSignerAuditCert(w http.ResponseWriter, r *http.Request) {
	s.handleCompletedArtifactDownloadV1(w, r, true)
}

func (s *Server) handleCompletedArtifactDownloadV1(w http.ResponseWriter, r *http.Request, certificate bool) {
	w.Header().Set("Cache-Control", "no-store")
	tok := chi.URLParam(r, "token")
	if tok == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return
	}
	tokenHash := auth.HashMagicToken(tok)
	lookup := s.Sign.LookupCompletedArtifactByToken
	recheck := s.Sign.RecheckCompletedArtifactByToken
	unavailable, suffix := "signed pdf not available", ".pdf"
	if certificate {
		lookup = s.Sign.LookupCompletedAuditCertificateByTokenV1
		recheck = s.Sign.RecheckCompletedAuditCertificateByTokenV1
		unavailable, suffix = "audit certificate not available", "-audit.pdf"
	}
	rc, err := lookup(r.Context(), tokenHash)
	if errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) {
		writeError(w, http.StatusServiceUnavailable, "signer access is temporarily unavailable")
		return
	}
	if err != nil {
		writeError(w, http.StatusNotFound, unavailable)
		return
	}
	defer closeSignerReadConsumerV1(rc)
	key, digest, version := rc.Document.FinalPdfKey.String, rc.Document.FinalPdfSha, rc.Document.FinalPdfVersionID
	if certificate {
		key, digest, version = rc.Document.AuditCertKey.String, rc.Document.AuditCertSha256, rc.Document.AuditCertVersionID
	}
	body, err := readDocumentArtifact(r.Context(), s.Storage, rc.Document, key, digest, version)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if certificate && !contentAddressedArtifactMatches(body, key, "audit", ".pdf") {
		writeInternalError(w, errors.New("stored audit certificate digest does not match its immutable key"))
		return
	}
	// Keep the original expiry and exact selected artifact across storage work.
	if err := recheck(r.Context(), tokenHash, rc); err != nil {
		if errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) {
			writeError(w, http.StatusServiceUnavailable, "signer access is temporarily unavailable")
			return
		}
		writeError(w, http.StatusNotFound, unavailable)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFileName(rc.Document.Name)+suffix+"\"")
	_, _ = w.Write(body)
}

// handleSignerPDF serves the original uploaded PDF of a pdf-source document to
// the signer (magic-token authed) so the signer page can render its pages with
// pdf.js and overlay the fillable fields.
func (s *Server) handleSignerPDF(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrErrorV1(w, r, pdfadmission.SignerReadDiagnosticPDFV1)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	observation, err := s.captureSignerReadObservation(r, rc)
	if err != nil || observation.pdf == nil {
		writeError(w, http.StatusNotFound, "document has no source pdf")
		return
	}
	body, err := readDocumentArtifact(r.Context(), s.Storage, rc.Document, rc.Document.PdfStorageKey.String, rc.Document.PdfSha256, rc.Document.PdfStorageVersionID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], rc.Document.PdfSha256) {
		writeSignerReadError(w, errSignerReadChanged)
		return
	}
	if err := s.recheckSignerRead(r, rc, observation); err != nil {
		writeSignerReadError(w, err)
		return
	}
	setSignerPDFObservationHeaders(w, observation.pdf)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline")
	_, _ = w.Write(body)
}

// lookupTokenOrError verifies the URL token and writes 404 on miss. Returns
// (recipientContext, true) on success.
func (s *Server) lookupTokenOrError(w http.ResponseWriter, r *http.Request) (*sign.RecipientContext, bool) {
	return s.lookupTokenOrErrorV1(w, r, pdfadmission.SignerReadDiagnosticOtherV1)
}
func (s *Server) lookupTokenOrErrorV1(w http.ResponseWriter, r *http.Request, route pdfadmission.SignerReadDiagnosticRouteV1) (*sign.RecipientContext, bool) {
	tok := chi.URLParam(r, "token")
	if tok == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return nil, false
	}
	hash := auth.HashMagicToken(tok)
	var rc *sign.RecipientContext
	var err error
	switch route {
	case pdfadmission.SignerReadDiagnosticFieldsV1:
		rc, err = s.Sign.LookupSignerFieldsByTokenV1(r.Context(), hash)
	case pdfadmission.SignerReadDiagnosticPDFV1:
		rc, err = s.Sign.LookupSignerPDFByTokenV1(r.Context(), hash)
	case pdfadmission.SignerReadDiagnosticCommentsV1:
		rc, err = s.Sign.LookupSignerCommentsByTokenV1(r.Context(), hash)
	case pdfadmission.SignerReadDiagnosticViewV1:
		rc, err = s.Sign.LookupSignerViewByTokenV1(r.Context(), hash)
	default:
		rc, err = s.Sign.LookupByToken(r.Context(), hash)
	}
	if errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) {
		writeError(w, http.StatusServiceUnavailable, "signer access is temporarily unavailable")
		return nil, false
	}
	if errors.Is(err, sign.ErrMagicLinkExpired) {
		// 410 Gone signals "this resource existed and is permanently
		// gone" so the signer UI can show "this link expired" copy
		// instead of the generic "invalid" copy that 404 implies.
		writeError(w, http.StatusGone, "magic link expired")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "invalid or expired link")
		return nil, false
	}
	return rc, true
}

// handleFinalPDF lets the sender download the final PDF (session-auth).
func (s *Server) handleFinalPDF(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), docGetParams(docID, u.OrgID))
	if err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if !doc.FinalPdfKey.Valid {
		writeError(w, http.StatusNotFound, "final pdf not yet rendered")
		return
	}
	body, err := readDocumentArtifact(r.Context(), s.Storage, doc, doc.FinalPdfKey.String, doc.FinalPdfSha, doc.FinalPdfVersionID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFileName(doc.Name)+`.pdf"`)
	_, _ = w.Write(body)
}

// handleAuditCert downloads the audit certificate PDF.
func (s *Server) handleAuditCert(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), docGetParams(docID, u.OrgID))
	if err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if !doc.AuditCertKey.Valid {
		writeError(w, http.StatusNotFound, "audit certificate not yet rendered")
		return
	}
	certDigest := doc.AuditCertSha256
	if len(certDigest) != sha256.Size && !doc.EvidenceVersionPinsRequired {
		certDigest = contentAddressedDigest(doc.AuditCertKey.String, "audit", ".pdf")
	}
	body, err := readDocumentArtifact(r.Context(), s.Storage, doc, doc.AuditCertKey.String, certDigest, doc.AuditCertVersionID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if !contentAddressedArtifactMatches(body, doc.AuditCertKey.String, "audit", ".pdf") {
		writeInternalError(w, errors.New("stored audit certificate digest does not match its immutable key"))
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFileName(doc.Name)+`-audit.pdf"`)
	_, _ = w.Write(body)
}

func finalPDFMatchesDigest(body, expected []byte) bool {
	if len(expected) != sha256.Size {
		return false
	}
	actual := sha256.Sum256(body)
	return bytes.Equal(actual[:], expected)
}

// contentAddressedArtifactMatches verifies new immutable keys while preserving
// downloads for historical rows whose legacy key did not encode a digest.
func contentAddressedArtifactMatches(body []byte, key, prefix, suffix string) bool {
	name := path.Base(key)
	marker := prefix + "-"
	if !strings.HasPrefix(name, marker) || !strings.HasSuffix(name, suffix) {
		return true
	}
	rawHex := strings.TrimSuffix(strings.TrimPrefix(name, marker), suffix)
	if len(rawHex) != sha256.Size*2 {
		return false
	}
	expected, err := hex.DecodeString(rawHex)
	if err != nil {
		return false
	}
	actual := sha256.Sum256(body)
	return bytes.Equal(actual[:], expected)
}

func contentAddressedDigest(key, prefix, suffix string) []byte {
	name := path.Base(key)
	marker := prefix + "-"
	if !strings.HasPrefix(name, marker) || !strings.HasSuffix(name, suffix) {
		return nil
	}
	rawHex := strings.TrimSuffix(strings.TrimPrefix(name, marker), suffix)
	if len(rawHex) != sha256.Size*2 {
		return nil
	}
	digest, err := hex.DecodeString(rawHex)
	if err != nil || len(digest) != sha256.Size {
		return nil
	}
	return digest
}

func sanitizeFileName(name string) string {
	if name == "" {
		return "document"
	}
	// Strip path separators + non-printable. Spaces stay.
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r == '/' || r == '\\':
			// drop
		case r < 0x20:
			// drop control chars
		default:
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "document"
	}
	return string(out)
}
