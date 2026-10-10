// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
)

const (
	htmlTemplatePreviewPurpose = "hash.html-template-preview.v1"
	htmlTemplatePreviewTTL     = 10 * time.Minute
	maxHTMLPreviewReceiptJSON  = 4096
	maxHTMLPreviewReceipt      = 8192
)

var errHTMLTemplatePreviewReceipt = errors.New("HTML template preview is missing, expired or does not match; preview the saved design again")

// The receipt carries commitments, never the sample inputs or original cookie.
// Its purpose-separated signature is independent of ordinary login cookies.
type htmlTemplatePreviewReceipt struct {
	SchemaVersion         int       `json:"schema_version"`
	PreviewID             uuid.UUID `json:"preview_id"`
	OrgID                 uuid.UUID `json:"org_id"`
	ReviewerID            uuid.UUID `json:"reviewer_id"`
	TemplateID            uuid.UUID `json:"template_id"`
	Version               int32     `json:"version"`
	TemplateContentSHA256 string    `json:"template_content_sha256"`
	MaterializationSHA256 string    `json:"materialization_sha256"`
	PDFSHA256             string    `json:"pdf_sha256"`
	PageCount             int       `json:"page_count"`
	SessionSHA256         string    `json:"session_sha256"`
	IssuedAt              time.Time `json:"issued_at"`
	ExpiresAt             time.Time `json:"expires_at"`
}

func htmlPreviewSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func htmlPreviewSessionSHA256(cookie string) string {
	digest := sha256.Sum256([]byte(cookie))
	return hex.EncodeToString(digest[:])
}

func (p htmlTemplatePreviewReceipt) validate(now time.Time) error {
	if p.SchemaVersion != 1 || p.PreviewID == uuid.Nil || p.OrgID == uuid.Nil || p.ReviewerID == uuid.Nil ||
		p.TemplateID == uuid.Nil || p.Version <= 0 || p.PageCount <= 0 || p.PageCount > sanitize.MaxPDFPages ||
		!htmlPreviewSHA256(p.TemplateContentSHA256) || !htmlPreviewSHA256(p.MaterializationSHA256) ||
		!htmlPreviewSHA256(p.PDFSHA256) || !htmlPreviewSHA256(p.SessionSHA256) ||
		p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() || p.IssuedAt.After(now) ||
		!p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > htmlTemplatePreviewTTL || !now.Before(p.ExpiresAt) {
		return errHTMLTemplatePreviewReceipt
	}
	return nil
}

func (s *Server) validateHTMLTemplatePreviewReceipt(r *http.Request, user auth.SessionUser, templateID uuid.UUID, version int32, contentSHA256, pdfSHA256, token string) (htmlTemplatePreviewReceipt, error) {
	var receipt htmlTemplatePreviewReceipt
	if s == nil || r == nil || s.Cookies == nil || len(token) == 0 || len(token) > maxHTMLPreviewReceipt ||
		user.UserID == uuid.Nil || user.OrgID == uuid.Nil || user.Role != string(auth.RoleOwner) ||
		templateID == uuid.Nil || version <= 0 || !htmlPreviewSHA256(contentSHA256) || !htmlPreviewSHA256(pdfSHA256) {
		return receipt, errHTMLTemplatePreviewReceipt
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return receipt, errHTMLTemplatePreviewReceipt
	}
	payload, err := s.Cookies.VerifyPurpose(htmlTemplatePreviewPurpose, token)
	if err != nil || len(payload) == 0 || len(payload) > maxHTMLPreviewReceiptJSON {
		return receipt, errHTMLTemplatePreviewReceipt
	}
	request := &http.Request{Body: io.NopCloser(bytes.NewReader(payload))}
	if err := decodeSignerJSON(request, &receipt); err != nil || receipt.validate(time.Now()) != nil ||
		receipt.OrgID != user.OrgID || receipt.ReviewerID != user.UserID || receipt.TemplateID != templateID ||
		receipt.Version != version || receipt.TemplateContentSHA256 != contentSHA256 || receipt.PDFSHA256 != pdfSHA256 ||
		subtle.ConstantTimeCompare([]byte(receipt.SessionSHA256), []byte(htmlPreviewSessionSHA256(cookie.Value))) != 1 {
		return htmlTemplatePreviewReceipt{}, errHTMLTemplatePreviewReceipt
	}
	return receipt, nil
}

// Retain this wrapper in the owner mutation's actor. Rechecking only when the
// request arrives would allow a receipt to expire while waiting for the audit.
func htmlTemplatePreviewReceiptAuthorization(original auth.TransactionAuthorization, receipt htmlTemplatePreviewReceipt) auth.TransactionAuthorization {
	return func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
		if original == nil || receipt.validate(time.Now()) != nil {
			return errHTMLTemplatePreviewReceipt
		}
		if err := original(ctx, tx, user); err != nil {
			return err
		}
		if err := receipt.validate(time.Now()); err != nil {
			return err
		}
		return ctx.Err()
	}
}

func (s *Server) mintHTMLTemplatePreviewReceipt(receipt htmlTemplatePreviewReceipt) (string, error) {
	if s == nil || s.Cookies == nil || receipt.validate(time.Now()) != nil {
		return "", errHTMLTemplatePreviewReceipt
	}
	payload, err := json.Marshal(receipt)
	if err != nil || len(payload) > maxHTMLPreviewReceiptJSON {
		return "", errHTMLTemplatePreviewReceipt
	}
	token, err := s.Cookies.MintPurpose(htmlTemplatePreviewPurpose, payload, time.Until(receipt.ExpiresAt))
	if err != nil || len(token) > maxHTMLPreviewReceipt {
		return "", errHTMLTemplatePreviewReceipt
	}
	return token, nil
}
