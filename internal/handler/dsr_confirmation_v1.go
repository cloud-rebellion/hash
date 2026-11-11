// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

const dsrConfirmationPurposeV1 = "hash.dsr-erasure-confirmation.v1"
const dsrConfirmationTTLV1 = 10 * time.Minute
const maxDSRConfirmationReceiptV1 = 8192
const maxDSRConfirmationJSONV1 = 4096

var errDSRConfirmationV1 = errors.New("erasure confirmation is missing, expired or does not match the current scope")

// Scope stores commitments, never the subject's identifiers, original session
// cookie, document content or object keys. Authorization remains the live
// transaction's job; this receipt is only consent to its exact displayed set.
type dsrConfirmationScopeV1 struct {
	RequestID            uuid.UUID `json:"request_id"`
	OrgID                uuid.UUID `json:"org_id"`
	ActorID              uuid.UUID `json:"actor_id"`
	RecipientID          uuid.UUID `json:"recipient_id"`
	DocumentID           uuid.UUID `json:"document_id"`
	DocumentStatus       string    `json:"document_status"`
	SessionSHA256        string    `json:"session_sha256"`
	RequestSHA256        string    `json:"request_sha256"`
	SubjectSHA256        string    `json:"subject_sha256"`
	DocumentsSHA256      string    `json:"documents_sha256"`
	PDFRevisionDocuments int       `json:"pdf_revision_documents"`
	PDFRevisions         int       `json:"pdf_revisions"`
}

type dsrConfirmationReceiptV1 struct {
	SchemaVersion int                    `json:"schema_version"`
	Scope         dsrConfirmationScopeV1 `json:"scope"`
	IssuedAt      time.Time              `json:"issued_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
}

type dsrConfirmationDocumentV1 struct {
	ID        uuid.UUID                                     `json:"id"`
	UpdatedAt time.Time                                     `json:"updated_at"`
	Status    string                                        `json:"status"`
	Revisions []*generated.ListDocumentPDFErasureScopeV1Row `json:"revisions"`
}

func dsrConfirmationSHA256V1(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// The caller already holds every selected parent privacy lock. The small
// revision projection names every immutable revision and exact object tuple;
// a changed/expanded set must be shown again instead of inheriting a boolean.
func readDSRConfirmationScopeV1(ctx context.Context, q *generated.Queries, user auth.SessionUser, cookie string, request *generated.DataSubjectRequest, recipient *generated.Recipient, linked *generated.Document, ids []uuid.UUID) (dsrConfirmationScopeV1, error) {
	var scope dsrConfirmationScopeV1
	if q == nil || request == nil || recipient == nil || linked == nil || cookie == "" || user.UserID == uuid.Nil || user.OrgID == uuid.Nil ||
		request.OrgID != user.OrgID || linked.OrgID != user.OrgID || recipient.DocumentID != linked.ID {
		return scope, errDSRConfirmationV1
	}
	documents := make([]dsrConfirmationDocumentV1, 0, len(ids))
	seen := make(map[uuid.UUID]bool, len(ids))
	revisionCount := 0
	for _, id := range ids {
		if id == uuid.Nil || seen[id] {
			return scope, errDSRConfirmationV1
		}
		seen[id] = true
		doc, err := q.GetDocumentForPrivacyUpdate(ctx, generated.GetDocumentForPrivacyUpdateParams{DocumentID: id, OrgID: user.OrgID})
		if err != nil {
			return scope, err
		}
		count, err := q.CountDocumentPDFRevisionsV1(ctx, generated.CountDocumentPDFRevisionsV1Params{DocumentID: id, OrgID: user.OrgID})
		if err != nil {
			return scope, err
		}
		// Native revisions are capped at 50. Refuse an oversized or partial
		// legacy inventory; never confirm a truncated revision list.
		if count <= 0 || count > 200 || !doc.UpdatedAt.Valid {
			return scope, errDSRConfirmationV1
		}
		revisions, err := q.ListDocumentPDFErasureScopeV1(ctx, generated.ListDocumentPDFErasureScopeV1Params{DocumentID: id, OrgID: user.OrgID})
		if err != nil {
			return scope, err
		}
		if len(revisions) != int(count) {
			return scope, errDSRConfirmationV1
		}
		documents = append(documents, dsrConfirmationDocumentV1{ID: id, UpdatedAt: doc.UpdatedAt.Time.UTC(), Status: doc.Status, Revisions: revisions})
		revisionCount += len(revisions)
	}
	sort.Slice(documents, func(i, j int) bool { return bytes.Compare(documents[i].ID[:], documents[j].ID[:]) < 0 })
	documentsSHA, err := dsrConfirmationSHA256V1(documents)
	if err != nil {
		return scope, err
	}
	requestSHA, err := dsrConfirmationSHA256V1(request)
	if err != nil {
		return scope, err
	}
	subjectSHA, err := dsrConfirmationSHA256V1(recipient)
	if err != nil {
		return scope, err
	}
	scope = dsrConfirmationScopeV1{RequestID: request.ID, OrgID: user.OrgID, ActorID: user.UserID, RecipientID: recipient.ID, DocumentID: linked.ID,
		DocumentStatus: linked.Status, SessionSHA256: htmlPreviewSessionSHA256(cookie), RequestSHA256: requestSHA, SubjectSHA256: subjectSHA,
		DocumentsSHA256: documentsSHA, PDFRevisionDocuments: len(documents), PDFRevisions: revisionCount}
	return scope, nil
}

func (p dsrConfirmationReceiptV1) validAt(now time.Time) bool {
	s := p.Scope
	return p.SchemaVersion == 1 && s.RequestID != uuid.Nil && s.OrgID != uuid.Nil && s.ActorID != uuid.Nil && s.RecipientID != uuid.Nil && s.DocumentID != uuid.Nil &&
		s.DocumentStatus != "" && htmlPreviewSHA256(s.SessionSHA256) && htmlPreviewSHA256(s.RequestSHA256) && htmlPreviewSHA256(s.SubjectSHA256) && htmlPreviewSHA256(s.DocumentsSHA256) &&
		s.PDFRevisionDocuments >= 0 && s.PDFRevisions >= s.PDFRevisionDocuments &&
		!p.IssuedAt.IsZero() && !p.IssuedAt.After(now) && p.ExpiresAt.After(p.IssuedAt) && p.ExpiresAt.Sub(p.IssuedAt) <= dsrConfirmationTTLV1 && now.Before(p.ExpiresAt)
}

func (s *Server) mintDSRConfirmationV1(scope dsrConfirmationScopeV1, now time.Time) (string, error) {
	if s == nil || s.Cookies == nil {
		return "", errDSRConfirmationV1
	}
	receipt := dsrConfirmationReceiptV1{SchemaVersion: 1, Scope: scope, IssuedAt: now.UTC(), ExpiresAt: now.Add(dsrConfirmationTTLV1).UTC()}
	if !receipt.validAt(now) {
		return "", errDSRConfirmationV1
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > maxDSRConfirmationJSONV1 {
		return "", errDSRConfirmationV1
	}
	token, err := s.Cookies.MintPurpose(dsrConfirmationPurposeV1, raw, time.Until(receipt.ExpiresAt))
	if err != nil || len(token) > maxDSRConfirmationReceiptV1 {
		return "", errDSRConfirmationV1
	}
	return token, nil
}

func (s *Server) verifyDSRConfirmationV1(token string, expected dsrConfirmationScopeV1, now time.Time) (dsrConfirmationReceiptV1, error) {
	var receipt dsrConfirmationReceiptV1
	if s == nil || s.Cookies == nil || token == "" || len(token) > maxDSRConfirmationReceiptV1 {
		return receipt, errDSRConfirmationV1
	}
	raw, err := s.Cookies.VerifyPurpose(dsrConfirmationPurposeV1, token)
	if err != nil || len(raw) == 0 || len(raw) > maxDSRConfirmationJSONV1 {
		return receipt, errDSRConfirmationV1
	}
	if err = decodeSignerJSON(&http.Request{Body: io.NopCloser(bytes.NewReader(raw))}, &receipt); err != nil || !receipt.validAt(now) || receipt.Scope != expected {
		return dsrConfirmationReceiptV1{}, errDSRConfirmationV1
	}
	return receipt, nil
}

func (s *Server) writeDSRConfirmationRequiredV1(w http.ResponseWriter, scope dsrConfirmationScopeV1, email string) {
	token, err := s.mintDSRConfirmationV1(scope, time.Now())
	if err != nil {
		writeInternalErrorMsg(w, "prepare erasure confirmation", err)
		return
	}
	writeJSON(w, http.StatusConflict, map[string]any{
		"error": "Review the current recipient and PDF history erasure scope, then explicitly confirm it. Nothing was erased.",
		"code":  "confirmation_required", "confirmation_receipt": token,
		"will_erase": map[string]any{"pdf_revision_documents": scope.PDFRevisionDocuments, "pdf_revisions": scope.PDFRevisions, "document_status": scope.DocumentStatus, "subject_email": email},
	})
}
