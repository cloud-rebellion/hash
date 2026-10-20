// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errHTMLCreationRequestConflict = errors.New("creation request already identifies a different command; inspect its committed result")
var errHTMLCreationAudit = errors.New("HTML document creation audit failed")

// UUID is a fixed array: encoding/json's omitempty cannot omit its zero value.
// Keep omitted recovery IDs absent for legacy Go callers while rejecting an
// explicitly supplied zero UUID at the HTTP decoding boundary.
func (in htmlDocumentInput) MarshalJSON() ([]byte, error) {
	type plain htmlDocumentInput
	var requestID *uuid.UUID
	var expectedOrgID, expectedUserID *uuid.UUID
	if in.RequestID != uuid.Nil {
		requestID = &in.RequestID
	}
	if in.ExpectedOrgID != uuid.Nil {
		expectedOrgID = &in.ExpectedOrgID
	}
	if in.ExpectedUserID != uuid.Nil {
		expectedUserID = &in.ExpectedUserID
	}
	return json.Marshal(struct {
		*plain
		RequestID      *uuid.UUID `json:"request_id,omitempty"`
		ExpectedOrgID  *uuid.UUID `json:"expected_org_id,omitempty"`
		ExpectedUserID *uuid.UUID `json:"expected_user_id,omitempty"`
	}{(*plain)(&in), requestID, expectedOrgID, expectedUserID})
}

// Presence is meaningful for new recovery/CRM fields. Explicit null may not
// silently downgrade a reviewed CRM creation into a manual one.
func (in *htmlDocumentInput) UnmarshalJSON(raw []byte) error {
	type plain htmlDocumentInput
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	_, hasRequest := fields["request_id"]
	_, hasPopulation := fields["crm_population"]
	_, hasOrg := fields["expected_org_id"]
	_, hasUser := fields["expected_user_id"]
	if hasRequest || hasPopulation || hasOrg || hasUser {
		var value any
		if json.Unmarshal(raw, &value) != nil || crmTemplateHasNull(value) {
			return errors.New("creation request members must not be null")
		}
	}
	if hasOrg != hasUser {
		return errors.New("expected_org_id and expected_user_id must be supplied together")
	}
	if hasOrg {
		for name, id := range map[string]uuid.UUID{"expected_org_id": decoded.ExpectedOrgID, "expected_user_id": decoded.ExpectedUserID} {
			var text string
			if json.Unmarshal(fields[name], &text) != nil || id == uuid.Nil || text != id.String() {
				return errors.New("creation actor witnesses must be nonzero canonical UUIDs")
			}
		}
	}
	if request, present := fields["request_id"]; present {
		var text string
		if json.Unmarshal(request, &text) != nil || decoded.RequestID == uuid.Nil || text != decoded.RequestID.String() {
			return errors.New("request_id must be a nonzero canonical UUID")
		}
	}
	if population, present := fields["crm_population"]; present {
		if bytes.Equal(bytes.TrimSpace(population), []byte("null")) || decoded.CRMPopulation == nil {
			return errors.New("crm_population must be an object")
		}
		if len(raw) > 256<<10 {
			return errors.New("CRM creation input exceeds the 256 KiB limit")
		}
	}
	*in = htmlDocumentInput(decoded)
	return nil
}

func (in htmlDocumentInput) checkExpectedActor(actor authoring.Actor) error {
	if in.ExpectedOrgID == uuid.Nil && in.ExpectedUserID == uuid.Nil {
		return nil
	}
	if in.ExpectedOrgID != actor.OrgID || in.ExpectedUserID != actor.UserID {
		return errCRMTemplateChanged
	}
	return nil
}

type htmlCreationPins struct {
	DocumentID            uuid.UUID `json:"document_id"`
	HTMLMaterializationID uuid.UUID `json:"html_materialization_id"`
	HTMLSourceCommitment  string    `json:"html_source_commitment"`
	PDFSHA256             string    `json:"pdf_sha256"`
	PageCount             int32     `json:"page_count"`
	CreatedAt             string    `json:"created_at"`
}

type htmlCreationOutcome struct {
	document         *generated.Document
	documentView     *documentResponse
	pages            int
	request          *generated.HtmlDocumentCreationRequest
	replayed         bool
	closeOwnedWriter func()
}

// Close after JSON response writing, not merely after COMMIT or response mapping.
func (result *htmlCreationOutcome) closeOwnedWriterV1() {
	if result != nil && result.closeOwnedWriter != nil {
		result.closeOwnedWriter()
	}
}

func htmlCreationRequestPins(row *generated.HtmlDocumentCreationRequest) htmlCreationPins {
	return htmlCreationPins{DocumentID: row.OriginalDocumentID, HTMLMaterializationID: row.HtmlMaterializationID,
		HTMLSourceCommitment: row.HtmlSourceCommitment, PDFSHA256: hex.EncodeToString(row.PdfSha256),
		PageCount: row.PageCount, CreatedAt: row.CreatedAt.Time.UTC().Format(time.RFC3339Nano)}
}

func (result *htmlCreationOutcome) response() map[string]any {
	var document any
	reviewRequired := false
	if result.document != nil {
		response := toDocumentResponse(result.document)
		document = response
		reviewRequired = response.HTMLReviewRequired
	}
	if result.documentView != nil {
		document = *result.documentView
		reviewRequired = result.documentView.HTMLReviewRequired
	}
	out := map[string]any{"document": document, "page_count": result.pages, "review_required": reviewRequired, "replayed": result.replayed}
	if result.request != nil {
		out["org_id"], out["user_id"] = result.request.OrgID, result.request.ActorUserID
		out["request_id"], out["input_digest"] = result.request.RequestID, hex.EncodeToString(result.request.InputDigest)
		out["creation"] = htmlCreationRequestPins(result.request)
	}
	return out
}

// The caller rechecks a fresh member/original-session guard before returning a
// result. Reads intentionally
// do not require a still-current template, CRM account or old review receipt.
func readHTMLCreationRequest(ctx context.Context, q *generated.Queries, actor authoring.Actor, templateID, requestID uuid.UUID, inputDigest string, readers ...*pdfadmission.ApplicationHTMLAuthoringReaderV1) (*htmlCreationOutcome, error) {
	// M79 pins are immutable. Read them without a request-row lock before
	// the actual document/cache header locks; deletion may only detach current
	// to NULL. An old pointer plus missing document remains a tombstone, never
	// permission to reuse a request or infer a safe absent-command retry.
	row, err := q.GetHTMLDocumentCreationRequest(ctx, generated.GetHTMLDocumentCreationRequestParams{OrgID: actor.OrgID, ActorUserID: actor.UserID, RequestID: requestID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if row.TemplateID != templateID || (inputDigest != "" && hex.EncodeToString(row.InputDigest) != inputDigest) {
		return nil, errHTMLCreationRequestConflict
	}
	result := &htmlCreationOutcome{request: row, pages: int(row.PageCount), replayed: true}
	if row.CurrentDocumentID.Valid {
		if len(readers) != 1 || readers[0] == nil {
			return nil, pdfadmission.ErrHTMLAuthoringReadV1
		}
		view, readErr := readers[0].ReadCreationResponseV1(ctx, uuid.UUID(row.CurrentDocumentID.Bytes))
		if errors.Is(readErr, pgx.ErrNoRows) {
			view, readErr = nil, nil
		}
		if readErr != nil {
			return nil, readErr
		}
		if view != nil {
			response := htmlCreationDocumentProjectionV1(view)
			result.documentView = &response
		}
	}

	return result, nil
}

func (s *Server) findHTMLCreationRequest(ctx context.Context, actor authoring.Actor, templateID, requestID uuid.UUID, inputDigest string) (*htmlCreationOutcome, error) {
	result, closed, err := s.findHTMLCreationResolution(ctx, actor, templateID, requestID, inputDigest)
	if err == nil && closed != nil {
		err = errHTMLCreationRequestClosed
	}
	return result, err
}

func (s *Server) handleGetHTMLCreationRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	templateID, requestID, ok := htmlCreationRequestIDs(w, r)
	if !ok {
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, user.OrgID, user.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize creation recovery", err)
		return
	}
	if s.Pool == nil {
		writeError(w, 503, "creation recovery unavailable")
		return
	}
	result, closed, err := s.findHTMLCreationResolution(r.Context(), authoring.Actor{OrgID: user.OrgID, UserID: user.UserID, Authorize: authorize}, templateID, requestID, "")
	if err != nil {
		if errors.Is(err, errHTMLCreationRequestConflict) {
			writeError(w, 404, "creation request not found")
			return
		}
		if errors.Is(err, errHTMLCreationClosureUnavailable) || errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) || errors.Is(err, context.DeadlineExceeded) {
			writeError(w, 503, "creation request outcome unavailable; keep this same request")
			return
		}
		s.writeDraftAuthoringError(w, "inspect creation request", err)
		return
	}
	if closed != nil {
		writeJSON(w, 200, htmlCreationClosedResponse(closed))
		return
	}
	if result == nil {
		writeJSON(w, 404, map[string]any{"state": "unconfirmed", "request_id": requestID, "error": "No committed result found. The original request may still be finishing; keep this request ID."})
		return
	}
	defer result.closeOwnedWriterV1()
	writeJSON(w, 200, htmlCreationCommittedResponse(result))
}

func htmlCreationCommittedResponse(result *htmlCreationOutcome) map[string]any {
	var document any
	if result.document != nil {
		document = toDocumentResponse(result.document)
	}
	if result.documentView != nil {
		document = *result.documentView
	}
	response := map[string]any{"state": "committed", "request_id": result.request.RequestID,
		"org_id": result.request.OrgID, "user_id": result.request.ActorUserID,
		"input_digest": hex.EncodeToString(result.request.InputDigest), "template_id": result.request.TemplateID,
		"document": document, "creation": htmlCreationRequestPins(result.request)}
	// Creation pins are immutable; document is the current authorized view and
	// may already be edited, signed, soft-deleted or hard-purged.
	return response
}

func (result *htmlCreationOutcome) addOwnedConsumerV1(closeConsumer func()) {
	if result == nil || closeConsumer == nil {
		return
	}
	previous := result.closeOwnedWriter
	var once sync.Once
	result.closeOwnedWriter = func() {
		once.Do(func() {
			if previous != nil {
				previous()
			}
			closeConsumer()
		})
	}
}
