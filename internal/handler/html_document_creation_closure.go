// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errHTMLCreationRequestClosed = errors.New("this creation request was stopped; inspect its outcome before reviewing another creation")
var errHTMLCreationClosureUnavailable = errors.New("creation request outcome unavailable")
var errHTMLCreationClosureAudit = errors.New("creation request closure audit failed")

type htmlCreationCloseInput struct {
	ExpectedOrgID  string `json:"expected_org_id"`
	ExpectedUserID string `json:"expected_user_id"`
	Confirmed      bool   `json:"confirmed"`
}

func htmlCreationRequestIDs(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	templateID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	requestID, ok := parseUUIDParam(w, r, "request_id")
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	if templateID == uuid.Nil || requestID == uuid.Nil || len(r.URL.Query()) != 0 ||
		chi.URLParam(r, "id") != templateID.String() || chi.URLParam(r, "request_id") != requestID.String() {
		writeError(w, 400, "canonical nonzero template and request UUIDs are required")
		return uuid.Nil, uuid.Nil, false
	}
	return templateID, requestID, true
}

// A read can cross the instant a concurrent creation commits. If the terminal
// registry now says committed, reread its immutable receipt with a fresh
// ReadCommitted statement snapshot rather than returning a misleading 404.
func readHTMLCreationResolution(ctx context.Context, q *generated.Queries, actor authoring.Actor, templateID, requestID uuid.UUID, inputDigest string, readers ...*pdfadmission.ApplicationHTMLAuthoringReaderV1) (*htmlCreationOutcome, *generated.HtmlDocumentCreationResolution, error) {
	committed, err := readHTMLCreationRequest(ctx, q, actor, templateID, requestID, inputDigest, readers...)
	if err != nil || committed != nil {
		return committed, nil, err
	}
	row, err := q.GetHTMLDocumentCreationResolution(ctx, generated.GetHTMLDocumentCreationResolutionParams{OrgID: actor.OrgID, ActorUserID: actor.UserID, RequestID: requestID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if row.TemplateID != templateID {
		return nil, nil, errHTMLCreationRequestConflict
	}
	if row.State == "closed" {
		return nil, row, nil
	}
	if row.State != "committed" {
		return nil, nil, errHTMLCreationClosureUnavailable
	}
	committed, err = readHTMLCreationRequest(ctx, q, actor, templateID, requestID, inputDigest, readers...)
	if err != nil {
		return nil, nil, err
	}
	if committed == nil {
		return nil, nil, errHTMLCreationClosureUnavailable
	}
	return committed, nil, nil
}

func (s *Server) findHTMLCreationResolution(ctx context.Context, actor authoring.Actor, templateID, requestID uuid.UUID, inputDigest string) (committed *htmlCreationOutcome, closed *generated.HtmlDocumentCreationResolution, failure error) {
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, actor.OrgID, requestID)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = o.closeSQLV1(ctx)
		if committed == nil {
			o.closeConsumerV1(ctx)
		}
	}()
	err = o.session.WithTxV1(ctx, func(ctx context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		guard, err := lockHTMLAuthorV1(ctx, tx, actor, false)
		if err != nil {
			return err
		}
		committed, closed, err = readHTMLCreationResolution(ctx, generated.New(tx), actor, templateID, requestID, inputDigest, o.reader)
		if err != nil {
			return err
		}
		return guard.Recheck(ctx)
	})
	if err != nil {
		return nil, nil, err
	}
	if err = o.session.CommitV1(ctx); err != nil {
		return nil, nil, err
	}
	if committed != nil {
		committed.addOwnedConsumerV1(func() { o.closeConsumerV1(ctx) })
	}
	return committed, closed, nil
}

func htmlCreationClosedResponse(row *generated.HtmlDocumentCreationResolution) map[string]any {
	return map[string]any{"state": "closed", "org_id": row.OrgID, "user_id": row.ActorUserID,
		"template_id": row.TemplateID, "request_id": row.RequestID,
		"closed_at": row.ResolvedAt.Time.UTC().Format(time.RFC3339Nano)}
}

// Closure retires the nonce even when its original renderer is still running.
// Take the unconditional DB lock used by final creation before author locks;
// the unique terminal registry additionally enforces mutual exclusion in SQL.
func (s *Server) closeHTMLCreationRequest(ctx context.Context, actor authoring.Actor, templateID, requestID uuid.UUID) (committed *htmlCreationOutcome, closed *generated.HtmlDocumentCreationResolution, failure error) {
	if s.Audit == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || templateID == uuid.Nil || requestID == uuid.Nil {
		return nil, nil, errHTMLCreationClosureUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, actor.OrgID, requestID)
	if err != nil {
		return nil, nil, errors.Join(errHTMLCreationClosureUnavailable, err)
	}
	defer func() {
		_ = o.closeSQLV1(ctx)
		if committed == nil {
			o.closeConsumerV1(ctx)
		}
	}()
	var pending *audit.PendingEvent
	err = o.session.WithTxV1(ctx, func(ctx context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		q := generated.New(tx)
		if err := q.LockBillingUsageForOrg(ctx, actor.OrgID.String()); err != nil {
			return errors.Join(errHTMLCreationClosureUnavailable, err)
		}
		guard, err := lockHTMLAuthorV1(ctx, tx, actor, false)
		if err != nil {
			return err
		}
		committed, closed, err = readHTMLCreationResolution(ctx, q, actor, templateID, requestID, "", o.reader)
		if err != nil {
			return err
		}
		if committed == nil && closed == nil {
			closed, err = q.InsertHTMLDocumentCreationClosure(ctx, generated.InsertHTMLDocumentCreationClosureParams{OrgID: actor.OrgID, ActorUserID: actor.UserID, RequestID: requestID, TemplateID: templateID})
			if errors.Is(err, pgx.ErrNoRows) {
				committed, closed, err = readHTMLCreationResolution(ctx, q, actor, templateID, requestID, "", o.reader)
				if err != nil || (committed == nil && closed == nil) {
					return errors.Join(errHTMLCreationClosureUnavailable, err)
				}
			} else if err != nil {
				return errors.Join(errHTMLCreationClosureUnavailable, err)
			} else {
				event, auditErr := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, Kind: "html.document.creation.closed",
					Payload: map[string]any{"template_id": templateID, "request_id": requestID, "closed_at": closed.ResolvedAt.Time.UTC().Format(time.RFC3339Nano)}})
				if auditErr != nil {
					return errors.Join(errHTMLCreationClosureAudit, auditErr)
				}
				pending = &event
			}
		}
		return guard.Recheck(ctx)
	})
	if err != nil {
		return nil, nil, err
	}
	if err = o.session.CommitV1(ctx); err != nil {
		return nil, nil, errors.Join(errHTMLCreationClosureUnavailable, err)
	}
	if pending != nil {
		s.Audit.Publish(detachHTMLCreationEventIDsV1(*pending))
	}
	if committed != nil {
		committed.addOwnedConsumerV1(func() { o.closeConsumerV1(ctx) })
	}
	return committed, closed, nil
}

func (s *Server) handleCloseHTMLCreationRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	templateID, requestID, ok := htmlCreationRequestIDs(w, r)
	if !ok {
		return
	}
	r, closeInput, inputOK := s.beginHTMLAuthoringInputV1(w, r, user.OrgID, pdfadmission.HTMLCreationClosureInputV1)
	if !inputOK {
		return
	}
	defer closeInput()
	r.Body = http.MaxBytesReader(w, r.Body, 2<<10)
	var in htmlCreationCloseInput
	decodeErr := decodeCRMTemplateJSON(r, &in)
	if writeHTMLAuthoringInputFailureV1(w, decodeErr) {
		return
	}
	if decodeErr != nil || !in.Confirmed {
		writeError(w, 400, "the original actor and explicit confirmation are required")
		return
	}
	orgID, orgErr := uuid.Parse(in.ExpectedOrgID)
	userID, userErr := uuid.Parse(in.ExpectedUserID)
	if orgErr != nil || userErr != nil || orgID == uuid.Nil || userID == uuid.Nil || orgID.String() != in.ExpectedOrgID || userID.String() != in.ExpectedUserID {
		writeError(w, 400, "canonical nonzero original actor UUIDs are required")
		return
	}
	if orgID != user.OrgID || userID != user.UserID {
		writeError(w, 409, "creation actor changed; return to the original session")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, user.OrgID, user.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize creation request closure", err)
		return
	}
	if s.Pool == nil || s.Audit == nil {
		writeError(w, 503, "creation request closure unavailable")
		return
	}
	committed, closed, err := s.closeHTMLCreationRequest(r.Context(), authoring.Actor{OrgID: user.OrgID, UserID: user.UserID, Authorize: authorize}, templateID, requestID)
	if err != nil {
		switch {
		case errors.Is(err, errHTMLCreationRequestConflict):
			writeError(w, 404, "creation request not found")
		case errors.Is(err, errHTMLCreationClosureAudit):
			writeError(w, 500, "creation request closure audit unavailable")
		case errors.Is(err, errHTMLCreationClosureUnavailable), errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1), errors.Is(err, context.DeadlineExceeded):
			writeError(w, 503, "creation request closure unavailable; inspect this same request")
		default:
			s.writeDraftAuthoringError(w, "close creation request", err)
		}
		return
	}
	if committed != nil {
		defer committed.closeOwnedWriterV1()
		writeJSON(w, 200, htmlCreationCommittedResponse(committed))
		return
	}
	writeJSON(w, 200, htmlCreationClosedResponse(closed))
}
