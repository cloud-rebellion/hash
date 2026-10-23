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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Session authoring only. An API credential cannot supply arbitrary source
// values through this route; approved policy/API birth is a separate contract.
type preSignSupersessionInputV1 struct {
	Prior      pdfadmission.PreSignSupersessionParentV1 `json:"prior"`
	TemplateID uuid.UUID                                `json:"template_id"`
	Source     htmlDocumentInput                        `json:"source"`
}

func preSignSupersessionInputDigestV1(actor authoring.Actor, in preSignSupersessionInputV1) (string, error) {
	if in.Prior.ValidateV1() != nil || in.TemplateID != in.Prior.Template.ID || in.Source.RequestID == uuid.Nil || in.Source.ExpectedOrgID != actor.OrgID || in.Source.ExpectedUserID != actor.UserID ||
		!utf8.ValidString(in.Source.Name) || strings.TrimSpace(in.Source.Name) == "" || utf8.RuneCountInString(in.Source.Name) > 200 || len(in.Source.Name) > 800 || strings.ContainsRune(in.Source.Name, 0) {
		return "", presignregistry.ErrInvalid
	}
	source, err := crmTemplateCreateInputDigest(actor, in.TemplateID, in.Source)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		Version      int                                      `json:"version"`
		OrgID        uuid.UUID                                `json:"org_id"`
		UserID       uuid.UUID                                `json:"user_id"`
		RequestID    uuid.UUID                                `json:"request_id"`
		Prior        pdfadmission.PreSignSupersessionParentV1 `json:"prior"`
		TemplateID   uuid.UUID                                `json:"template_id"`
		SourceSHA256 string                                   `json:"source_sha256"`
	}{1, actor.OrgID, actor.UserID, in.Source.RequestID, in.Prior, in.TemplateID, source})
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("hash:presign-supersession-source-request:v1\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (s *Server) writePreSignSupersessionErrorV1(w http.ResponseWriter, err error) {
	if errors.Is(err, presignregistry.ErrInvalid) {
		writeError(w, 400, "invalid exact supersession command")
		return
	}
	if errors.Is(err, presignregistry.ErrConflict) {
		writeError(w, 409, "original agreement, successor request or source differs")
		return
	}
	s.writeHTMLCreationError(w, err)
}

// POST /api/v1/presign/supersessions. Explicitly creates one fresh unreviewed
// signing draft, never a new signature, dispatch, mutation of prior evidence or
// an override of the existing ordinary later-amendment notice/signature choice.
func (s *Server) handlePreSignSupersessionV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if !s.requireHTMLAuthoringRuntimeV1(w) {
		return
	}
	if err := requireAutomationJSONContentType(r.Header.Values("Content-Type")); err != nil {
		writeError(w, 415, "application/json is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	actor := authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}
	r, closeInput, ok := s.beginHTMLAuthoringInputV1(w, r, u.OrgID, pdfadmission.HTMLPreSignSupersessionInputV1)
	if !ok {
		return
	}
	defer closeInput()
	var in preSignSupersessionInputV1
	if err = decodeCRMTemplateJSON(r, &in); err != nil {
		if !writeHTMLAuthoringInputFailureV1(w, err) {
			writeError(w, 400, "invalid closed supersession command")
		}
		return
	}
	digest, err := preSignSupersessionInputDigestV1(actor, in)
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	prior, err := s.readPreSignSupersessionV1(ctx, actor, in.Source.RequestID, digest)
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	if prior.State == "committed" {
		writeJSON(w, 200, prior)
		return
	}
	if !s.preSignExecutionAvailableV1() || s.Billing == nil || s.Versions == nil {
		writeError(w, 503, "new pre-sign supersession is unavailable")
		return
	}
	var expires pgtype.Timestamptz
	if in.Source.ExpiresAt != "" {
		value, e := time.Parse(time.RFC3339, in.Source.ExpiresAt)
		if e != nil || !value.After(time.Now()) {
			writeError(w, 400, "expires_at must be a future RFC3339 time")
			return
		}
		expires = pgtype.Timestamptz{Time: value, Valid: true}
	}
	release, err := importguard.Shared.Acquire(actor.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, 429, "source creation is temporarily busy")
		return
	}
	defer release()
	// Parent eligibility and complete original retained descriptors are checked
	// before receipt/provider/render/upload work, then in each real author recheck.
	if err = s.checkPreSignSupersessionParentV1(ctx, actor, in.Prior, in.TemplateID, in.Source.ExpectedTemplateVersion, in.Source.ExpectedTemplateContentSHA256); err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	population, err := s.prepareCRMTemplatePopulation(ctx, r, actor, in.TemplateID, in.Source)
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	defer population.closeOwnedV1()
	var pending []audit.PendingEvent
	original := actor.Authorize
	actor.Authorize = func(call context.Context, tx pgx.Tx, user *generated.User) error {
		if err := original(call, tx, user); err != nil {
			return err
		}
		reader, err := htmlAuthoringReaderV1(tx)
		if err != nil {
			return err
		}
		facts, ready, err := reader.ReadPreSignSupersessionBirthV1(call, actor.UserID, in.Source.RequestID, digest, in.Prior, in.TemplateID)
		if err != nil || !ready {
			return err
		}
		event, err := s.Audit.LogTx(call, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &facts.DocumentID, Kind: "presign.execution.superseded", Payload: map[string]any{
			"prior_execution_id": facts.PriorExecutionID, "prior_execution_sha256": facts.PriorExecutionSHA256, "prior_document_id": facts.PriorDocumentID,
			"document_id": facts.DocumentID, "request_id": facts.RequestID, "source_commitment": facts.SourceCommitment,
		}})
		if err != nil {
			return err
		}
		if err = reader.SealPreSignSupersessionBirthV1(call, actor.UserID, in.Source.RequestID, event.ID, digest, in.Prior, in.TemplateID); err != nil {
			return err
		}
		// Repeat the same original credential after the actual transactional audit.
		if err = original(call, tx, user); err != nil {
			return err
		}
		pending = append(pending, event)
		return nil
	}
	content, err := hex.DecodeString(in.Source.ExpectedTemplateContentSHA256)
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	outcome, err := s.instantiateHTMLDocument(ctx, actor, in.TemplateID, in.Source, content, expires, population, digest)
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	defer outcome.closeOwnedWriterV1()
	for _, event := range pending {
		s.Audit.Publish(detachHTMLCreationEventIDsV1(event))
	}
	view, err := s.readPreSignSupersessionV1(ctx, authoring.Actor{OrgID: actor.OrgID, UserID: actor.UserID, Authorize: original}, in.Source.RequestID, digest)
	if err != nil || view.State != "committed" {
		if err == nil {
			err = pdfadmission.ErrHTMLAuthoringReadV1
		}
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	status := http.StatusCreated
	if outcome.replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, view)
}

func (s *Server) checkPreSignSupersessionParentV1(ctx context.Context, actor authoring.Actor, p pdfadmission.PreSignSupersessionParentV1, template uuid.UUID, version int32, digest string) error {
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, actor.OrgID, p.DocumentID)
	if err != nil {
		return err
	}
	defer o.closeConsumerV1(ctx)
	defer o.closeSQLV1(ctx)
	err = o.session.WithTxV1(ctx, func(call context.Context, owned generated.DBTX) error {
		// Match the genuine HTML birth's template-before-member/parent lock order.
		if e := o.reader.CheckPreSignSupersessionTemplateV1(call, template, version, digest); e != nil {
			return e
		}
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		guard, e := lockHTMLAuthorV1(call, tx, actor, false)
		if e != nil {
			return e
		}
		if e = o.reader.CheckPreSignSupersessionParentV1(call, actor.UserID, p, template); e != nil {
			return e
		}
		return guard.Recheck(call)
	})
	if err != nil {
		return err
	}
	return o.session.CommitV1(ctx)
}
func (s *Server) readPreSignSupersessionV1(ctx context.Context, actor authoring.Actor, request uuid.UUID, input string) (out pdfadmission.PreSignSupersessionViewV1, failure error) {
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, actor.OrgID, request)
	if err != nil {
		return out, err
	}
	defer o.closeConsumerV1(ctx)
	defer o.closeSQLV1(ctx)
	err = o.session.WithTxV1(ctx, func(call context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		guard, e := lockHTMLAuthorV1(call, tx, actor, false)
		if e != nil {
			return e
		}
		out, e = o.reader.ReadPreSignSupersessionRequestV1(call, actor.UserID, request, input)
		if e != nil {
			return e
		}
		return guard.Recheck(call)
	})
	if err != nil {
		return out, err
	}
	if err = o.session.CommitV1(ctx); err != nil {
		return out, err
	}
	return out, nil
}
func (s *Server) handleGetPreSignSupersessionV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if !s.requireHTMLAuthoringRuntimeV1(w) {
		return
	}
	raw := chi.URLParam(r, "request_id")
	request, err := uuid.Parse(raw)
	if err != nil || request == uuid.Nil || request.String() != raw || len(r.URL.Query()) != 0 {
		writeError(w, 400, "canonical original request UUID required")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	out, err := s.readPreSignSupersessionV1(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, request, "")
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	status := http.StatusOK
	if out.State == "unconfirmed" {
		status = http.StatusNotFound
	}
	writeJSON(w, status, out)
}
