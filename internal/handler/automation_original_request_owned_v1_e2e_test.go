//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// The old direct composite/claim regressions intentionally inspect exact typed
// internal errors and can perturb only the supplied digest. Each fixed call
// still decodes/prepares genuine request bytes under the actual route input
// owner, then keeps the actual typed materialization/Send response slot until
// that test's real row/error/status consumer has finished.
type originalAutomationCallLeaseV1 struct {
	once     sync.Once
	ctx      context.Context
	input    automationSignatureRequestProcessInput
	request  *pdfadmission.ApplicationBlocksInputV1
	response *automationSendResponseV1
}

func (l *originalAutomationCallLeaseV1) closeV1() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.input = automationSignatureRequestProcessInput{}
		l.ctx = nil
		if l.response != nil {
			l.response.closeV1()
			l.response = nil
		}
		if l.request != nil {
			l.request.CloseConsumerV1()
			l.request = nil
		}
	})
}
func newOriginalAutomationCallLeaseV1(t *testing.T, s *Server, ctx context.Context, in automationSignatureRequestProcessInput) (lease *originalAutomationCallLeaseV1, failure error) {
	lease = &originalAutomationCallLeaseV1{}
	t.Cleanup(lease.closeV1)
	if s == nil || s.HTMLCreationSessions == nil {
		return lease, errors.New("actual automation source factory missing")
	}
	// Request serialization is the synthetic client's work, before admission.
	wire := automationSignatureRequestInput{TemplateID: in.Request.TemplateID.String(), TemplateVersion: in.Request.TemplateVersion, TemplateContentSHA256: in.Request.TemplateContentSHA256, Name: in.Request.Name, Variables: in.Request.Variables, LawfulBasis: in.Request.LawfulBasis, ExpiresAt: in.Request.ExpiresAt, Recipients: make([]automationSignatureRecipientInput, len(in.Request.Recipients))}
	for i, r := range in.Request.Recipients {
		wire.Recipients[i] = automationSignatureRecipientInput{Role: r.Role, Email: r.Email, Name: r.Name, OrderIndex: r.OrderIndex, Locale: r.Locale}
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return lease, err
	}
	lease.request, err = s.HTMLCreationSessions.NewBlocksHTTPInputV1(ctx, in.User.OrgID)
	if err != nil {
		return lease, err
	}
	var prepared preparedAutomationSignatureRequest
	err = lease.request.WithAutomationHTTPBodyV1(ctx, httptest.NewRecorder(), io.NopCloser(bytes.NewReader(raw)), func(body []byte) error {
		var decoded automationSignatureRequestInput
		if err := decodeAutomationSignatureRequestRawV1(body, &decoded); err != nil {
			return err
		}
		var err error
		prepared, _, err = prepareAutomationSignatureRequest(decoded)
		return err
	})
	if err != nil {
		return lease, err
	}
	lease.ctx, lease.response = newAutomationSendResponseV1(ctx)
	lease.input = in
	lease.input.Request = prepared
	return lease, nil
}
func originalAutomationProcessV1(t *testing.T, s *Server, ctx context.Context, in automationSignatureRequestProcessInput) (automationSignatureRequestResponse, error, *originalAutomationCallLeaseV1) {
	lease, err := newOriginalAutomationCallLeaseV1(t, s, ctx, in)
	if err != nil {
		return automationSignatureRequestResponse{}, err, lease
	}
	value, err := s.processAutomationSignatureRequest(lease.ctx, lease.input)
	return value, err, lease
}
func originalAutomationMaterializeV1(t *testing.T, s *Server, ctx context.Context, in automationSignatureRequestProcessInput) (*generated.AutomationSignatureRequest, bool, error, *originalAutomationCallLeaseV1) {
	lease, err := newOriginalAutomationCallLeaseV1(t, s, ctx, in)
	if err != nil {
		return nil, false, err, lease
	}
	value, replayed, err := s.materializeAutomationSignatureRequest(lease.ctx, lease.input)
	return value, replayed, err, lease
}
func originalAutomationTemplateCreateV1(t *testing.T, q *ownedPublicReadFixtureV1, name string, body, variables json.RawMessage) (*generated.Template, error) {
	response := ownedBlocksTemplateCallV1(t, q.f, q.cookie, http.MethodPost, "/api/v1/templates", map[string]any{"name": name, "blocks_json": body, "variables_json": variables})
	if response.Code != http.StatusCreated {
		return nil, errors.New("actual automation template creation: " + response.Body.String())
	}
	var result templateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		return nil, err
	}
	return q.f.q.GetTemplate(q.f.ctx, generated.GetTemplateParams{ID: result.ID, OrgID: q.f.org})
}
func originalAutomationTemplateUpdateV1(q *ownedPublicReadFixtureV1, template *generated.Template, body, variables json.RawMessage) (*generated.Template, error) {
	raw, err := json.Marshal(map[string]any{"name": template.Name, "blocks_json": body, "variables_json": variables})
	if err != nil {
		return nil, err
	}
	response := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/templates/"+template.ID.String(), string(raw), q.cookie)
	if response.Code != http.StatusOK {
		return nil, errors.New("actual automation template update: " + response.Body.String())
	}
	return q.f.q.GetTemplate(q.f.ctx, generated.GetTemplateParams{ID: template.ID, OrgID: q.f.org})
}

// Controlled original recovery-fixture setup, not full public Send acceptance:
// actual native source/actor -> lawful basis -> effective branding/fresh cache
// -> real intent -> sealing -> acknowledged commit. The original later direct
// retention/deadline mutations remain explicit recovery-state test stimuli.
func originalAutomationStageSealingV1(ctx context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, org, document, user uuid.UUID) (failure error) {
	operation, err := factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return err
	}
	defer operation.CloseConsumerV1()
	stage, err := operation.OpenSQLV1(pdfadmission.HTMLSendAdmissionV1)
	if err != nil {
		return err
	}
	var reconcileAdmission func(context.Context) error
	defer func() {
		failure = errors.Join(failure, stage.CloseSQLV1())
		operation.CloseConsumerV1()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if reconcileAdmission != nil {
			failure = errors.Join(failure, reconcileAdmission(cleanup))
		}
		failure = errors.Join(failure, factory.ReconcileCleanupV1(cleanup))
	}()
	session := stage.SessionV1()
	admission, err := session.NewAdmissionV1(stage.ContextV1())
	if err != nil {
		return err
	}
	reconcileAdmission = func(cleanup context.Context) error { _, err := admission.ReconcileCleanupV1(cleanup); return err }
	err = stage.WithTxV1(func(call context.Context, _ generated.DBTX) error {
		work, err := session.NewHTMLSendWorkV1(call, stage)
		if err != nil {
			return err
		}
		state, err := work.StateV1(call)
		if err != nil {
			return err
		}
		if state == nil || state.ID != document || state.OrgID != org || state.BoundedStatus != "draft" {
			return errors.New("actual controlled recovery source is not the original draft")
		}
		models, err := work.ReadModelsV1(call)
		if err != nil {
			return err
		}
		if models == nil || models.Document == nil || models.Document.ID != document || models.Document.OrgID != org || models.Document.SourceKind != "blocks" || models.Document.Status != "draft" {
			return errors.New("actual controlled recovery body differs")
		}
		member, err := work.ReadActorV1(call, user)
		if err != nil {
			return err
		}
		if member == nil || member.ID != user || member.OrgID != org || member.Role != "owner" {
			return errors.New("actual controlled recovery owner differs")
		}
		source, err := work.NewSourceV1(call)
		if err != nil {
			return err
		}
		if err = source.ValidateReviewedV1(); err != nil {
			return err
		}
		if err = source.ValidateCurrentV1(); err != nil {
			return err
		}
		if _, err = work.ConfirmLawfulBasisV1(call, "contract", "automation"); err != nil {
			return err
		}
		if _, err = work.FreezeBrandingV1(call); err != nil {
			return err
		}
		if err = work.ValidateFrozenBrandingV1(call, source); err != nil {
			return err
		}
		if err = work.CreateIntentV1(call, pdfadmission.HTMLSendIntentActorV1{IP: "127.0.0.1", Via: "automation", Tool: "signature_request"}); err != nil {
			return err
		}
		return work.BeginSendSealingV1(call)
	})
	if err != nil {
		return err
	}
	return session.CommitV1(stage.ContextV1())
}
