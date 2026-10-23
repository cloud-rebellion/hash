// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var errPreSignSourceUnsupportedV1 = errors.New("pre-sign source requires a supported original data witness")

// This schema3 command is distinct from the unchanged block-only automation
// command. No values, HTML/PDF bytes, provider identity or review flags enter.
type preSignAPISourceInputV1 struct {
	RequestID      uuid.UUID                                 `json:"request_id"`
	ExpectedOrgID  uuid.UUID                                 `json:"expected_org_id"`
	ExpectedUserID uuid.UUID                                 `json:"expected_user_id"`
	Policy         presign.Reference                         `json:"policy"`
	Grant          presign.Reference                         `json:"grant"`
	DocumentName   string                                    `json:"document_name"`
	CRMRecords     []presignregistry.RecordRule              `json:"crm_records,omitempty"`
	Prior          *pdfadmission.PreSignSupersessionParentV1 `json:"prior,omitempty"`
}

func preSignSourceReferenceV1(r presign.Reference) bool {
	raw, err := hex.DecodeString(r.SHA256)
	return r.ID != uuid.Nil && r.Revision > 0 && r.Revision <= presign.MaxRevision && err == nil && len(raw) == 32 && hex.EncodeToString(raw) == r.SHA256
}
func preSignSourceInputDigestV1(in preSignAPISourceInputV1, org, user, credential uuid.UUID, binding string) (string, error) {
	if org == uuid.Nil || user == uuid.Nil || credential == uuid.Nil || in.ExpectedOrgID != org || in.ExpectedUserID != user || in.RequestID == uuid.Nil ||
		!preSignSourceReferenceV1(in.Policy) || !preSignSourceReferenceV1(in.Grant) || !utf8.ValidString(in.DocumentName) ||
		strings.TrimSpace(in.DocumentName) == "" || utf8.RuneCountInString(in.DocumentName) > 200 || len(in.DocumentName) > 800 || strings.ContainsRune(in.DocumentName, 0) {
		return "", presignregistry.ErrInvalid
	}
	rawBinding, err := hex.DecodeString(binding)
	if err != nil || len(rawBinding) != 32 || hex.EncodeToString(rawBinding) != binding {
		return "", auth.ErrMutationPermissionRevoked
	}
	if len(in.CRMRecords) > 3 {
		return "", presignregistry.ErrInvalid
	}
	if in.Prior != nil && in.Prior.ValidateV1() != nil {
		return "", presignregistry.ErrInvalid
	}
	previous := ""
	for _, record := range in.CRMRecords {
		if record.Kind <= previous || crmconnection.ValidateRecordRef(crmconnection.RecordRef{Kind: crmconnection.RecordKind(record.Kind), ID: record.ID}) != nil {
			return "", presignregistry.ErrInvalid
		}
		previous = record.Kind
	}
	raw, err := json.Marshal(struct {
		Version          int                     `json:"version"`
		CredentialID     uuid.UUID               `json:"credential_id"`
		CredentialSHA256 string                  `json:"credential_sha256"`
		Input            preSignAPISourceInputV1 `json:"input"`
	}{1, credential, binding, in})
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("hash:presign-api-source-request:v1\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// The exact approved declarations are the sole values/sections producer.
// Existing HTML creation merges defaults. An absent rule with an existing
// default therefore refuses BEFORE rendering instead of pretending deletion.
func preSignSourceFrozenDataV1(d presignregistry.WorkflowDefinition, g presign.NamedRepresentative, master, defaultsJSON []byte) (htmlStringMap, htmlStringMap, error) {
	if d.Kind != presignregistry.KindApprovedData || d.Executor.UserID != g.UserID {
		return nil, nil, errPreSignSourceUnsupportedV1
	}
	if err := presignregistry.ValidateDefinitionAgainstTemplate(d, master, defaultsJSON); err != nil {
		return nil, nil, err
	}
	var defaults map[string]string
	if json.Unmarshal(defaultsJSON, &defaults) != nil {
		return nil, nil, presignregistry.ErrInvalid
	}
	values, sections := htmlStringMap{}, htmlStringMap{}
	grantor := map[string]string{"name": g.Name, "email": g.Email, "company_name": g.CompanyName, "company_id": g.CompanyID, "authority_basis": g.AuthorityBasis}
	for _, rule := range d.DataRules.Values {
		switch rule.Mode {
		case presignregistry.ModeDefault:
			value, ok := defaults[rule.Variable]
			if !ok {
				return nil, nil, presignregistry.ErrInvalid
			}
			values[rule.Variable] = value
		case presignregistry.ModeLiteral:
			if rule.Literal == nil {
				return nil, nil, presignregistry.ErrInvalid
			}
			values[rule.Variable] = *rule.Literal
		case presignregistry.ModeGrantor:
			value, ok := grantor[rule.GrantorField]
			if !ok {
				return nil, nil, presignregistry.ErrInvalid
			}
			values[rule.Variable] = value
		case presignregistry.ModeAbsent:
			if _, exists := defaults[rule.Variable]; exists {
				return nil, nil, errPreSignSourceUnsupportedV1
			}
		case presignregistry.ModeCRM:
			if d.DataRules.CRM == nil {
				return nil, nil, presignregistry.ErrInvalid
			} // protected native producer fills it after SQL retirement
		default:
			return nil, nil, errPreSignSourceUnsupportedV1
		}
	}
	for _, rule := range d.DataRules.Sections {
		switch rule.Mode {
		case presignregistry.ModeDefault: // genuine materializer selects approved text
		case presignregistry.ModeLiteral:
			if rule.Literal == nil {
				return nil, nil, presignregistry.ErrInvalid
			}
			sections[rule.Section] = *rule.Literal
		default:
			return nil, nil, errPreSignSourceUnsupportedV1
		}
	}
	return values, sections, nil
}

func preSignSourceActorV1(a auth.PreSignAPIAdmissionV1) authoring.Actor {
	return authoring.Actor{OrgID: a.OrgID(), UserID: a.UserID(), Authorize: a.AuthorizeV1}
}
func (s *Server) preSignSourceAdmissionV1(w http.ResponseWriter, r *http.Request) (auth.PreSignAPIAdmissionV1, bool) {
	a, err := auth.NewPreSignAPIAdmissionV1(r.Context(), uuid.Nil)
	if err != nil {
		writeError(w, http.StatusForbidden, "an original API credential with authoring and workflow scope is required")
		return a, false
	}
	if !s.requireHTMLAuthoringRuntimeV1(w) {
		return a, false
	}
	return a, true
}

// One private diagnostic wrapper. It grants no authority and preserves the
// exact original error text/chain. Only closed labels can reach the logger.
type preSignAPISourceDiagnosticV1 struct {
	stage string
	cause error
}

func (e *preSignAPISourceDiagnosticV1) Error() string { return e.cause.Error() }
func (e *preSignAPISourceDiagnosticV1) Unwrap() error { return e.cause }
func preSignAPISourceStageAllowedV1(stage string) bool {
	switch stage {
	case "input_digest", "initial_request", "replay_conflict", "replay_linked", "initial_open",
		"initial_authority", "initial_template", "initial_content", "initial_parent", "initial_frozen_data", "initial_crm_start",
		"initial_commit", "initial_transaction", "initial_sql_close", "crm_read", "crm_values",
		"callback_authorize", "callback_source_seal", "callback_parent_birth_read", "callback_supersession_audit", "callback_supersession_seal", "callback_reauthorize",
		"instantiate", "post_read", "post_linked", "post_linked_read",
		"html_prepare", "html_prepare_open", "html_prepare_maps", "html_template_revision", "html_template_author", "html_template_canonical", "html_prepare_commit",
		"html_render", "html_recheck", "html_artifact", "html_final_open", "html_final_writer", "html_final_source", "html_final_commit", "html_postcommit_publish":
		return true
	}
	return false
}
func preSignAPISourceStageV1(err error) string {
	var diagnostic *preSignAPISourceDiagnosticV1
	if errors.As(err, &diagnostic) && diagnostic != nil && preSignAPISourceStageAllowedV1(diagnostic.stage) {
		return diagnostic.stage
	}
	return ""
}
func preSignAPISourceFailureV1(stage string, err error) error {
	if err == nil || !preSignAPISourceStageAllowedV1(stage) || preSignAPISourceStageV1(err) != "" {
		return err
	}
	return &preSignAPISourceDiagnosticV1{stage: stage, cause: err}
}

// Only the explicit-prior API caller installs this private marker. Ordinary
// HTML creation returns the identical original error object, including nil.
type preSignAPIHTMLCreationPhaseKeyV1 struct{}

func preSignAPIHTMLCreationFailureV1(ctx context.Context, stage string, err error) error {
	if ctx == nil || ctx.Value(preSignAPIHTMLCreationPhaseKeyV1{}) != true {
		return err
	}
	return preSignAPISourceFailureV1(stage, err)
}

func (s *Server) writePreSignSourceErrorV1(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		writeError(w, 403, "original pre-sign source authority is unavailable")
	case errors.Is(err, presignregistry.ErrConflict):
		writeError(w, 409, "this original source request is closed or differs from its committed command")
	case errors.Is(err, errPreSignSourceUnsupportedV1):
		writeError(w, 422, "this workflow requires an original data witness unsupported by this source path")
	case errors.Is(err, presignregistry.ErrInvalid):
		writeError(w, 400, "invalid approved-data source command")
	case errors.Is(err, presignregistry.ErrNotFound):
		writeError(w, 404, "original source request not found")
	default:
		stage := preSignAPISourceStageV1(err)
		if stage != "" {
			kind := ""
			switch {
			case errors.Is(err, pdfadmission.ErrHTMLCreationWriterV1):
				kind = "html_creation_writer"
			case errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1):
				kind = "html_authoring_read"
			case errors.Is(err, pdfadmission.ErrHTMLAuditEventV1):
				kind = "html_audit_event"
			}
			if kind != "" {
				facts := []any{"request_id", middleware.GetReqID(ctx), "stage", stage, "error_kind", kind}
				canonical := pdfadmission.HTMLCanonicalDiagnosticV1(ctx)
				if canonical.Stage != "" {
					facts = append(facts, "canonical_stage", canonical.Stage, "atomic_decision", canonical.AtomicDecision, "reason", canonical.Reason, "dimension", canonical.Dimension,
						"requested_parent_bytes", canonical.RequestedParentBytes, "current_global_parent_bytes", canonical.GlobalParentBytes, "current_org_parent_bytes", canonical.OrganisationParentBytes,
						"global_parent_limit", canonical.GlobalParentLimit, "org_parent_limit", canonical.OrganisationParentLimit,
						"global_grants", canonical.GlobalGrants, "org_grants", canonical.OrganisationGrants, "global_grant_limit", canonical.GlobalGrantLimit, "org_grant_limit", canonical.OrganisationGrantLimit)
				}
				slog.ErrorContext(ctx, "pre-sign API source failed", facts...)
			}
		}
		s.writeHTMLCreationError(w, err)
	}
}

// POST /api/automation/v1/presign/documents. Route registration and the default
// disabled production gate belong to the existing server integration owner.
func (s *Server) handlePreSignAPISourceV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := requireAutomationJSONContentType(r.Header.Values("Content-Type")); err != nil {
		writeError(w, 415, "application/json is required")
		return
	}
	a, ok := s.preSignSourceAdmissionV1(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	r, closeInput, ok := s.beginHTMLAuthoringInputV1(w, r, a.OrgID(), pdfadmission.HTMLPreSignAPISourceInputV1)
	if !ok {
		return
	}
	defer closeInput()
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var in preSignAPISourceInputV1
	if err := decodeCRMTemplateJSON(r, &in); err != nil {
		if !writeHTMLAuthoringInputFailureV1(w, err) {
			writeError(w, 400, "invalid closed approved-data source command")
		}
		return
	}
	stageError := func(stage string, err error) error {
		if in.Prior == nil {
			return err
		}
		return preSignAPISourceFailureV1(stage, err)
	}
	fail := func(stage string, err error) { s.writePreSignSourceErrorV1(r.Context(), w, stageError(stage, err)) }
	digest, err := preSignSourceInputDigestV1(in, a.OrgID(), a.UserID(), a.CredentialID(), a.Commitment())
	if err != nil {
		fail("input_digest", err)
		return
	}
	// Resolve the SAME original request before current template/grant admission.
	prior, err := s.readPreSignAPISourceV1(ctx, a, in.RequestID, false)
	if err != nil {
		fail("initial_request", err)
		return
	}
	if prior.State != "unconfirmed" {
		if prior.State != "committed" || prior.InputSHA256 != digest {
			fail("replay_conflict", presignregistry.ErrConflict)
			return
		}
		if err = s.checkPreSignAPISupersessionResultV1(ctx, a, in, digest, prior); err != nil {
			fail("replay_linked", err)
			return
		}
		writeJSON(w, 200, prior)
		return
	}
	if s.Billing == nil || s.Audit == nil || s.Storage == nil || s.Sign == nil || s.Sign.PDF == nil || s.Versions == nil {
		writeError(w, 503, "approved HTML source dependencies unavailable")
		return
	}
	release, err := importguard.Shared.Acquire(a.OrgID())
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, 429, "source creation is temporarily busy")
		return
	}
	defer release()
	// Retain actual registry/template/default bodies through genuine preparation,
	// rendering, COMMIT and final response. No source byte model is fabricated.
	o, err := s.openHTMLAuthoringV1(ctx, a.OrgID(), in.RequestID)
	if err != nil {
		fail("initial_open", err)
		return
	}
	defer o.closeConsumerV1(ctx)
	defer o.closeSQLV1(ctx)
	command := pdfadmission.PreSignAPISourceCommandV1{RequestID: in.RequestID, InputSHA256: digest, Policy: in.Policy, Grant: in.Grant}
	var template presign.TemplatePin
	var values, sections htmlStringMap
	var nativeCRM *pdfadmission.ApplicationPreSignCRMSourceV1
	defer func() {
		if nativeCRM != nil {
			nativeCRM.CloseConsumerV1()
		}
	}()
	err = o.session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		authority, err := o.reader.LockPreSignAPIBirthAuthorityV1(call, a, in.Policy, in.Grant)
		if err != nil {
			return stageError("initial_authority", err)
		}
		definition := authority.Definition()
		template = authority.Policy().Snapshot().Template
		if template.Version < 1 || template.Version > presign.MaxRevision || authority.Grant().Snapshot().Grantor.UserID != a.UserID() {
			return presignregistry.ErrInvalid
		}
		row, revision, err := o.reader.ReadTemplateRevisionExpectedV1(call, template.ID, int32(template.Version), template.ContentSHA256)
		if err != nil {
			return stageError("initial_template", err)
		}
		if row.Version != int32(template.Version) || !revision.ApprovedBy.Valid || uuid.UUID(revision.ApprovedBy.Bytes) != template.ApprovedBy || !revision.ApprovedAt.Valid || !revision.ApprovedAt.Time.Equal(template.ApprovedAt) {
			return presignregistry.ErrConflict
		}
		content, err := o.reader.CanonicalRetainedTemplateV1(call, template.ID, int32(template.Version))
		if err != nil {
			return stageError("initial_content", err)
		}
		// Exact expected parent is checked under this genuine current API/policy
		// authority BEFORE any CRM provider, render, upload or fresh birth effects.
		if in.Prior != nil {
			if template.ID != in.Prior.Template.ID {
				return presignregistry.ErrInvalid
			}
			if err = o.reader.CheckPreSignSupersessionParentV1(call, a.UserID(), *in.Prior, template.ID); err != nil {
				return stageError("initial_parent", err)
			}
		}
		values, sections, err = preSignSourceFrozenDataV1(definition, authority.Grant().Snapshot().Grantor, content.MasterJSON, content.DefaultsJSON)
		if err != nil {
			return stageError("initial_frozen_data", err)
		}
		if definition.DataRules.CRM == nil {
			if len(in.CRMRecords) != 0 {
				return presignregistry.ErrInvalid
			}
			return nil
		}
		nativeCRM, err = o.reader.StartPreSignCRMSourceV1(call, ctx, a, command, in.CRMRecords, s.CRMClient, s.CRMKeys, s.CRMOrigin)
		return stageError("initial_crm_start", err)
	})
	if err == nil {
		err = stageError("initial_commit", o.session.CommitV1(ctx))
	}
	if err != nil {
		fail("initial_transaction", err)
		return
	}
	if err = o.closeSQLV1(ctx); err != nil {
		fail("initial_sql_close", err)
		return
	}
	var population htmlPopulationV1
	if nativeCRM != nil {
		if err = nativeCRM.ReadV1(); err != nil {
			fail("crm_read", err)
			return
		}
		observed, e := nativeCRM.ValuesV1()
		if e != nil {
			fail("crm_values", e)
			return
		}
		for name, value := range observed {
			values[name] = value
		}
		population = &preSignCRMSourcePopulationV1{native: nativeCRM, admission: a, command: command, template: template, values: values}
	}
	var pending []audit.PendingEvent
	actor := preSignSourceActorV1(a)
	actor.Authorize = func(call context.Context, tx pgx.Tx, u *generated.User) error {
		if err := a.AuthorizeV1(call, tx, u); err != nil {
			return stageError("callback_authorize", err)
		}
		reader, err := htmlAuthoringReaderV1(tx)
		if err != nil {
			return stageError("callback_source_seal", err)
		}
		if nativeCRM != nil {
			err = reader.SealPreSignAPICRMSourceV1(call, a, command, template, nativeCRM)
		} else {
			err = reader.SealPreSignAPISourceV1(call, a, command, template)
		}
		if err != nil || in.Prior == nil {
			return stageError("callback_source_seal", err)
		}
		event, ready, err := s.sealPreSignAPISupersessionV1(call, tx, reader, a, command, template, *in.Prior)
		if err != nil {
			return stageError("callback_supersession_seal", err)
		}
		if ready {
			pending = append(pending, event)
		}
		return stageError("callback_reauthorize", a.AuthorizeV1(call, tx, u))
	}
	htmlInput := htmlDocumentInput{Name: in.DocumentName, ExpectedTemplateVersion: int32(template.Version), ExpectedTemplateContentSHA256: template.ContentSHA256,
		Values: values, Sections: sections, RequestID: in.RequestID, ExpectedOrgID: a.OrgID(), ExpectedUserID: a.UserID()}
	rawDigest, err := hex.DecodeString(template.ContentSHA256)
	if err != nil {
		fail("instantiate", err)
		return
	}
	instantiateContext := ctx
	if in.Prior != nil {
		instantiateContext = context.WithValue(ctx, preSignAPIHTMLCreationPhaseKeyV1{}, true)
		instantiateContext = pdfadmission.WithHTMLCanonicalDiagnosticV1(instantiateContext)
	}
	result, err := s.instantiateHTMLDocumentPopulationV1(instantiateContext, actor, template.ID, htmlInput, rawDigest, pgtype.Timestamptz{}, population, digest)
	if err != nil {
		s.writePreSignSourceErrorV1(instantiateContext, w, stageError("instantiate", err))
		return
	}
	result.closeOwnedWriterV1()
	for _, event := range pending {
		s.Audit.Publish(detachHTMLCreationEventIDsV1(event))
	}
	view, err := s.readPreSignAPISourceV1(ctx, a, in.RequestID, false)
	if err != nil || view.State != "committed" || view.InputSHA256 != digest {
		if err == nil {
			err = pdfadmission.ErrHTMLAuthoringReadV1
		}
		fail("post_read", err)
		return
	}
	if err = s.checkPreSignAPISupersessionResultV1(ctx, a, in, digest, view); err != nil {
		fail("post_linked", err)
		return
	}
	status := http.StatusCreated
	if result.replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, view)
}

func preSignSourceRequestIDV1(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := chi.URLParam(r, "request_id")
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || id.String() != raw || len(r.URL.Query()) != 0 {
		writeError(w, 400, "canonical original request UUID required")
		return uuid.Nil, false
	}
	return id, true
}
func (s *Server) handleGetPreSignAPISourceV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.preSignSourceAdmissionV1(w, r)
	if !ok {
		return
	}
	request, ok := preSignSourceRequestIDV1(w, r)
	if !ok {
		return
	}
	view, err := s.readPreSignAPISourceV1(r.Context(), a, request, false)
	if err != nil {
		s.writePreSignSourceErrorV1(r.Context(), w, err)
		return
	}
	status := http.StatusOK
	if view.State == "unconfirmed" {
		status = http.StatusNotFound
	}
	writeJSON(w, status, view)
}
func (s *Server) handleClosePreSignAPISourceV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.preSignSourceAdmissionV1(w, r)
	if !ok {
		return
	}
	request, ok := preSignSourceRequestIDV1(w, r)
	if !ok {
		return
	}
	if err := requireAutomationJSONContentType(r.Header.Values("Content-Type")); err != nil {
		writeError(w, 415, "application/json is required")
		return
	}
	r, closeInput, ok := s.beginHTMLAuthoringInputV1(w, r, a.OrgID(), pdfadmission.HTMLCreationClosureInputV1)
	if !ok {
		return
	}
	defer closeInput()
	r.Body = http.MaxBytesReader(w, r.Body, 2<<10)
	var in htmlCreationCloseInput
	if decodeCRMTemplateJSON(r, &in) != nil || !in.Confirmed || in.ExpectedOrgID != a.OrgID().String() || in.ExpectedUserID != a.UserID().String() {
		writeError(w, 400, "original actor and explicit close confirmation required")
		return
	}
	view, err := s.readPreSignAPISourceV1(r.Context(), a, request, true)
	if err != nil {
		s.writePreSignSourceErrorV1(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, view)
}

func (s *Server) readPreSignAPISourceV1(ctx context.Context, a auth.PreSignAPIAdmissionV1, request uuid.UUID, closeRequest bool) (out pdfadmission.PreSignAPISourceViewV1, failure error) {
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, a.OrgID(), request)
	if err != nil {
		return out, err
	}
	defer o.closeConsumerV1(ctx)
	defer o.closeSQLV1(ctx)
	var pending *audit.PendingEvent
	err = o.session.WithTxV1(ctx, func(call context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		if closeRequest {
			if s.Audit == nil {
				return pdfadmission.ErrHTMLAuthoringReadV1
			}
			if err := generated.New(tx).LockBillingUsageForOrg(call, a.OrgID().String()); err != nil {
				return err
			}
		}
		guard, err := lockHTMLAuthorV1(call, tx, preSignSourceActorV1(a), false)
		if err != nil {
			return err
		}
		if closeRequest {
			out, err = o.reader.ReadPreSignAPISourceV1(call, a, request)
			if err != nil {
				return err
			}
			if out.State == "unconfirmed" {
				user := a.UserID()
				event, e := s.Audit.LogTx(call, tx, audit.Entry{OrgID: a.OrgID(), ActorUserID: &user, Kind: "presign.source.request.closed", Payload: map[string]any{"request_id": request, "executor_credential_id": a.CredentialID()}})
				if e != nil {
					return e
				}
				var changed bool
				out, changed, err = o.reader.ClosePreSignAPISourceV1(call, a, request, event.ID)
				if err != nil {
					return err
				}
				if !changed {
					return presignregistry.ErrConflict
				}
				pending = &event
			}
		} else {
			out, err = o.reader.ReadPreSignAPISourceV1(call, a, request)
			if err != nil {
				return err
			}
		}
		return guard.Recheck(call)
	})
	if err != nil {
		return out, err
	}
	if err = o.session.CommitV1(ctx); err != nil {
		return out, err
	}
	if pending != nil {
		s.Audit.Publish(detachHTMLCreationEventIDsV1(*pending))
	}
	return out, nil
}
