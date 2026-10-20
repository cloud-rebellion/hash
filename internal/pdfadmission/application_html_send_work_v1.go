// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/google/uuid"
)

var ErrHTMLSendWorkV1 = errors.New("pdfadmission: owned standalone HTML send unavailable")

type HTMLSendModelsV1 struct {
	Document   *generated.Document
	Current    *htmlmaterialization.CurrentReadProjectionV1
	Recipients []*generated.Recipient
	Fields     []*generated.DocumentField
	Bindings   []*generated.DocumentVariableBinding
}

// Fixed same-session read work. Original actor/credential/source/CRM/evidence
// checks remain mandatory in Send. This owner supplies no family authority.
type ApplicationHTMLSendWorkV1 struct {
	reminder                                                                                          *applicationReminderStateV1
	reminderIdentityAttempted                                                                         bool
	fieldListRead, fieldListCredentialRead                                                            bool
	mu                                                                                                sync.Mutex
	self                                                                                              *ApplicationHTMLSendWorkV1
	session                                                                                           *ApplicationSessionV1
	stage                                                                                             *ApplicationHTMLSendSQLStageV1
	observationsAttempted                                                                             bool
	crmReviewChecks                                                                                   int
	recipientsAttempted, fieldsAttempted, bindingsAttempted                                           bool
	recipientsRead, fieldsRead, bindingsRead                                                          bool
	quotaAttempted                                                                                    bool
	sourceActor                                                                                       *generated.User
	sourceIntent                                                                                      *generated.SendSealingIntent
	evidence                                                                                          *ApplicationHTMLSendEvidenceV1
	packageDraft                                                                                      *applicationHTMLSendPackageDraftStateV1
	packageDraftAttempted                                                                             bool
	packageCapture                                                                                    *applicationHTMLSendPackageCaptureStateV1
	packageIntentAttempted                                                                            bool
	packageCaptureAttempted                                                                           bool
	packageInitialLookupAttempted, packageInitialSelectionChecked                                     bool
	packageRecoveryInspectionAttempted                                                                bool
	packageCompletion                                                                                 *applicationPackageSendCompletionV1
	packageAudits                                                                                     *applicationPackageSendAuditBatchV1
	completionOutputs                                                                                 *htmlSendCompletionOutputsV1
	completionOutputsAttempted, completedAttempted, expiredAttempted                                  bool
	confirmed, intentCreated, beginSealingAttempted, pinsAttempted, pinsCompleted                     bool
	confirmedBasis                                                                                    string
	confirmedBasisValid                                                                               bool
	sourceBorrowers                                                                                   int
	sourceStarted                                                                                     bool
	sourceOwner                                                                                       *applicationHTMLRevisionSourceOwnerV1
	sourceState, resolvedState                                                                        *applicationHTMLSendSourceStateV1
	resolverOwner                                                                                     *applicationHTMLSendResolverV1
	resolvedOwner                                                                                     *applicationHTMLRevisionSourceOwnerV1
	resolvedStarted, reviewedCandidateValidated                                                       bool
	resourcesClosed                                                                                   bool
	actor                                                                                             *ApplicationHTMLAuthoringReaderV1
	queries                                                                                           *generated.Queries
	state                                                                                             *generated.GetHTMLSendDocumentStateHeaderV1Row
	familyRoot                                                                                        *ApplicationHTMLSendWorkV1
	memberDocument                                                                                    uuid.UUID
	familyMembers                                                                                     []*ApplicationHTMLSendWorkV1
	familyMembersAttempted                                                                            bool
	familyPin                                                                                         *generated.ListBlockSendFamilyMemberPinsV1Row
	familyReleaseRoot                                                                                 func()
	familyMutations                                                                                   *blockSendFamilyMutationsV1
	completedDocument                                                                                 *generated.Document
	blockSignature                                                                                    *applicationBlockSignatureMutationV1
	acknowledgement                                                                                   *applicationAcknowledgementMutationV1
	packageResponse                                                                                   *applicationPackageResponseMutationV1
	responseReportFamilyPrepared, responseReportAttempted                                             bool
	signerView                                                                                        *applicationSignerViewMutationV1
	signerFields                                                                                      *applicationSignerFieldsMutationV1
	comment                                                                                           *applicationCommentMutationV1
	commentPageRead, commentPageCredentialRead                                                        bool
	finalization                                                                                      *applicationHistoricalFinalizationV1
	certificateRead                                                                                   *applicationHistoricalCertificateReadV1
	finalizationEvidence                                                                              *ApplicationHistoricalFinalizationEvidenceV1
	historicalSourceEvidence                                                                          *ApplicationHistoricalFinalizationSourceEvidenceV1
	sourceDocument                                                                                    *generated.Document
	sourceServerVersion                                                                               int32
	priorFrozenSource                                                                                 *applicationHTMLSendSourceStateV1
	priorPinnedSource                                                                                 *applicationHTMLSendSourceStateV1
	freezeVariablesAttempted                                                                          bool
	sourceCurrent                                                                                     *htmlmaterialization.CurrentReadProjectionV1
	sourceRecipients                                                                                  []*generated.Recipient
	sourceFields                                                                                      []*generated.DocumentField
	sourceBindings                                                                                    []*generated.DocumentVariableBinding
	frozenBranding                                                                                    *generated.DocumentBrandingOverride
	models                                                                                            *HTMLSendModelsV1
	closes                                                                                            []func()
	call                                                                                              context.Context
	initialPolicyAttempted, initialPolicyRead, currentAttempted, currentRead                          bool
	modelsRead, intentRead, brandingWritten, signingStateAttempted, reviewedOriginalValidated, closed bool
}

func (h *ApplicationSessionV1) NewHTMLSendWorkV1(ctx context.Context, stage *ApplicationHTMLSendSQLStageV1) (*ApplicationHTMLSendWorkV1, error) {
	if h == nil || h.state == nil || stage == nil || stage.self != stage || stage.operation == nil || stage.operation.self != stage.operation {
		return nil, ErrHTMLSendWorkV1
	}
	o := stage.operation
	o.mu.Lock()
	if o.closed || !stage.active || stage.session != h || stage.work != nil || stage.startingWork || o.factory == nil || o.factory.state != h.state.factory || o.org != h.state.org || o.document != h.state.document || o.original.Err() != nil {
		o.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	stage.startingWork = true
	o.mu.Unlock()
	actor, err := h.NewHTMLAuthoringReaderV1(ctx)
	if err != nil {
		o.mu.Lock()
		stage.startingWork = false
		o.mu.Unlock()
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w := &ApplicationHTMLSendWorkV1{call: ctx, session: h, stage: stage, actor: actor, queries: generated.New(&applicationOwnedDBTXV1{session: h.state})}
	w.self = w
	o.mu.Lock()
	stage.startingWork = false
	if stage.work != nil {
		o.mu.Unlock()
		actor.CloseConsumerV1()
		return nil, ErrHTMLSendWorkV1
	}
	stage.work = w
	closed := o.closed
	o.mu.Unlock()
	if closed {
		w.CloseConsumerV1()
		return nil, ErrHTMLSendWorkV1
	}
	return w, nil
}
func (w *ApplicationHTMLSendWorkV1) valid(ctx context.Context) bool {
	return w != nil && w.self == w && !w.closed && w.session != nil && w.session.state != nil && w.actor != nil && w.actor.valid(ctx) && w.queries != nil
}
func (w *ApplicationHTMLSendWorkV1) StateV1(ctx context.Context) (*generated.GetHTMLSendDocumentStateHeaderV1Row, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) {
		return nil, ErrHTMLSendWorkV1
	}
	if w.state == nil {
		s := w.session.state
		h, err := w.queries.GetHTMLSendDocumentStateHeaderV1(ctx, generated.GetHTMLSendDocumentStateHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org})
		if err != nil {
			return nil, err
		}
		if h == nil || h.ID != w.logicalDocumentV1() || h.OrgID != s.org {
			return nil, ErrHTMLSendWorkV1
		}
		if pin := w.familyPin; pin != nil && (h.ParentEnvelopeID != pin.ParentEnvelopeID || h.UpdatedAt != pin.UpdatedAt || h.IsEnvelope != pin.IsEnvelope || h.RequiresSignature != pin.RequiresSignature || h.IsPdfSource != pin.IsPdfSource || h.BoundedStatus != pin.BoundedStatus) {
			return nil, ErrHTMLSendWorkV1
		}
		w.state = h
	}
	copy := *w.state
	return &copy, nil
}
func (w *ApplicationHTMLSendWorkV1) AcquireActorV1(ctx context.Context, user uuid.UUID) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || user == uuid.Nil {
		return ErrHTMLSendWorkV1
	}
	return w.actor.AcquireActorV1(ctx, w.session.state.org, user, true)
}

func (w *ApplicationHTMLSendWorkV1) ReadModelsV1(ctx context.Context) (*HTMLSendModelsV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.modelsRead || w.state == nil || (w.state.ParentEnvelopeID.Valid && w.familyRoot == nil && w.stage.purpose != HTMLSignerViewMutationV1 && w.stage.purpose != HTMLSignerFieldsMutationV1 && w.stage.purpose != HTMLSignerCommentMutationV1 && w.stage.purpose != HTMLStaffCommentMutationV1) || (w.familyRoot == nil && w.state.BoundedStatus != "draft" && w.state.BoundedStatus != "sealing" && w.stage.purpose != HTMLBlockSignPreparationV1 && w.stage.purpose != HTMLBlockSignMutationV1 && w.stage.purpose != HTMLHistoricalFinalizationClaimV1 && w.stage.purpose != HTMLHistoricalFinalizationStageV1 && w.stage.purpose != HTMLHistoricalFinalizationResumeV1 && w.stage.purpose != HTMLHistoricalFinalizationPublicationV1 && w.stage.purpose != HTMLHistoricalFinalizationSourceV1 && w.stage.purpose != HTMLAcknowledgementMutationV1 && w.stage.purpose != HTMLSignerViewMutationV1 && w.stage.purpose != HTMLSignerFieldsMutationV1 && w.stage.purpose != HTMLSignerCommentMutationV1 && w.stage.purpose != HTMLStaffCommentMutationV1 && w.stage.purpose != HTMLReminderManualV1 && w.stage.purpose != HTMLReminderScheduledV1) {
		return nil, ErrHTMLSendWorkV1
	}
	w.modelsRead = true
	s := w.session.state
	h, err := w.queries.GetHTMLRevisionDocumentReadHeaderV1(ctx, generated.GetHTMLRevisionDocumentReadHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.ID != w.logicalDocumentV1() || h.OrgID != s.org || h.UpdatedAt != w.state.UpdatedAt || h.ServerVersionNum <= 0 || h.PolicyMeasurementServerVersionNum != h.ServerVersionNum || h.ResponseMeasurementServerVersionNum != h.ServerVersionNum || h.ReportMeasurementServerVersionNum != h.ServerVersionNum {
		return nil, ErrHTMLSendWorkV1
	}
	wire, err := htmlAuthoringSumV1(h.HtmlOriginWireBytes, h.HtmlCurrentWireBytes, h.VariablesWireBytes, h.BlocksWireBytes, h.MetadataWireBytes, h.ReportWireBytes)
	if err != nil {
		return nil, ErrHTMLSendWorkV1
	}
	raw := h.RawTextBytes
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	doc, err := w.queries.ReadSignerDocumentV1(ctx, generated.ReadSignerDocumentV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org, ExpectedUpdatedAt: h.UpdatedAt, ExpectedHtmlOriginWireBytes: h.HtmlOriginWireBytes, ExpectedHtmlCurrentWireBytes: h.HtmlCurrentWireBytes, ExpectedVariablesWireBytes: h.VariablesWireBytes, ExpectedBlocksWireBytes: h.BlocksWireBytes, ExpectedMetadataWireBytes: h.MetadataWireBytes, ExpectedReportWireBytes: h.ReportWireBytes})
	if err != nil {
		return nil, err
	}
	if doc == nil || (doc.SourceKind != "pdf" && doc.SourceKind != "blocks") || (doc.SourceKind == "pdf") != w.state.IsPdfSource || doc.ID != w.logicalDocumentV1() || doc.OrgID != s.org || doc.UpdatedAt != h.UpdatedAt || signerDocumentRawBytesV1(doc) != h.RawTextBytes || int64(len(doc.HtmlSourceJson)) != h.HtmlOriginWireBytes || int64(len(doc.HtmlCurrentSourceJson)) != h.HtmlCurrentWireBytes || int64(len(doc.VariablesJson)) != h.VariablesWireBytes || int64(len(doc.BlocksJson)) != h.BlocksWireBytes || int64(len(doc.Metadata)) != h.MetadataWireBytes || int64(len(doc.MetadataRedactionReport)) != h.ReportWireBytes {
		return nil, ErrHTMLSendWorkV1
	}
	w.sourceDocument = htmlSendCloneDocumentV1(doc)
	w.sourceServerVersion = h.ServerVersionNum
	w.models = &HTMLSendModelsV1{Document: doc}
	return w.models, nil
}

// ReadInitialPolicyV1 is the genuine small policy projection, before any
// document JSON/report or Current12 query. Its retained body grant comes from
// this SAME actual locked scalar header, never a caller model or byte count.
func (w *ApplicationHTMLSendWorkV1) ReadInitialPolicyV1(ctx context.Context) (*generated.ReadHTMLSendInitialPolicyV1Row, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.state == nil || w.stage.purpose != HTMLSendPreparationV1 || w.initialPolicyAttempted || w.modelsRead {
		return nil, ErrHTMLSendWorkV1
	}
	w.initialPolicyAttempted = true
	s := w.session.state
	h, err := w.queries.GetHTMLSendInitialPolicyHeaderV1(ctx, generated.GetHTMLSendInitialPolicyHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != w.logicalDocumentV1() || h.OrgID != s.org || h.UpdatedAt != w.state.UpdatedAt || h.RawTextBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, h.RawTextBytes, 0)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.ReadHTMLSendInitialPolicyV1(ctx, generated.ReadHTMLSendInitialPolicyV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != w.logicalDocumentV1() || row.OrgID != s.org || row.UpdatedAt != h.UpdatedAt || int64(len(row.RoutingTier)+len(row.PdfStorageKey.String)) != h.RawTextBytes {
		return nil, ErrHTMLSendWorkV1
	}
	w.initialPolicyRead = true
	return row, nil
}

// Called only by the fixed ValidateCurrentV1 decision with a live original
// callback. Reviewed-source failure wins before this query/cache expansion.
func (w *ApplicationHTMLSendWorkV1) readCurrentForSourceV1(owner *applicationHTMLRevisionSourceOwnerV1) (*htmlmaterialization.CurrentReadProjectionV1, error) {
	if w == nil || w.self != w || owner == nil {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	ctx := w.call
	if !w.valid(ctx) || w.sourceDocument == nil || w.models == nil || (owner != w.sourceOwner && owner != w.resolvedOwner) {
		return nil, ErrHTMLSendWorkV1
	}
	if w.currentRead {
		return w.sourceCurrent, nil
	}
	if w.currentAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	w.currentAttempted = true
	doc := w.sourceDocument
	s := w.session.state
	if len(doc.HtmlCurrentSourceJson) == 0 {
		w.currentRead = true
		return nil, nil
	}
	h, err := w.queries.GetSignerCurrentMaterializationHeaderV1(ctx, generated.GetSignerCurrentMaterializationHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != w.logicalDocumentV1() || h.OrgID != s.org || h.MaterializationID == uuid.Nil || h.SourceWireBytes != int64(len(doc.HtmlCurrentSourceJson)) || h.ServerVersionNum <= 0 || h.MeasurementServerVersionNum != h.ServerVersionNum || (h.ReportWireUpperBound != 0 && h.ReportWireUpperBound != 65536) {
		return nil, ErrHTMLSendWorkV1
	}
	wire, err := htmlAuthoringSumV1(h.SourceWireBytes, h.ReportWireUpperBound)
	if err != nil {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, h.RawTextBytes, wire)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	m, err := w.queries.ReadSignerCurrentMaterializationV1(ctx, generated.ReadSignerCurrentMaterializationV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org, ExpectedMaterializationID: h.MaterializationID, ExpectedSourceWireBytes: h.SourceWireBytes, ExpectedRawTextBytes: h.RawTextBytes, ExpectedReportWireUpperBound: h.ReportWireUpperBound})
	if err != nil {
		return nil, err
	}
	if m == nil || m.ID != h.MaterializationID || m.DocumentID != w.logicalDocumentV1() || m.OrgID != s.org || !doc.HtmlCurrentMaterializationID.Valid || uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) != m.ID || int64(len(m.SourceJson)) != h.SourceWireBytes || int64(len(m.MetadataRedactionReport)) > h.ReportWireUpperBound || signerMaterializationRawBytesV1(m) != h.RawTextBytes {
		return nil, ErrHTMLSendWorkV1
	}
	current := &htmlmaterialization.CurrentReadProjectionV1{ID: m.ID, DocumentID: m.DocumentID, OrgID: m.OrgID, Sequence: m.Sequence, PageCount: m.PageCount, PdfKey: m.PdfKey, PdfVersionID: m.PdfVersionID, PdfSha256: m.PdfSha256, SourceCommitment: m.SourceCommitment, OriginCommitment: m.OriginCommitment, SourceJson: m.SourceJson, MetadataRedactionReport: m.MetadataRedactionReport}
	copy := *current
	copy.PdfKey = strings.Clone(current.PdfKey)
	copy.PdfVersionID = strings.Clone(current.PdfVersionID)
	copy.PdfSha256 = bytes.Clone(current.PdfSha256)
	copy.SourceCommitment = bytes.Clone(current.SourceCommitment)
	copy.OriginCommitment = bytes.Clone(current.OriginCommitment)
	copy.SourceJson = bytes.Clone(current.SourceJson)
	copy.MetadataRedactionReport = bytes.Clone(current.MetadataRedactionReport)
	w.sourceCurrent = &copy
	w.models.Current = current
	w.currentRead = true
	return w.sourceCurrent, nil
}

func (w *ApplicationHTMLSendWorkV1) ReadIntentV1(ctx context.Context) (*generated.SendSealingIntent, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.intentRead || w.state == nil {
		return nil, ErrHTMLSendWorkV1
	}
	w.intentRead = true
	s := w.session.state
	h, err := w.queries.GetHTMLSendIntentReadHeaderV1(ctx, generated.GetHTMLSendIntentReadHeaderV1Params{DocumentID: s.document, OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != w.logicalDocumentV1() || h.OrgID != s.org || h.RawTextBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	if h.PackageSendAttemptID.Valid {
		return nil, ErrHTMLSendPackagePathRequiredV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, h.RawTextBytes, 0)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	intent, err := w.queries.ReadHTMLSendIntentV1(ctx, generated.ReadHTMLSendIntentV1Params{DocumentID: s.document, OrgID: s.org, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if intent == nil || intent.DocumentID != s.document || intent.OrgID != s.org || intent.UpdatedAt != h.UpdatedAt || intent.PackageSendAttemptID != h.PackageSendAttemptID || int64(len(intent.ActorEmail)+len(intent.ActorIp)+len(intent.Via)+len(intent.Tool)+len(intent.LastError.String)) != h.RawTextBytes {
		return nil, ErrHTMLSendWorkV1
	}
	copy := *intent
	copy.ActorEmail = strings.Clone(intent.ActorEmail)
	copy.ActorIp = strings.Clone(intent.ActorIp)
	copy.Via = strings.Clone(intent.Via)
	copy.Tool = strings.Clone(intent.Tool)
	copy.LastError.String = strings.Clone(intent.LastError.String)
	w.sourceIntent = &copy
	return intent, nil
}
func (w *ApplicationHTMLSendWorkV1) FreezeBrandingV1(ctx context.Context) (*generated.DocumentBrandingOverride, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.brandingWritten || w.models == nil {
		return nil, ErrHTMLSendWorkV1
	}
	w.brandingWritten = true
	s := w.session.state
	h, err := w.queries.GetHTMLSendBrandingInputHeaderV1(ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != w.logicalDocumentV1() || h.OrgID != s.org {
		return nil, ErrHTMLSendWorkV1
	}
	defaults := branding.DefaultBranding()
	defaultRaw := int64(len(defaults.PrimaryHex) + len(defaults.AccentHex) + len(defaults.SurfaceHex) + len(defaults.TextHex) + len(defaults.MutedHex) + len(defaults.LogoURL) + len(defaults.LogoAlt) + len(defaults.FontHeading) + len(defaults.FontBody) + len(defaults.SignatureColor))
	raw, err := htmlAuthoringSumV1(h.OrgBrandingRawBytes, h.DocumentBrandingRawBytes, defaultRaw)
	if err != nil {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.FreezeHTMLSendBrandingV1(ctx, generated.FreezeHTMLSendBrandingV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org, ExpectedHasOrgBranding: h.HasOrgBranding, ExpectedHasDocumentBranding: h.HasDocumentBranding, ExpectedOrgBrandingRawBytes: h.OrgBrandingRawBytes, ExpectedDocumentBrandingRawBytes: h.DocumentBrandingRawBytes, DefaultPrimaryHex: defaults.PrimaryHex, DefaultAccentHex: defaults.AccentHex, DefaultSurfaceHex: defaults.SurfaceHex, DefaultTextHex: defaults.TextHex, DefaultMutedHex: defaults.MutedHex, DefaultLogoUrl: defaults.LogoURL, DefaultLogoAlt: defaults.LogoAlt, DefaultFontHeading: defaults.FontHeading, DefaultFontBody: defaults.FontBody, DefaultSignatureColor: defaults.SignatureColor})
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != w.logicalDocumentV1() {
		return nil, ErrHTMLSendWorkV1
	}
	snapshot := &generated.DocumentBrandingOverride{DocumentID: row.DocumentID, PrimaryHex: row.PrimaryHex, AccentHex: row.AccentHex, SurfaceHex: row.SurfaceHex, TextHex: row.TextHex, MutedHex: row.MutedHex, LogoUrl: row.LogoUrl, LogoAlt: row.LogoAlt, FontHeading: row.FontHeading, FontBody: row.FontBody, SignatureColor: row.SignatureColor}
	w.frozenBranding = htmlSendCloneBrandingV1(snapshot)
	return snapshot, nil
}
func (w *ApplicationHTMLSendWorkV1) retireSourcesLockedV1() ([]func(), *ApplicationHTMLAuthoringReaderV1) {
	if !w.closed || w.resourcesClosed || w.sourceBorrowers != 0 {
		return nil, nil
	}
	w.resourcesClosed = true
	w.models = nil
	w.familyMembers = nil
	w.familyMutations = nil
	w.completedDocument = nil
	w.blockSignature = nil
	w.acknowledgement = nil
	w.packageResponse = nil
	w.reminder = nil
	w.signerView = nil
	w.signerFields = nil
	w.comment = nil
	w.finalization = nil
	w.certificateRead = nil
	w.call = nil
	w.confirmedBasis = ""
	w.completionOutputs = nil
	w.sourceActor = nil
	w.sourceIntent = nil
	w.packageCompletion = nil
	w.packageAudits = nil
	w.sourceDocument = nil
	w.sourceCurrent = nil
	w.sourceRecipients = nil
	w.sourceFields = nil
	w.sourceBindings = nil
	w.frozenBranding = nil
	w.state = nil
	closes := w.closes
	w.closes = nil
	actor := w.actor
	w.actor = nil
	return closes, actor
}
func htmlSendCloseSourceResourcesV1(closes []func(), actor *ApplicationHTMLAuthoringReaderV1) {
	for _, close := range closes {
		if close != nil {
			close()
		}
	}
	if actor != nil {
		actor.CloseConsumerV1()
	}
}
func (w *ApplicationHTMLSendWorkV1) CloseConsumerV1() {
	if w == nil || w.self != w {
		return
	}
	w.mu.Lock()
	w.closed = true
	reminder := w.reminder
	members := w.familyMembers
	finalizationEvidence := w.finalizationEvidence
	w.finalizationEvidence = nil
	historicalSourceEvidence := w.historicalSourceEvidence
	w.historicalSourceEvidence = nil
	evidence := w.evidence
	w.evidence = nil
	packageDraft := w.packageDraft
	w.packageDraft = nil
	w.packageCapture = nil
	resolverOwner := w.resolverOwner
	w.resolverOwner = nil
	source := w.sourceOwner
	w.sourceOwner = nil
	resolved := w.resolvedOwner
	w.resolvedOwner = nil
	sourceState, resolvedState, priorFrozenSource, priorPinnedSource := w.sourceState, w.resolvedState, w.priorFrozenSource, w.priorPinnedSource
	w.sourceState = nil
	w.resolvedState = nil
	w.priorFrozenSource = nil
	w.priorPinnedSource = nil
	closes, actor := w.retireSourcesLockedV1()
	w.mu.Unlock()
	if reminder != nil {
		reminder.closeConsumerV1()
	}
	for _, member := range members {
		if member != nil {
			member.CloseConsumerV1()
		}
	}
	if finalizationEvidence != nil {
		finalizationEvidence.CloseConsumerV1()
	}
	if historicalSourceEvidence != nil {
		historicalSourceEvidence.CloseConsumerV1()
	}
	if evidence != nil {
		evidence.CloseConsumerV1()
	}
	if packageDraft != nil {
		packageDraft.closeV1()
	}
	if resolverOwner != nil {
		resolverOwner.CloseConsumerV1()
	}
	if resolvedState != nil {
		resolvedState.closeV1()
	} else if resolved != nil {
		(&ApplicationHTMLRevisionSourceV1{state: resolved}).CloseConsumerV1()
	}
	if sourceState != nil {
		sourceState.closeV1()
	} else if source != nil {
		(&ApplicationHTMLRevisionSourceV1{state: source}).CloseConsumerV1()
	}
	if priorFrozenSource != nil {
		priorFrozenSource.closeV1()
	}
	if priorPinnedSource != nil {
		priorPinnedSource.closeV1()
	}
	htmlSendCloseSourceResourcesV1(closes, actor)
	w.releaseFamilyRootIfRetiredV1()
}

// Private native body borrower for the common fixed source owner. No caller
// Document, later context, reported raw bytes or mutable model can mint it.
func (w *ApplicationHTMLSendWorkV1) borrowHTMLSendSourceV1() (*generated.Document, *htmlmaterialization.CurrentReadProjectionV1, func(), error) {
	if w == nil || w.self != w {
		return nil, nil, nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if w.closed || w.resourcesClosed || w.stage == nil || w.stage.self != w.stage || w.stage.operation == nil || w.stage.operation.self != w.stage.operation || w.sourceDocument == nil || w.models == nil || w.session == nil || w.session.state == nil || w.stage.session != w.session {
		w.mu.Unlock()
		return nil, nil, nil, ErrHTMLSendWorkV1
	}
	o := w.stage.operation
	if o.original.Err() != nil || !time.Now().Before(o.deadline) || o.org != w.sourceDocument.OrgID || w.logicalDocumentV1() != w.sourceDocument.ID || o.factory == nil || o.factory.state != w.session.state.factory {
		w.mu.Unlock()
		return nil, nil, nil, ErrHTMLSendWorkV1
	}
	w.sourceBorrowers++
	document, current := w.sourceDocument, w.sourceCurrent
	w.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			w.mu.Lock()
			w.sourceBorrowers--
			closes, actor := w.retireSourcesLockedV1()
			w.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			w.releaseFamilyRootIfRetiredV1()
		})
	}
	return document, current, release, nil
}

// Immutable grant minted only from the SAME actual scoped scalar header.
// It is a fixed native stage token, never public caller work/byte authority.
type applicationHTMLSendCollectionGrantV1 struct {
	self                 *applicationHTMLSendCollectionGrantV1
	owner                *ApplicationHTMLSendWorkV1
	session              *applicationOwnedSessionV1
	admission            *ApplicationAdmissionV1
	work                 *WorkAdmissionV1
	bodyHeader           *applicationHTMLAuthoringBodyHeaderV1
	actor                *ApplicationHTMLAuthoringReaderV1
	callbackDone         <-chan struct{}
	org, document        uuid.UUID
	header               generated.GetHTMLSendCollectionReadHeaderV1Row
	purpose              htmlSendCollectionPurposeV1
	parentBytes, dbBytes int64
}

func htmlSendCollectionResourcesV1(h generated.GetHTMLSendCollectionReadHeaderV1Row, purpose htmlSendCollectionPurposeV1) (parent, db int64, err error) {
	if purpose < htmlSendRecipientCollectionV1 || purpose > htmlSendFieldCollectionV1 {
		return 0, 0, ErrHTMLSendWorkV1
	}
	wire := int64(0)
	if purpose == htmlSendFieldCollectionV1 {
		wire = h.FieldOptionsWireBytes
	}
	raw, e := htmlAuthoringSumV1(h.RecipientRawBytes, h.FieldRawBytes, h.BindingRawBytes)
	if e != nil || h.FieldOptionsWireBytes < 0 || h.RecipientCount < 0 || h.FieldCount < 0 || h.BindingCount < 0 {
		return 0, 0, ErrHTMLSendWorkV1
	}
	// Logical parent/DB staging classes agree with the existing8raw/16wire
	// retained-body class under this SAME actual reader header. Explicit counts
	// price Go model+pointer copies and fixed SQL
	// ID/timestamp pin/sort staging. These are not PostgreSQL/RSS heap claims.
	resources, e := htmlAuthoringRetainedBodyResourcesV1(raw, wire)
	if e != nil {
		return 0, 0, ErrHTMLSendWorkV1
	}
	parent, db = resources.WorkingBytes, resources.DBStagingBytes
	for _, part := range [][2]int64{{h.RecipientCount, int64(unsafe.Sizeof(generated.Recipient{})) + 16}, {h.FieldCount, int64(unsafe.Sizeof(generated.DocumentField{})) + 16}, {h.BindingCount, int64(unsafe.Sizeof(generated.DocumentVariableBinding{})) + 16}} {
		if !htmlInputAddV1(&parent, part[0], 4*part[1]) || !htmlInputAddV1(&db, part[0], 64) {
			return 0, 0, ErrHTMLSendWorkV1
		}
	}
	// Actual migration4 geometry is NUMERIC(7,4): one word per Int. All four
	// native/public copies plus big.Int objects and rounded limbs stay retained.
	if !htmlInputAddV1(&parent, h.FieldCount, 8*4*(int64(unsafe.Sizeof(big.Int{}))+16)) {
		return 0, 0, ErrHTMLSendWorkV1
	}
	return parent, db, nil
}
func (g *applicationHTMLSendCollectionGrantV1) validBudgetV1(ctx context.Context, a *WorkAdmissionV1, b ApplicationBudgetV1) bool {
	if g == nil || g.self != g || g.owner == nil || g.owner.self != g.owner || g.session == nil || g.owner.session == nil || g.owner.session.state != g.session || g.admission == nil || g.admission.fence != g.session.fence || g.work != a || g.session.factory == nil || g.session.factory.work != a || ctx == nil || g.callbackDone == nil || ctx.Done() != g.callbackDone || ctx.Value(applicationSessionCallbackKeyV1{}) != g.session {
		return false
	}
	select {
	case <-g.callbackDone:
		return false
	default:
	}
	h := g.bodyHeader
	if h == nil || h.self != h || h.reader != g.actor || h.reader == nil || h.reader.self != h.reader || h.reader.bodyHeader != h || h.session != g.owner.session || h.admission != g.admission || h.fence != g.session.fence || h.loanClose == nil || h.closed.Load() {
		return false
	}
	wantParent, wantDB, deriveErr := htmlSendCollectionResourcesV1(g.header, g.purpose)
	if deriveErr != nil || wantParent != g.parentBytes || wantDB != g.dbBytes {
		return false
	}
	expected := ApplicationBudgetV1{Phase: "locked-html-send-collections", OrgID: g.org, DocumentID: g.document, WorkingBytes: g.parentBytes, DBStagingBytes: g.dbBytes, htmlSendCollectionGrant: g}
	return b == expected && g.org != uuid.Nil && g.document != uuid.Nil && g.session.org == g.org && g.session.document == g.document && g.header.OrgID == g.org && g.header.DocumentID == g.owner.logicalDocumentV1() && g.parentBytes > 0 && g.dbBytes > 0
}

func (w *ApplicationHTMLSendWorkV1) holdCollectionV1(ctx context.Context, h generated.GetHTMLSendCollectionReadHeaderV1Row, purpose htmlSendCollectionPurposeV1) (func(), error) {
	parent, db, err := htmlSendCollectionResourcesV1(h, purpose)
	if err != nil {
		return nil, err
	}
	s := w.session.state
	p := s.factory
	if p == nil {
		return nil, ErrHTMLSendWorkV1
	}
	p.mu.Lock()
	s.mu.Lock()
	a := s.admission
	if p.closing || p.work == nil || p.htmlAdmissions == nil || s.observer || s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) || a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone || !s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	g := &applicationHTMLSendCollectionGrantV1{owner: w, session: s, admission: a, work: p.work, bodyHeader: w.actor.bodyHeader, actor: w.actor, callbackDone: ctx.Done(), org: s.org, document: s.document, header: h, purpose: purpose, parentBytes: parent, dbBytes: db}
	g.self = g
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	close, err := a.admit(ctx, ApplicationBudgetV1{Phase: "locked-html-send-collections", OrgID: s.org, DocumentID: s.document, WorkingBytes: parent, DBStagingBytes: db, htmlSendCollectionGrant: g})
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	return close, nil
}

func htmlSendCloneDocumentV1(in *generated.Document) *generated.Document {
	if in == nil {
		return nil
	}
	out := *in
	out.Name = strings.Clone(in.Name)
	out.Status = strings.Clone(in.Status)
	out.RoutingMode = strings.Clone(in.RoutingMode)
	out.SourceKind = strings.Clone(in.SourceKind)
	out.BlocksJson = bytes.Clone(in.BlocksJson)
	out.VariablesJson = bytes.Clone(in.VariablesJson)
	out.RenderedPdfKey.String = strings.Clone(in.RenderedPdfKey.String)
	out.RenderedPdfSha = bytes.Clone(in.RenderedPdfSha)
	out.PdfStorageKey.String = strings.Clone(in.PdfStorageKey.String)
	out.PdfSha256 = bytes.Clone(in.PdfSha256)
	out.FinalPdfKey.String = strings.Clone(in.FinalPdfKey.String)
	out.FinalPdfSha = bytes.Clone(in.FinalPdfSha)
	out.AuditCertKey.String = strings.Clone(in.AuditCertKey.String)
	out.Metadata = bytes.Clone(in.Metadata)
	out.MetadataRedactionReport = bytes.Clone(in.MetadataRedactionReport)
	out.RoutingTier = strings.Clone(in.RoutingTier)
	out.BilingualTargetLang = strings.Clone(in.BilingualTargetLang)
	out.LawfulBasis = strings.Clone(in.LawfulBasis)
	out.DefaultLocale = strings.Clone(in.DefaultLocale)
	out.AuditPayloadKey.String = strings.Clone(in.AuditPayloadKey.String)
	out.AuditPayloadSha256 = bytes.Clone(in.AuditPayloadSha256)
	out.AuditSignatureKey.String = strings.Clone(in.AuditSignatureKey.String)
	out.AuditSignatureSha256 = bytes.Clone(in.AuditSignatureSha256)
	out.PdfStorageVersionID.String = strings.Clone(in.PdfStorageVersionID.String)
	out.RenderedPdfVersionID.String = strings.Clone(in.RenderedPdfVersionID.String)
	out.FinalPdfVersionID.String = strings.Clone(in.FinalPdfVersionID.String)
	out.AuditCertSha256 = bytes.Clone(in.AuditCertSha256)
	out.AuditCertVersionID.String = strings.Clone(in.AuditCertVersionID.String)
	out.AuditPayloadVersionID.String = strings.Clone(in.AuditPayloadVersionID.String)
	out.AuditSignatureVersionID.String = strings.Clone(in.AuditSignatureVersionID.String)
	out.Article13NoticeSchema = strings.Clone(in.Article13NoticeSchema)
	out.HtmlSourceJson = bytes.Clone(in.HtmlSourceJson)
	out.HtmlReviewedPdfSha256 = bytes.Clone(in.HtmlReviewedPdfSha256)
	out.HtmlCurrentSourceJson = bytes.Clone(in.HtmlCurrentSourceJson)
	out.HtmlEffectiveSourceCommitment.String = strings.Clone(in.HtmlEffectiveSourceCommitment.String)
	out.FitsIndexStorageKey.String = strings.Clone(in.FitsIndexStorageKey.String)
	out.FitsIndexVersionID.String = strings.Clone(in.FitsIndexVersionID.String)
	out.FitsIndexSha256 = bytes.Clone(in.FitsIndexSha256)
	out.ParticipantReportSchema = strings.Clone(in.ParticipantReportSchema)
	out.SigningAdmissionPolicy = strings.Clone(in.SigningAdmissionPolicy)
	return &out
}

// Original confirmation/controller read, under its existing cheap M93 scoped
// header and SAME retained parent/confirmation/org locks. No guessed limits.
func (w *ApplicationHTMLSendWorkV1) ReadConfirmationV1(ctx context.Context) (*generated.DocumentLawfulBasisConfirmation, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.state == nil {
		return nil, ErrHTMLSendWorkV1
	}
	s := w.session.state
	h, err := w.queries.GetSignerControllerReadHeaderV1(ctx, generated.GetSignerControllerReadHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != w.logicalDocumentV1() || h.OrgID != s.org {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, h.RawTextBytes, 0)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.ReadSignerLawfulBasisConfirmationV1(ctx, generated.ReadSignerLawfulBasisConfirmationV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org, ExpectedRawTextBytes: h.ConfirmationRawTextBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != w.logicalDocumentV1() || row.OrgID != s.org || int64(len(row.LawfulBasis)+len(row.Via)+len(row.ControllerName)+len(row.ControllerContact)) != h.ConfirmationRawTextBytes {
		return nil, ErrHTMLSendWorkV1
	}
	return row, nil
}
func (w *ApplicationHTMLSendWorkV1) AcquireBrandingReadV1(ctx context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.state == nil {
		return ErrHTMLSendWorkV1
	}
	s := w.session.state
	h, err := w.queries.GetHTMLSendBrandingInputHeaderV1(ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org})
	if err != nil {
		return err
	}
	if h == nil || h.DocumentID != w.logicalDocumentV1() || h.OrgID != s.org {
		return ErrHTMLSendWorkV1
	}
	raw, err := htmlAuthoringSumV1(h.OrgBrandingRawBytes, h.DocumentBrandingRawBytes)
	if err != nil {
		return ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	return nil
}

// All string backing is immutable; detach mutable byte/numeric backing and
// each row header before exposing the original generated models to Send.
func htmlSendCloneRecipientV1(in *generated.Recipient) *generated.Recipient {
	if in == nil {
		return nil
	}
	out := *in
	out.MagicTokenHash = bytes.Clone(in.MagicTokenHash)
	return &out
}
func htmlSendCloneFieldV1(in *generated.DocumentField) *generated.DocumentField {
	if in == nil {
		return nil
	}
	out := *in
	out.OptionsJson = bytes.Clone(in.OptionsJson)
	if in.XPct.Int != nil {
		out.XPct.Int = new(big.Int).Set(in.XPct.Int)
	}
	if in.YPct.Int != nil {
		out.YPct.Int = new(big.Int).Set(in.YPct.Int)
	}
	if in.WPct.Int != nil {
		out.WPct.Int = new(big.Int).Set(in.WPct.Int)
	}
	if in.HPct.Int != nil {
		out.HPct.Int = new(big.Int).Set(in.HPct.Int)
	}
	return &out
}
