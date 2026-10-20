// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var errApplicationBoundRequestV1 = errors.New("sign: immutable request journal unavailable")
var errApplicationBoundRequestUnknownV1 = errors.New("sign: immutable request outcome unresolved")

const applicationBoundRequestOwnersV1 = 128
const applicationBoundRequestCleanupV1 = 5 * time.Second

// This private component owns only atomic85/87/90/88 request data. It performs
// no rendering, storage/provider I/O, selection, status/audit mutation, READY
// activation or Sign dispatch. A committed row is identity, not permission.
// The future driver must enforce actual resource/controller readiness,
// producer/source proof and full current publication policy at every dispatch.
//
// Keep ONE instance for the Engine/application lifetime. First issuance after
// process restart additionally requires a genuine startup writer-generation
// fence. An absent first-sidecar cannot reconstruct lost original SQL identity;
// this component never converts absent/TTL/rowlock/XID metadata to replacement.
type applicationRequestJournalV1 struct {
	engine  *Engine
	factory *pdfadmission.ApplicationSessionFactoryV1
	mu      sync.Mutex
	owners  map[applicationRequestKeyV1]*applicationRequestOperationV1
	closing bool
}
type applicationRequestKeyV1 struct{ org, document, recipient uuid.UUID }

// The owner, not an HTTP UUID, carries in-process unknown-outcome provenance.
// Its original session, payload, candidate and consumer loans remain reachable
// until physical retirement AND exact immutable row reconciliation.
type applicationRequestOperationV1 struct {
	mu                                       sync.Mutex
	journal                                  *applicationRequestJournalV1
	key                                      applicationRequestKeyV1
	session                                  *pdfadmission.ApplicationSessionV1
	admission                                *pdfadmission.ApplicationAdmissionV1
	cleanup                                  applicationRequestCleanupLifetimeV1
	candidate                                *pdfadmission.ApplicationCandidateV1
	payload                                  *durableRequestPayloadV1
	authority, span                          []byte
	recovery                                 *applicationRequestOperationV1
	releases                                 []func()
	metadata                                 *generated.ReserveBoundSignatureFitRequestV1Row
	context                                  *RecipientContext
	intent                                   *fittedSigningIntentV1
	policy                                   *applicationFittedPolicyQueriesV1
	attempted, acknowledged, unknown, closed bool
	exactRowReconciled                       bool
	running                                  bool
}

// This private seam exists only for owner-cleanup bookkeeping. Production
// prepareV1 installs the actual opaque owned session and its actual registry;
// no constructor or exported API accepts caller booleans or custom callbacks.
// Native spies may prove transitions only, never physical/runtime authority.
type applicationRequestCleanupLifetimeV1 interface {
	retireV1(context.Context) error
	retiredV1() bool
	closeRegistryV1(context.Context) error
}
type applicationOwnedRequestCleanupV1 struct {
	session  *pdfadmission.ApplicationSessionV1
	registry *pdfadmission.ApplicationAdmissionV1
}

func (o *applicationOwnedRequestCleanupV1) retireV1(ctx context.Context) error {
	if o == nil || o.session == nil || o.registry == nil {
		return errApplicationBoundRequestUnknownV1
	}
	if err := o.session.CloseV1(ctx); err != nil || !o.session.RetiredV1() {
		return errApplicationBoundRequestUnknownV1
	}
	return nil
}
func (o *applicationOwnedRequestCleanupV1) retiredV1() bool {
	return o != nil && o.session != nil && o.registry != nil && o.session.RetiredV1()
}
func (o *applicationOwnedRequestCleanupV1) closeRegistryV1(ctx context.Context) error {
	if o == nil || o.session == nil || o.registry == nil {
		return errApplicationBoundRequestUnknownV1
	}
	return o.registry.CloseV1(ctx)
}

func newApplicationRequestJournalV1(e *Engine) (*applicationRequestJournalV1, error) {
	if e == nil || e.Pool == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, errApplicationBoundRequestV1
	}
	// The factory already owns this process's observers, session registry and
	// shared coordinator. Never create a second per-engine factory or budget.
	factory := e.WorkRuntime.SessionsV1()
	if factory == nil {
		return nil, errApplicationBoundRequestV1
	}
	return &applicationRequestJournalV1{engine: e, factory: factory, owners: make(map[applicationRequestKeyV1]*applicationRequestOperationV1)}, nil
}
func applicationBoundRequestErrorV1(ctx context.Context, cause error) error {
	phases := []error{errApplicationBoundRequestV1}
	if errors.Is(cause, errApplicationBoundRequestUnknownV1) || errors.Is(cause, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(cause, pdfadmission.ErrApplicationSessionCommitUnknownV1) {
		phases = append(phases, errApplicationBoundRequestUnknownV1)
	}
	// No SQL/config/internal transport details escape this fixed facade.
	for _, known := range []error{ErrSigningAdmissionUnavailableV1, ErrSignaturePreparationChanged, ErrInvalidNoticeEvidence, ErrMagicLinkExpired, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(cause, known) {
			phases = append(phases, known)
		}
	}
	if ctx != nil && ctx.Err() != nil {
		return fittedRequestCancellationV1(ctx, phases...)
	}
	return &fittedRequestContextErrorV1{causes: phases}
}
func applicationBoundRequestContextV1(ctx context.Context) error {
	if err := requestPayloadCheckContextV1(ctx); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return errApplicationBoundRequestV1
	}
	return nil
}
func (j *applicationRequestJournalV1) privateKeyV1(ctx context.Context, rc *RecipientContext) (applicationRequestKeyV1, error) {
	if err := applicationBoundRequestContextV1(ctx); err != nil {
		return applicationRequestKeyV1{}, err
	}
	if j == nil || j.engine == nil || j.factory == nil || rc == nil || rc.presentedCredential == nil || rc.presentedCredential.issuer != j.engine {
		return applicationRequestKeyV1{}, errApplicationBoundRequestV1
	}
	p := rc.presentedCredential
	if p.orgID == uuid.Nil || p.documentID == uuid.Nil || p.recipientID == uuid.Nil {
		return applicationRequestKeyV1{}, errApplicationBoundRequestV1
	}
	return applicationRequestKeyV1{p.orgID, p.documentID, p.recipientID}, nil
}
func (j *applicationRequestJournalV1) claimV1(key applicationRequestKeyV1) (*applicationRequestOperationV1, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closing || len(j.owners) >= applicationBoundRequestOwnersV1 {
		return nil, errApplicationBoundRequestV1
	}
	if old := j.owners[key]; old != nil {
		return nil, errApplicationBoundRequestUnknownV1
	}
	op := &applicationRequestOperationV1{journal: j, key: key, running: true}
	j.owners[key] = op
	return op, nil
}
func (j *applicationRequestJournalV1) forgetV1(op *applicationRequestOperationV1) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.owners[op.key] == op {
		delete(j.owners, op.key)
	}
}

// Validate the exact source-derived header SUM before raw text/body work.
func applicationRequestHeaderV1(h *generated.GetSignatureFitRequestScopeHeaderV1Row, key applicationRequestKeyV1) (int64, error) {
	if h == nil || h.OrgID != key.org || h.DocumentID != key.document || h.AdmissionID == uuid.Nil || !finiteFittedTimeV1(h.CeremonyEpoch) || len(h.StaticBasisSha256) != sha256.Size {
		return 0, errApplicationBoundRequestV1
	}
	n := int64(8192)
	for _, v := range []int64{h.DocumentNameBytes, h.LawfulBasisBytes, h.ControllerNameBytes, h.ControllerContactBytes, h.ConfirmationBasisBytes, h.ConfirmationViaBytes, h.ControllerOrgNameBytes} {
		var err error
		n, err = requestPayloadAddV1(n, v)
		if err != nil {
			return 0, err
		}
	}
	if h.DocumentNameBytes < 1 || h.DocumentNameBytes > requestDocumentNameMaxBytesV1 || n != h.CurrentContextProcessingBytes {
		return 0, errApplicationBoundRequestV1
	}
	return n, nil
}

// Original issuance keeps its existing HTML/master/variables checks. Price the
// exact retained original projection before any such decoding, independently of
// the fresh protected SQL projection. These byte lengths are work cost only;
// mutable exported source data never authorizes scope, capture or signing.
func applicationOriginalPolicyBytesV1(rc *RecipientContext) (int64, error) {
	if rc == nil || rc.Document == nil {
		return 0, errApplicationBoundRequestV1
	}
	d := rc.Document
	n := int64(4096)
	for _, v := range []int64{
		int64(len(d.HtmlSourceJson)), int64(len(d.HtmlCurrentSourceJson)), int64(len(d.VariablesJson)),
		int64(len(d.Name)), int64(len(d.Status)), int64(len(d.SourceKind)), int64(len(d.RoutingTier)), int64(len(d.RoutingMode)), int64(len(d.LawfulBasis)), int64(len(d.SigningAdmissionPolicy)), int64(len(d.ParticipantReportSchema)), int64(len(d.DefaultLocale)), int64(len(d.Article13NoticeSchema)),
		int64(len(d.PdfStorageKey.String)), int64(len(d.PdfStorageVersionID.String)), int64(len(d.HtmlEffectiveSourceCommitment.String)),
	} {
		var err error
		n, err = requestPayloadAddV1(n, v)
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

func applicationRequestMetadataV1(m *generated.ReserveBoundSignatureFitRequestV1Row, s pdfadmission.ApplicationScopeV1, p *durableRequestPayloadV1, authority []byte) error {
	if m == nil || p == nil || m.PreparationID == uuid.Nil || m.OrgID != s.OrgID || m.DocumentID != s.DocumentID || m.RecipientID != p.header.RecipientID || m.AdmissionID != s.AdmissionID ||
		!finiteFittedTimeV1(m.CeremonyEpoch) || m.CeremonyEpoch.Time.UTC().Format(time.RFC3339Nano) != p.header.CeremonyEpoch ||
		!bytes.Equal(m.StaticBasisSha256, mustApplicationRequestDigestV1(s.StaticBasisSHA256)) || m.OriginalRequestBytes != p.header.OriginBytes || m.AcceptedIntentBytes != p.header.IntentBytes ||
		!bytes.Equal(m.OriginalRequestSha256, p.header.OriginSHA256[:]) || !bytes.Equal(m.AcceptedIntentSha256, p.header.IntentSHA256[:]) || !bytes.Equal(m.AcceptedIntentSemanticSha256, p.header.SemanticIntentSHA256[:]) ||
		len(m.BindingSha256) != sha256.Size || !finiteFittedTimeV1(m.CapturedAt) || !m.CapturedTransactionID.Valid || m.CapturedTransactionID.Uint64 == 0 {
		return errApplicationBoundRequestV1
	}
	ah := sha256.Sum256(authority)
	if !bytes.Equal(m.AuthoritySha256, ah[:]) {
		return errApplicationBoundRequestV1
	}
	if m.CreatorBackendPid <= 0 || !finiteFittedTimeV1(m.CreatorBackendStart) || m.CreatorDatabaseOid < 1 || m.CreatorDatabaseOid > 4294967295 || m.CreatorUserOid < 1 || m.CreatorUserOid > 4294967295 || len(m.CreatorServerAddress) > 128 || m.CreatorServerPort < 0 || m.CreatorServerPort > 65535 || !finiteFittedTimeV1(m.CreatorPostmasterStart) {
		return errApplicationBoundRequestV1
	}
	return nil
}
func mustApplicationRequestDigestV1(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != sha256.Size {
		return nil
	}
	return raw
}
func applicationRequestPayloadHeaderV1(m *generated.ReserveBoundSignatureFitRequestV1Row) (requestPayloadHeaderV1, error) {
	if m == nil || !finiteFittedTimeV1(m.CeremonyEpoch) || m.OriginalRequestBytes < 1 || m.OriginalRequestBytes > requestOriginMaxBytesV1 || m.AcceptedIntentBytes < 1 || m.AcceptedIntentBytes > acceptedIntentMaxBytesV1 ||
		len(m.OriginalRequestSha256) != sha256.Size || len(m.AcceptedIntentSha256) != sha256.Size || len(m.AcceptedIntentSemanticSha256) != sha256.Size {
		return requestPayloadHeaderV1{}, errApplicationBoundRequestV1
	}
	h := requestPayloadHeaderV1{OrgID: m.OrgID, DocumentID: m.DocumentID, RecipientID: m.RecipientID, CeremonyEpoch: m.CeremonyEpoch.Time.UTC().Format(time.RFC3339Nano), OriginBytes: m.OriginalRequestBytes, IntentBytes: m.AcceptedIntentBytes}
	copy(h.OriginSHA256[:], m.OriginalRequestSha256)
	copy(h.IntentSHA256[:], m.AcceptedIntentSha256)
	copy(h.SemanticIntentSHA256[:], m.AcceptedIntentSemanticSha256)
	if h.IntentSHA256 != h.SemanticIntentSHA256 {
		return requestPayloadHeaderV1{}, errApplicationBoundRequestV1
	}
	return h, nil
}

// Cleanup timeout is never retirement or disposition proof.
func (op *applicationRequestOperationV1) retireV1(ctx context.Context) error {
	if op == nil {
		return errApplicationBoundRequestV1
	}
	if op.cleanup != nil {
		return op.cleanup.retireV1(ctx)
	}
	if op.session == nil {
		return nil
	}
	if err := op.session.CloseV1(ctx); err != nil || !op.session.RetiredV1() {
		return errApplicationBoundRequestUnknownV1
	}
	return nil
}
func (op *applicationRequestOperationV1) closeConsumersV1() {
	if op.candidate != nil {
		op.candidate.Close()
		op.candidate = nil
	}
	if op.payload != nil {
		op.payload.releaseV1()
		clear(op.payload.origin)
		clear(op.payload.intent)
		op.payload = nil
	}
	clear(op.authority)
	clear(op.span)
	op.authority = nil
	op.span = nil
	op.policy = nil
	for _, closeConsumer := range op.releases {
		closeConsumer()
	}
	op.releases = nil
}
func (op *applicationRequestOperationV1) finishWorkV1(ctx context.Context) error {
	if err := op.retireV1(ctx); err != nil {
		return err
	}
	op.closeConsumersV1()
	if op.cleanup != nil {
		if err := op.cleanup.closeRegistryV1(ctx); err != nil {
			return err
		}
	} else if op.admission != nil {
		if err := op.admission.CloseV1(ctx); err != nil {
			return err
		}
	}
	op.closed = true
	return nil
}
func (op *applicationRequestOperationV1) finishV1(ctx context.Context) error {
	if err := op.finishWorkV1(ctx); err != nil {
		return err
	}
	op.journal.forgetV1(op)
	return nil
}
func (op *applicationRequestOperationV1) CloseV1(ctx context.Context) error {
	if op == nil || op.journal == nil {
		return errApplicationBoundRequestV1
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.running {
		return errApplicationBoundRequestUnknownV1
	}
	if child := op.recovery; child != nil {
		if err := child.CloseV1(ctx); err != nil {
			return errApplicationBoundRequestUnknownV1
		}
		op.recovery = nil
	}
	if op.closed {
		op.journal.forgetV1(op)
		return nil
	}
	if op.exactRowReconciled {
		// Exact row reconciliation already completed. Closing its retained child
		// above expresses disposal, not another read/signing permission. Retry only
		// this original registry closure; a deadline failure retains this owner.
		if err := op.finishV1(ctx); err != nil {
			op.unknown = true
			return errApplicationBoundRequestUnknownV1
		}
		op.unknown = false
		return nil
	}
	if op.unknown {
		if op.attempted {
			return errApplicationBoundRequestUnknownV1
		}
		// Read/failed-before-COMMIT ownership can finish ONLY after the actual
		// original physical retirement plus consumer/registry conjunction.
		if err := op.finishV1(ctx); err != nil {
			return errApplicationBoundRequestUnknownV1
		}
		op.unknown = false
		return nil
	}
	return op.finishV1(ctx)
}
func (op *applicationRequestOperationV1) dataV1() (*generated.ReserveBoundSignatureFitRequestV1Row, *RecipientContext, *fittedSigningIntentV1, error) {
	if op == nil {
		return nil, nil, nil, errApplicationBoundRequestV1
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.running || op.closed || op.unknown || !op.acknowledged || op.metadata == nil || op.session == nil || !op.session.RetiredV1() {
		return nil, nil, nil, errApplicationBoundRequestUnknownV1
	}
	// Copy bounded scalar metadata/digest arrays; no caller can rewrite the
	// retained immutable header used by recovery or fixed creator observation.
	metadata := *op.metadata
	metadata.StaticBasisSha256 = bytes.Clone(op.metadata.StaticBasisSha256)
	metadata.AuthoritySha256 = bytes.Clone(op.metadata.AuthoritySha256)
	metadata.OriginalRequestSha256 = bytes.Clone(op.metadata.OriginalRequestSha256)
	metadata.AcceptedIntentSha256 = bytes.Clone(op.metadata.AcceptedIntentSha256)
	metadata.AcceptedIntentSemanticSha256 = bytes.Clone(op.metadata.AcceptedIntentSemanticSha256)
	metadata.BindingSha256 = bytes.Clone(op.metadata.BindingSha256)
	return &metadata, op.context, op.intent, nil
}
func (j *applicationRequestJournalV1) prepareV1(ctx context.Context, op *applicationRequestOperationV1, rc *RecipientContext, in SignInput, kind pdfadmission.ApplicationRequestJournalKindV1) (*generated.Queries, pdfadmission.ApplicationScopeV1, error) {
	h, err := j.factory.OpenV1(ctx, op.key.org, op.key.document)
	op.session = h
	if err != nil {
		return nil, pdfadmission.ApplicationScopeV1{}, err
	}
	a, err := h.NewAdmissionV1(ctx)
	op.admission = a
	if err != nil {
		return nil, pdfadmission.ApplicationScopeV1{}, err
	}
	if a == nil {
		return nil, pdfadmission.ApplicationScopeV1{}, errApplicationBoundRequestV1
	}
	op.cleanup = &applicationOwnedRequestCleanupV1{session: h, registry: a}
	closeHeader, err := h.AcquireRequestHeaderV1(ctx, op.key.org, op.key.document, op.key.recipient)
	if err != nil {
		return nil, pdfadmission.ApplicationScopeV1{}, err
	}
	op.releases = append(op.releases, closeHeader)
	var scope pdfadmission.ApplicationScopeV1
	var queries *generated.Queries
	err = h.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		queries = generated.New(db)
		header, err := queries.GetSignatureFitRequestScopeHeaderV1(call, generated.GetSignatureFitRequestScopeHeaderV1Params{DocumentID: op.key.document, OrgID: op.key.org})
		if err != nil {
			return err
		}
		currentBytes, err := applicationRequestHeaderV1(header, op.key)
		if err != nil {
			return err
		}
		// The exact active candidate is already locked. Owner is scoped server data,
		// never supplied signer authorization or a claimed original request.
		owner, err := queries.GetPDFSigningAdmissionCandidateMetadataV1(call, generated.GetPDFSigningAdmissionCandidateMetadataV1Params{DocumentID: op.key.document, OrgID: op.key.org, CeremonyEpoch: header.CeremonyEpoch, StaticBasisSha256: header.StaticBasisSha256})
		if err != nil || owner == nil || owner.ID != header.AdmissionID || owner.OrgID != op.key.org || owner.DocumentID != op.key.document || owner.OwnerID == uuid.Nil || owner.StaleAt.Valid || !finiteFittedTimeV1(owner.CeremonyEpoch) || !owner.CeremonyEpoch.Time.Equal(header.CeremonyEpoch.Time) || !bytes.Equal(owner.StaticBasisSha256, header.StaticBasisSha256) {
			return errApplicationBoundRequestV1
		}
		scope = pdfadmission.ApplicationScopeV1{OrgID: op.key.org, DocumentID: op.key.document, AdmissionID: header.AdmissionID, OwnerID: owner.OwnerID, StaticBasisSHA256: hex.EncodeToString(header.StaticBasisSha256)}
		policyHeader, err := queries.GetSignatureFitHTMLPolicySizeHeaderV1(call, generated.GetSignatureFitHTMLPolicySizeHeaderV1Params{DocumentID: op.key.document, OrgID: op.key.org, AdmissionID: pgtype.UUID{Bytes: scope.AdmissionID, Valid: true}})
		if err != nil {
			return err
		}
		policyBytes, err := applicationRequestPolicyHeaderV1(policyHeader, op.key, scope.AdmissionID)
		if err != nil {
			return err
		}
		originalPolicyBytes, err := applicationOriginalPolicyBytesV1(rc)
		if err != nil {
			return err
		}
		policyBytes, err = requestPayloadAddV1(policyBytes, originalPolicyBytes)
		if err != nil {
			return err
		}
		original, err := requestPayloadBudgetForV1(rc.presentedCredential, requestOriginMaxBytesV1, acceptedIntentMaxBytesV1)
		if err != nil {
			return err
		}
		// Maxima reserve production BEFORE authority/span/intent clones. Current and
		// original raw lengths remain separately source-derived, with no text cap.
		closeJournal, err := h.AcquireRequestJournalV1(call, scope, op.key.recipient, pdfadmission.ApplicationRequestJournalCostV1{Kind: kind, OriginBytes: requestOriginMaxBytesV1, IntentBytes: acceptedIntentMaxBytesV1, AuthorityBytes: manualfit.MaxAuthorityBytesV1, SpanBytes: manualfit.MaxSpanBytesV1, CurrentContextBytes: currentBytes, OriginalRawContextBytes: original.RawContextBytes, PolicyBytes: policyBytes})
		if err != nil {
			return err
		}
		op.releases = append(op.releases, closeJournal)
		op.policy = &applicationFittedPolicyQueriesV1{queries: queries, key: op.key, admissionID: scope.AdmissionID, header: *policyHeader, contextHeader: *header}
		intent, err := j.engine.issueFittedSigningIntentV1(call, rc, in)
		if err != nil {
			return err
		}
		op.context, op.intent = rc, intent
		codec, err := j.engine.newApplicationRequestPayloadAdmissionV1(call, rc, intent, h, scope)
		if err != nil {
			return err
		}
		payload, err := j.engine.captureDurableRequestPayloadV1(call, rc, intent, codec)
		if err != nil {
			return err
		}
		op.payload = payload
		candidate, err := a.LoadCurrentV1(call, scope)
		if err != nil {
			return err
		}
		op.candidate = candidate
		spanText, err := render.RenderSignatureSpan(intent.typedName, intent.font)
		if err != nil {
			return err
		}
		op.span = []byte(spanText)
		if int64(len(op.span)) > manualfit.MaxSpanBytesV1 || manualfit.ValidateArchivedSpanV1(op.span, intent.typedName, intent.font) != nil {
			return errApplicationBoundRequestV1
		}
		spanSHA, err := requestBodySHA256V1(call, op.span)
		if err != nil {
			return err
		}
		return candidate.WithBasisV1(call, func(b *pdfadmission.BasisV1) error {
			targets, err := b.SignatureTargets(op.key.recipient)
			if err != nil {
				return err
			}
			ai := manualfit.AuthorityInputV1{OrgID: op.key.org, DocumentID: op.key.document, RecipientID: op.key.recipient, CeremonyEpoch: header.CeremonyEpoch.Time.UTC(), Source: b.Source(), TypedName: intent.typedName, Font: intent.font, SpanSHA256: hex.EncodeToString(spanSHA[:]), Targets: targets}
			for _, target := range targets {
				ai.ExpectedTargetIDs = append(ai.ExpectedTargetIDs, target.ID)
			}
			authority, err := manualfit.BuildAuthorityV1(ai, b.Geometry())
			if err != nil {
				return err
			}
			op.authority = authority.CanonicalJSON()
			if len(op.authority) < 1 || int64(len(op.authority)) > manualfit.MaxAuthorityBytesV1 {
				return errApplicationBoundRequestV1
			}
			return requestPayloadCheckContextV1(call)
		})
	})
	return queries, scope, err
}
func (j *applicationRequestJournalV1) lockedPolicyV1(ctx context.Context, q *generated.Queries, op *applicationRequestOperationV1) error {
	if q == nil || op.context == nil || op.intent == nil || op.policy == nil || op.policy.queries != q {
		return errApplicationBoundRequestV1
	}
	doc, err := op.policy.documentV1(ctx)
	if err != nil {
		return err
	}
	recipient, err := op.policy.recipientV1(ctx)
	if err != nil {
		return err
	}
	return j.engine.validateFittedSigningPolicyQueriesV1(ctx, op.context, op.intent.inputV1(SignInput{}), doc, recipient, op.policy)
}

func (j *applicationRequestJournalV1) CaptureV1(ctx context.Context, rc *RecipientContext, in SignInput) (out *applicationRequestOperationV1, retErr error) {
	key, err := j.privateKeyV1(ctx, rc)
	if err != nil {
		return nil, applicationBoundRequestErrorV1(ctx, err)
	}
	op, err := j.claimV1(key)
	if err != nil {
		return nil, applicationBoundRequestErrorV1(ctx, err)
	}
	out = op
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), applicationBoundRequestCleanupV1)
		defer cancel()
		op.mu.Lock()
		defer op.mu.Unlock()
		op.running = false
		if ctx.Err() != nil {
			retErr = applicationBoundRequestErrorV1(ctx, retErr)
		}
		if !op.attempted && op.session != nil {
			_ = op.session.RollbackV1(cleanup)
		}
		if err := op.retireV1(cleanup); err != nil {
			op.unknown = true
			retErr = applicationBoundRequestErrorV1(ctx, err)
		}
		if op.session != nil && op.session.CommitUnknownV1() {
			op.unknown = true
		}
		if retErr != nil && !op.unknown {
			if err := op.finishV1(cleanup); err != nil {
				op.unknown = true
				retErr = applicationBoundRequestErrorV1(ctx, err)
			}
		}
		if retErr != nil {
			retErr = applicationBoundRequestErrorV1(ctx, retErr)
		}
	}()
	q, scope, err := j.prepareV1(ctx, op, rc, in, pdfadmission.ApplicationRequestJournalCaptureV1)
	if err != nil {
		return out, err
	}
	err = op.session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		if err := j.lockedPolicyV1(call, q, op); err != nil {
			return err
		}
		owner := uuid.New() // lease nonce only; SQL issues the stable preparation UUID.
		leaseEnd := j.engine.now().Add(time.Minute)
		p := op.intent.credential
		if p.recipientExpiry.Time.Before(leaseEnd) {
			leaseEnd = p.recipientExpiry.Time
		}
		if p.documentExpiry.Valid && p.documentExpiry.Time.Before(leaseEnd) {
			leaseEnd = p.documentExpiry.Time
		}
		metadata, err := q.ReserveBoundSignatureFitRequestV1(call, generated.ReserveBoundSignatureFitRequestV1Params{OrgID: key.org, DocumentID: key.document, RecipientID: key.recipient, AdmissionID: scope.AdmissionID, ReviewedBasisSha256: mustApplicationRequestDigestV1(scope.StaticBasisSHA256), LeaseOwnerID: owner, LeaseUntil: pgtype.Timestamptz{Time: leaseEnd.UTC(), Valid: true}, OriginalRequestPayload: op.payload.origin, AcceptedIntentPayload: op.payload.intent, AuthorityPayload: op.authority, SpanPayload: op.span})
		if err != nil {
			return err
		}
		if err = applicationRequestMetadataV1(metadata, scope, op.payload, op.authority); err != nil {
			return err
		}
		op.metadata = metadata
		// Recheck controller/roles/fields and original/current deadlines after every
		// reserve/hash/trigger wait, immediately before the owned COMMIT attempt.
		return j.lockedPolicyV1(call, q, op)
	})
	if err != nil {
		return out, err
	}
	if err = requestPayloadCheckContextV1(ctx); err != nil {
		return out, err
	}
	err = op.session.CommitV1(ctx)
	// Read the SAME private owned session only AFTER its Commit method returned.
	// A pre-dispatch context/state refusal is known no-COMMIT; true attempts stay
	// conservative even if the result or its acknowledgement is uncertain.
	op.attempted = !op.session.CommitDispatchObservationV1().NeverDispatchedV1()
	if err != nil {
		if op.attempted {
			op.unknown = true
			return out, errApplicationBoundRequestUnknownV1
		}
		return out, err
	}
	if !op.attempted {
		op.unknown = true
		return out, errApplicationBoundRequestUnknownV1
	}
	op.acknowledged = true
	return out, nil
}

// ExistingReadV1 never creates/replaces an operation. Absence stays a refusal.
func (j *applicationRequestJournalV1) ExistingReadV1(ctx context.Context, rc *RecipientContext, in SignInput) (*applicationRequestOperationV1, error) {
	return j.existingReadV1(ctx, rc, in, nil)
}
func (j *applicationRequestJournalV1) existingReadV1(ctx context.Context, rc *RecipientContext, in SignInput, original *applicationRequestOperationV1) (out *applicationRequestOperationV1, retErr error) {
	key, err := j.privateKeyV1(ctx, rc)
	if err != nil {
		return nil, applicationBoundRequestErrorV1(ctx, err)
	}
	var op *applicationRequestOperationV1
	if original == nil {
		op, err = j.claimV1(key)
		if err != nil {
			return nil, applicationBoundRequestErrorV1(ctx, err)
		}
	} else {
		if original.journal != j || original.key != key || original.metadata == nil || original.session == nil || !original.session.RetiredV1() {
			return nil, errApplicationBoundRequestUnknownV1
		}
		op = &applicationRequestOperationV1{journal: j, key: key, running: true}
		original.recovery = op // Retain new read ownership before its first dispatch.
	}
	out = op
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), applicationBoundRequestCleanupV1)
		defer cancel()
		op.mu.Lock()
		defer op.mu.Unlock()
		op.running = false
		if ctx.Err() != nil {
			retErr = applicationBoundRequestErrorV1(ctx, retErr)
		}
		if op.session != nil {
			_ = op.session.RollbackV1(cleanup)
		}
		if err := op.retireV1(cleanup); err != nil {
			op.unknown = true
			retErr = applicationBoundRequestErrorV1(ctx, err)
		}
		if retErr != nil && !op.unknown {
			if err := op.finishV1(cleanup); err != nil {
				op.unknown = true
				retErr = applicationBoundRequestErrorV1(ctx, err)
			}
		}
		if retErr != nil {
			retErr = applicationBoundRequestErrorV1(ctx, retErr)
		}
	}()
	q, scope, err := j.prepareV1(ctx, op, rc, in, pdfadmission.ApplicationRequestJournalReadV1)
	if err != nil {
		return out, err
	}
	err = op.session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		ah, err := requestBodySHA256V1(call, op.authority)
		if err != nil {
			return err
		}
		var metadata *generated.ReserveBoundSignatureFitRequestV1Row
		if original != nil {
			m, readErr := q.GetSignatureFitRequestBindingMetadataV1(call, generated.GetSignatureFitRequestBindingMetadataV1Params{PreparationID: original.metadata.PreparationID, OrgID: key.org, DocumentID: key.document, RecipientID: key.recipient})
			if readErr != nil {
				return errApplicationBoundRequestUnknownV1
			}
			metadata = (*generated.ReserveBoundSignatureFitRequestV1Row)(m)
		} else {
			m, readErr := q.FindSignatureFitRequestBindingByIntentV1(call, generated.FindSignatureFitRequestBindingByIntentV1Params{OrgID: key.org, DocumentID: key.document, RecipientID: key.recipient, CeremonyEpoch: pgtype.Timestamptz{Time: op.intent.credential.noticeEpoch.Time, Valid: true}, AdmissionID: scope.AdmissionID, StaticBasisSha256: mustApplicationRequestDigestV1(scope.StaticBasisSHA256), AuthoritySha256: ah[:], AcceptedIntentSemanticSha256: op.payload.header.SemanticIntentSHA256[:]})
			if readErr != nil {
				return errApplicationBoundRequestUnknownV1
			}
			metadata = (*generated.ReserveBoundSignatureFitRequestV1Row)(m)
		}
		header, err := applicationRequestPayloadHeaderV1(metadata)
		if err != nil {
			return err
		}
		if metadata.OrgID != scope.OrgID || metadata.DocumentID != scope.DocumentID || metadata.RecipientID != key.recipient || metadata.AdmissionID != scope.AdmissionID || !bytes.Equal(metadata.StaticBasisSha256, mustApplicationRequestDigestV1(scope.StaticBasisSHA256)) || !bytes.Equal(metadata.AuthoritySha256, ah[:]) || header.SemanticIntentSHA256 != op.payload.header.SemanticIntentSHA256 || len(metadata.BindingSha256) != sha256.Size {
			return errApplicationBoundRequestV1
		}
		// Journal-production loan owns body bounds BEFORE BYTEA allocation/read.
		originBody, err := q.ReadSignatureFitOriginalRequestBodyV1(call, generated.ReadSignatureFitOriginalRequestBodyV1Params{PreparationID: metadata.PreparationID, OrgID: key.org, DocumentID: key.document, RecipientID: key.recipient, BindingSha256: metadata.BindingSha256, ExpectedSha256: metadata.OriginalRequestSha256, ExpectedBytes: metadata.OriginalRequestBytes})
		if err != nil {
			return err
		}
		defer clear(originBody)
		intentBody, err := q.ReadSignatureFitAcceptedIntentBodyV1(call, generated.ReadSignatureFitAcceptedIntentBodyV1Params{PreparationID: metadata.PreparationID, OrgID: key.org, DocumentID: key.document, RecipientID: key.recipient, BindingSha256: metadata.BindingSha256, ExpectedSha256: metadata.AcceptedIntentSha256, ExpectedBytes: metadata.AcceptedIntentBytes})
		if err != nil {
			return err
		}
		defer clear(intentBody)
		if original != nil && (original.payload == nil || !bytes.Equal(originBody, original.payload.origin) || !bytes.Equal(intentBody, original.payload.intent) || !bytes.Equal(original.metadata.BindingSha256, metadata.BindingSha256)) {
			return errApplicationBoundRequestV1
		}
		am, err := q.GetSignatureFitOriginalAuthorityMetadata(call, generated.GetSignatureFitOriginalAuthorityMetadataParams{PreparationID: metadata.PreparationID, OrgID: key.org, DocumentID: key.document})
		if err != nil || am == nil || am.PreparationID != metadata.PreparationID || am.OrgID != key.org || am.DocumentID != key.document || am.RecipientID != key.recipient || am.AuthorityBytes != int64(len(op.authority)) || !bytes.Equal(am.AuthoritySha256, metadata.AuthoritySha256) {
			return errApplicationBoundRequestV1
		}
		authorityBody, err := q.GetSignatureFitOriginalAuthorityBody(call, generated.GetSignatureFitOriginalAuthorityBodyParams{PreparationID: metadata.PreparationID, OrgID: key.org, DocumentID: key.document, ExpectedSha256: am.AuthoritySha256, ExpectedBytes: am.AuthorityBytes})
		if err != nil {
			return err
		}
		defer clear(authorityBody)
		if !bytes.Equal(authorityBody, op.authority) {
			return errApplicationBoundRequestV1
		}
		sm, err := q.GetSignatureFitOriginalPayloadMetadata(call, generated.GetSignatureFitOriginalPayloadMetadataParams{PreparationID: metadata.PreparationID, OrgID: key.org, DocumentID: key.document, Kind: "span", Page: 0})
		spanSHA, hashErr := requestBodySHA256V1(call, op.span)
		if err != nil || hashErr != nil || sm == nil || sm.PreparationID != metadata.PreparationID || sm.OrgID != key.org || sm.DocumentID != key.document || sm.Kind != "span" || sm.Page != 0 || sm.Bytes != int64(len(op.span)) || sm.Bytes > manualfit.MaxSpanBytesV1 || sm.ContentType != "text/html" || !bytes.Equal(sm.Sha256, spanSHA[:]) {
			return errApplicationBoundRequestV1
		}
		spanBody, err := q.GetSignatureFitOriginalPayloadBody(call, generated.GetSignatureFitOriginalPayloadBodyParams{PreparationID: metadata.PreparationID, OrgID: key.org, DocumentID: key.document, Kind: "span", Page: 0, ExpectedSha256: sm.Sha256, ExpectedBytes: sm.Bytes})
		if err != nil {
			return err
		}
		defer clear(spanBody)
		if !bytes.Equal(spanBody, op.span) {
			return errApplicationBoundRequestV1
		}
		codec, err := j.engine.newApplicationRequestPayloadAdmissionV1(call, rc, op.intent, op.session, scope)
		if err != nil {
			return err
		}
		rebound, err := j.engine.rebindDurableRequestPayloadV1(call, rc, op.intent, header, originBody, intentBody, codec)
		if err != nil {
			return err
		}
		oldPayload := op.payload
		op.payload = rebound.payload
		oldPayload.releaseV1()
		clear(oldPayload.origin)
		clear(oldPayload.intent)
		op.context, op.intent = rebound.context, rebound.intent
		if err = applicationRequestMetadataV1(metadata, scope, op.payload, op.authority); err != nil {
			return err
		}
		op.metadata = metadata
		return j.lockedPolicyV1(call, q, op)
	})
	if err != nil {
		return out, err
	}
	// No COMMIT/new stable UUID. This is immutable visible row data, never READY.
	if err = requestPayloadCheckContextV1(ctx); err != nil {
		return out, err
	}
	op.acknowledged = true
	return out, nil
}

// finishReconciledRequestV1 requires original.mu. It performs cleanup and one
// retained-child handoff only: no SQL read/reserve, new ID, credential issuance
// or dispatch. The child already owns the exact row/body proof and its grants.
func (j *applicationRequestJournalV1) finishReconciledRequestV1(ctx context.Context, original *applicationRequestOperationV1) (*applicationRequestOperationV1, error) {
	if err := applicationBoundRequestContextV1(ctx); err != nil {
		return nil, err
	}
	if original == nil || original.journal != j || !original.exactRowReconciled || original.session == nil || original.admission == nil || original.cleanup == nil || original.metadata == nil {
		return nil, errApplicationBoundRequestUnknownV1
	}
	recovered := original.recovery
	if recovered == nil {
		return nil, errApplicationBoundRequestUnknownV1
	}
	recovered.mu.Lock()
	defer recovered.mu.Unlock()
	if recovered.running || recovered.attempted || recovered.closed || recovered.unknown || !recovered.acknowledged || recovered.session == nil || recovered.admission == nil || recovered.cleanup == nil || !recovered.cleanup.retiredV1() || recovered.metadata == nil || recovered.key != original.key || recovered.metadata.PreparationID != original.metadata.PreparationID || len(original.metadata.BindingSha256) != sha256.Size || !bytes.Equal(original.metadata.BindingSha256, recovered.metadata.BindingSha256) {
		return recovered, errApplicationBoundRequestUnknownV1
	}
	original.acknowledged = true
	if err := original.finishWorkV1(ctx); err != nil {
		original.unknown = true
		return recovered, errApplicationBoundRequestUnknownV1
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closing || j.owners[original.key] != original {
		// Shutdown still reaches original.recovery even after original registry
		// closure. Do not hand off after Close took its owner snapshot.
		return recovered, errApplicationBoundRequestUnknownV1
	}
	j.owners[recovered.key] = recovered
	original.recovery = nil
	original.unknown = false
	return recovered, nil
}

func (j *applicationRequestJournalV1) RecoverV1(ctx context.Context, original *applicationRequestOperationV1, rc *RecipientContext, in SignInput) (*applicationRequestOperationV1, error) {
	if original == nil || original.journal != j {
		return nil, errApplicationBoundRequestV1
	}
	if err := applicationBoundRequestContextV1(ctx); err != nil {
		return nil, applicationBoundRequestErrorV1(ctx, err)
	}
	j.mu.Lock()
	closing := j.closing
	j.mu.Unlock()
	if closing {
		return nil, errApplicationBoundRequestUnknownV1
	}
	original.mu.Lock()
	defer original.mu.Unlock()
	if original.running {
		return nil, errApplicationBoundRequestUnknownV1
	}
	if original.exactRowReconciled {
		// Expired credentials cannot authorize new dispatch. This branch performs
		// no dispatch or read at all; it retries already-proven owner cleanup only.
		return j.finishReconciledRequestV1(ctx, original)
	}
	if original.closed || !original.unknown || !original.attempted || original.metadata == nil {
		return nil, errApplicationBoundRequestUnknownV1
	}
	if err := original.retireV1(ctx); err != nil {
		return nil, err
	}
	if child := original.recovery; child != nil {
		child.mu.Lock()
		if child.running || child.attempted {
			child.mu.Unlock()
			return nil, errApplicationBoundRequestUnknownV1
		}
		err := child.finishWorkV1(ctx)
		child.mu.Unlock()
		if err != nil {
			return nil, errApplicationBoundRequestUnknownV1
		}
		original.recovery = nil
	}
	recovered, err := j.existingReadV1(ctx, rc, in, original)
	if err != nil {
		return recovered, err
	}
	// This flag has one production producer: the successful exact immutable row
	// read/rebind whose deferred cleanup joined the actual new read session, after
	// original.retireV1 above. Keep the child reachable through registry errors.
	original.exactRowReconciled = true
	original.acknowledged = true
	return j.finishReconciledRequestV1(ctx, original)
}
func (j *applicationRequestJournalV1) ObserveCreatorMetadataV1(ctx context.Context, op *applicationRequestOperationV1) (*pdfadmission.RecordedApplicationBackendMetadataV1, error) {
	if op == nil || op.journal != j {
		return nil, errApplicationBoundRequestV1
	}
	metadata, _, _, err := op.dataV1()
	if err != nil {
		return nil, err
	}
	record := pdfadmission.RecordedApplicationBackendIdentityV1{PID: metadata.CreatorBackendPid, BackendStart: metadata.CreatorBackendStart, DatabaseOID: metadata.CreatorDatabaseOid, UserOID: metadata.CreatorUserOid, ServerAddress: metadata.CreatorServerAddress, ServerPort: metadata.CreatorServerPort, PostmasterStart: metadata.CreatorPostmasterStart}
	return j.factory.ObserveRecordedBackendMetadataV1(ctx, metadata.OrgID, record)
}

// Never replay: attempted unknown requires exact fresh immutable row recovery.
func (j *applicationRequestJournalV1) ReconcileCleanupV1(ctx context.Context) error {
	if j == nil || j.factory == nil {
		return errApplicationBoundRequestV1
	}
	if err := applicationBoundRequestContextV1(ctx); err != nil {
		return err
	}
	j.mu.Lock()
	list := make([]*applicationRequestOperationV1, 0, len(j.owners))
	for _, op := range j.owners {
		list = append(list, op)
	}
	j.mu.Unlock()
	pending := false
	for _, op := range list {
		op.mu.Lock()
		if op.running {
			pending = true
			op.mu.Unlock()
			continue
		}
		if op.exactRowReconciled {
			if child := op.recovery; child != nil {
				child.mu.Lock()
				disposed := child.closed && !child.running
				child.mu.Unlock()
				// Explicit child Close completed its actual registry/session/consumer
				// conjunction. Keep no disposed result handle; finish original cleanup.
				if disposed {
					op.recovery = nil
				}
			}
			if op.recovery == nil {
				// A successful child Close already disposed the reconciled data. Finish
				// only the original retained registry; never create a replacement owner.
				if err := op.finishV1(ctx); err != nil {
					op.unknown = true
					pending = true
				} else {
					op.unknown = false
				}
			} else {
				// ReconcileCleanup has no result handle to return. Retry only original
				// cleanup and retain original->child ownership; explicit Recover alone
				// may publish that same child to its caller through an atomic handoff.
				if err := op.finishWorkV1(ctx); err != nil {
					op.unknown = true
					pending = true
				} else {
					op.unknown = false
				}
			}
			op.mu.Unlock()
			continue
		}
		if op.unknown {
			if err := op.retireV1(ctx); err != nil || op.attempted {
				pending = true
				op.mu.Unlock()
				continue
			}
			op.unknown = false
			if err := op.finishV1(ctx); err != nil {
				op.unknown = true
				pending = true
			}
		}
		op.mu.Unlock()
	}
	if err := j.factory.ReconcileCleanupV1(ctx); err != nil {
		pending = true
	}
	if pending {
		return errApplicationBoundRequestUnknownV1
	}
	return requestPayloadCheckContextV1(ctx)
}
func (j *applicationRequestJournalV1) CloseV1(ctx context.Context) error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	j.closing = true
	list := make([]*applicationRequestOperationV1, 0, len(j.owners))
	for _, op := range j.owners {
		list = append(list, op)
	}
	j.mu.Unlock()
	pending := false
	for _, op := range list {
		if err := op.CloseV1(ctx); err != nil {
			pending = true
		}
	}
	// This journal borrows the process factory. Closing its own owners must
	// never close shared authoring/other-engine sessions; WorkRuntime owns the
	// final factory Close at process shutdown.
	if pending {
		return errApplicationBoundRequestUnknownV1
	}
	return nil
}
