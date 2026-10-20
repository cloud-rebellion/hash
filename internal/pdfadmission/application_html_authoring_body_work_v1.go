// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/actiontoken"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/google/uuid"
	"math"
	"sync/atomic"
	"unsafe"
)

// This immutable header exists only after this SAME native reader has acquired
// its genuine fixed header class. Its original consumer remains in the reader,
// through every retained model and the actual client/backend retirement fence.
type applicationHTMLAuthoringBodyHeaderV1 struct {
	self      *applicationHTMLAuthoringBodyHeaderV1
	reader    *ApplicationHTMLAuthoringReaderV1
	session   *ApplicationSessionV1
	admission *ApplicationAdmissionV1
	fence     *applicationSessionFenceV1
	loanClose func()
	closed    atomic.Bool
}
type applicationHTMLAuthoringBodyGrantV1 struct {
	self                   *applicationHTMLAuthoringBodyGrantV1
	header                 *applicationHTMLAuthoringBodyHeaderV1
	callbackDone           <-chan struct{}
	factory                *applicationSessionFactoryStateV1
	org, document          uuid.UUID
	raw, wire, working, db int64
}

// Every body gets positive independently retained typed/container storage,
// including empty TEXT/JSON. This fixed union dominates each actual body type;
// map topology is the existing <=64 declarations/string-map grammar, not a new
// capacity or input limit. All dynamic backing remains additive8raw+16wire.
func htmlAuthoringRetainedBodyFixedV1() (int64, error) {
	total := int64(0)
	for _, size := range []int64{
		// Actual plain PDF creation/field/source/result owners.
		int64(unsafe.Sizeof(applicationPlainPDFCreationStateV1{})),
		int64(unsafe.Sizeof(ApplicationPlainPDFCreationWriterV1{})),
		int64(unsafe.Sizeof(applicationPlainPDFFieldBatchStateV1{})),
		int64(unsafe.Sizeof(ApplicationPlainPDFFieldBatchV1{})),
		int64(unsafe.Sizeof(plainPDFQuotaSourceReadsV1{})),
		int64(unsafe.Sizeof(generated.CreatePDFDocumentParams{})),
		int64(unsafe.Sizeof(generated.CreateDraftFieldParams{})),
		// Full Send source/intent/controller/catalog/review/rule/output result headers.
		int64(unsafe.Sizeof(generated.EmailDelivery{})),
		// Fixed standalone sent+expired payload/entry containers; invite-sized
		// dynamic containers are separately funded per actual recipient.
		3*int64(unsafe.Sizeof(audit.Entry{})) + 32*int64(unsafe.Sizeof("")+unsafe.Sizeof(any(nil))+2*unsafe.Sizeof(uintptr(0))),
		int64(unsafe.Sizeof(htmlSendCompletionOutputsV1{})),
		int64(unsafe.Sizeof(htmlSendCompletionRecipientV1{})),
		int64(unsafe.Sizeof(generated.EidasRoutingRule{})),
		int64(unsafe.Sizeof(generated.EidasRuleWireSizesV1{})),
		int64(unsafe.Sizeof(generated.GetActiveEIDASRuleSetHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.LockActiveEIDASRuleSetPinsV1Row{})),
		int64(unsafe.Sizeof(generated.SendSealingIntent{})),
		int64(unsafe.Sizeof(generated.DocumentPackageSendAttemptsV1{})),
		int64(unsafe.Sizeof(generated.CreateDocumentPackageSendAttemptV1Params{})),
		int64(unsafe.Sizeof(generated.CreateDocumentPackageSealingIntentV1Params{})),
		int64(unsafe.Sizeof(generated.InspectDocumentPackageSendAttemptV1Row{})),
		int64(unsafe.Sizeof(generated.DocumentLawfulBasisConfirmation{})),
		int64(unsafe.Sizeof(generated.DocumentCrmMappingReview{})),
		int64(unsafe.Sizeof(generated.OrgBranding{})),
		int64(unsafe.Sizeof(generated.BillingPlan{})),
		int64(unsafe.Sizeof(generated.OrgSubscription{})),
		int64(unsafe.Sizeof(generated.CountBillingUsageInPeriodForOrgRow{})),
		// Original CRM review bounded query returns its129th sentinel row intact.
		129 * (int64(unsafe.Sizeof(generated.DocumentVariableBinding{})) + 2*int64(unsafe.Sizeof(uintptr(0)))),
		int64(unsafe.Sizeof(generated.BillingPlanFeatureSizesV1{})),
		int64(unsafe.Sizeof(generated.GetHTMLSendDocumentStateHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetHTMLSendCollectionReadHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetHTMLSendIntentReadHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetHTMLSendOrgSourceReadHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetHTMLSendOrgBrandingSourceReadHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetHTMLSendCRMReviewReadHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetPlanSourceHeaderByIDV1Row{})),
		int64(unsafe.Sizeof(generated.GetPlanSourceHeaderBySlugV1Row{})),
		int64(unsafe.Sizeof(generated.GetPlanSourceSubscriptionHeaderV1Row{})),

		// Full revision/workflow actor/document/current and fresh write/cache/version results.
		// Distinct old/new/native/exposed Document headers coexist; dynamic backing
		// remains independently charged by each actual raw/wire body loan.
		4 * int64(unsafe.Sizeof(generated.Document{})),
		2 * int64(unsafe.Sizeof(htmlmaterialization.CurrentReadProjectionV1{})),
		2 * int64(unsafe.Sizeof(generated.HtmlDocumentMaterialization{})),
		2 * int64(unsafe.Sizeof(generated.HtmlDocumentMaterializationSnapshot{})),
		2 * int64(unsafe.Sizeof(generated.DocumentVersion{})),
		int64(unsafe.Sizeof(generated.GetHTMLRevisionDocumentReadHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetHTMLRevisionSnapshotSizeHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetSignerCurrentMaterializationHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.LockHTMLRevisionSnapshotSizeCachesV1Row{})),
		int64(unsafe.Sizeof(generated.HtmlRevisionSnapshotSizesV1{})),
		int64(unsafe.Sizeof(generated.DocumentSigningPolicySizesV1{})),
		int64(unsafe.Sizeof(generated.FieldSigningPolicySizesV1{})),
		int64(unsafe.Sizeof(generated.DocumentReadReportSizesV1{})),
		2 * int64(unsafe.Sizeof(generated.ChangeRequest{})),
		int64(unsafe.Sizeof(ApplicationHTMLCeremonyWorkflowV1{})),
		int64(unsafe.Sizeof(ApplicationHTMLChangeNotificationV1{})),
		2 * int64(unsafe.Sizeof(dispatch.Message{})),
		int64(unsafe.Sizeof(dispatch.TemplateContext{})),
		int64(unsafe.Sizeof(generated.EmailDelivery{})),
		2 * int64(unsafe.Sizeof(actiontoken.Claims{})),
		int64(unsafe.Sizeof(HTMLParticipantChangeInputV1{})),
		int64(unsafe.Sizeof(HTMLCeremonyParticipantPolicyV1{})),
		int64(unsafe.Sizeof(HTMLCeremonyWorkflowAccessV1{})),
		int64(unsafe.Sizeof(generated.GetHTMLCeremonyWorkflowAccessV1Row{})),
		int64(unsafe.Sizeof(generated.ReadHTMLCeremonyParticipantPolicyV1Row{})),
		int64(unsafe.Sizeof(generated.GetHTMLChangeRequestReadHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetHTMLChangeNotificationSenderHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.GetHTMLCeremonyParticipantRecipientHeaderV1Row{})),
		int64(unsafe.Sizeof(generated.Recipient{})),
		int64(unsafe.Sizeof(generated.DocumentField{})),
		int64(unsafe.Sizeof(generated.DocumentBrandingOverride{})),
		int64(unsafe.Sizeof(ApplicationHTMLRevisionWriterV1{})),
		int64(unsafe.Sizeof(ApplicationHTMLRevisionCollectionsV1{})),
		int64(unsafe.Sizeof(HTMLRevisionReadModelsV1{})),
		int64(unsafe.Sizeof(applicationHTMLRevisionSourceSnapshotV1{})),
		4 * int64(unsafe.Sizeof(HTMLRevisionSourceParentErrorV1{})),
		int64(unsafe.Sizeof(generated.Template{})),
		int64(unsafe.Sizeof(generated.HtmlTemplateRevision{})),
		2 * int64(unsafe.Sizeof(generated.User{})),
		int64(unsafe.Sizeof(generated.Org{})),
		int64(unsafe.Sizeof(generated.CrmConnection{})),
		int64(unsafe.Sizeof(generated.ReadHTMLCreationResponseV1Row{})),
		int64(unsafe.Sizeof(htmlAuthoringCanonicalSourceV1{})),
		int64(unsafe.Sizeof(applicationHTMLAuthoringBodyGrantV1{})),
		int64(unsafe.Sizeof(applicationHTMLAuthoringBodyHeaderV1{})),
		int64(unsafe.Sizeof(ApplicationBudgetV1{})),
		int64(unsafe.Sizeof([]func(){})),
	} {
		if !htmlStoredRetentionAllocV1(&total, size) {
			return 0, ErrHTMLAuthoringReadV1
		}
	}
	// Two separately retained string maps, including old/current Swiss groups,
	// key/value headers and controls. The union's map slot80B dominates string32B.
	slots := 2 * htmlInputPowerV1(max(8, (int64(htmlmaster.MaxDefinitions)*8+6)/7))
	for range 2 {
		if !htmlInputAddV1(&total, slots, 2*(80+1)) || !htmlInputAddV1(&total, 1, 2*16*256) {
			return 0, ErrHTMLAuthoringReadV1
		}
	}
	// Per-loan closure/interface/header and exact registry bookkeeping storage.
	for _, part := range [][2]int64{{8, 16}, {8, 32}, {1, 2 * 256}} {
		if !htmlInputAddV1(&total, part[0], part[1]) {
			return 0, ErrHTMLAuthoringReadV1
		}
	}
	return htmlStoredRetentionFinishV1(total)
}
func htmlAuthoringRetainedBodyResourcesV1(raw, wire int64) (ApplicationRequestPayloadResourcesV1, error) {
	var empty ApplicationRequestPayloadResourcesV1
	fixed, err := htmlAuthoringRetainedBodyFixedV1()
	if err != nil || raw < 0 || wire < 0 || wire > (math.MaxInt64-fixed)/16 {
		return empty, ErrHTMLAuthoringReadV1
	}
	db := 16*wire + fixed
	if raw > (math.MaxInt64-db)/8 {
		return empty, ErrHTMLAuthoringReadV1
	}
	return ApplicationRequestPayloadResourcesV1{WorkingBytes: 8*raw + db, DBStagingBytes: db}, nil
}

// Called only by the actual reader while its own mutex is held. Public budget
// fields cannot manufacture a header proof or adopt another native session.
func (r *ApplicationHTMLAuthoringReaderV1) acquireRetainedBodyV1(ctx context.Context, raw, wire int64) (func(), error) {
	if r == nil || r.self != r || !r.valid(ctx) {
		return nil, ErrHTMLAuthoringReadV1
	}
	header := r.bodyHeader
	if header == nil || header.self != header || header.reader != r || header.session != r.session || header.loanClose == nil || header.closed.Load() {
		return nil, ErrHTMLAuthoringReadV1
	}
	resources, err := htmlAuthoringRetainedBodyResourcesV1(raw, wire)
	if err != nil {
		return nil, err
	}
	s := r.session.state
	p := s.factory
	if p == nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	a := s.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || s.observer || s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) || a == nil || !a.valid() || header.admission != a || header.fence != s.fence || a.fence != s.fence || a.cleanupDone != s.fence.clientDone || !s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		return nil, ErrHTMLAuthoringReadV1
	}
	grant := &applicationHTMLAuthoringBodyGrantV1{header: header, callbackDone: ctx.Done(), factory: p, org: s.org, document: s.document, raw: raw, wire: wire, working: resources.WorkingBytes, db: resources.DBStagingBytes}
	grant.self = grant
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	closeConsumer, err := a.admit(ctx, ApplicationBudgetV1{Phase: "locked-html-authoring-retained-body", OrgID: s.org, DocumentID: s.document, HTMLAuthoringRawBytes: raw, HTMLAuthoringWireBytes: wire, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes, htmlAuthoringBodyGrant: grant})
	if err != nil {
		return nil, errors.Join(ErrHTMLAuthoringReadV1, err)
	}
	return closeConsumer, nil
}

// Only immutable fields are read by the coordinator adapter. Mutable live
// reader/session checks above run under reader->factory->session ownership;
// actual CloseConsumer cannot race that production acquire.
func (g *applicationHTMLAuthoringBodyGrantV1) validBudgetV1(ctx context.Context, work *WorkAdmissionV1, b ApplicationBudgetV1) bool {
	if g == nil || g.self != g || g.factory == nil || g.factory.work != work || g.header == nil || ctx == nil || g.callbackDone == nil || ctx.Done() != g.callbackDone {
		return false
	}
	select {
	case <-g.callbackDone:
		return false
	default:
	}
	h := g.header
	r := h.reader
	if h.self != h || r == nil || r.self != r || r.bodyHeader != h || r.session != h.session || h.session == nil || h.session.state == nil || h.admission == nil || h.fence == nil || h.loanClose == nil || h.closed.Load() {
		return false
	}
	s := h.session.state
	if ctx.Value(applicationSessionCallbackKeyV1{}) != s || s.factory != g.factory || s.org != g.org || s.document != g.document || s.admission != h.admission || s.fence != h.fence || h.admission.fence != h.fence || h.admission.cleanupDone != h.fence.clientDone {
		return false
	}
	expected := ApplicationBudgetV1{Phase: "locked-html-authoring-retained-body", OrgID: g.org, DocumentID: g.document, HTMLAuthoringRawBytes: g.raw, HTMLAuthoringWireBytes: g.wire, WorkingBytes: g.working, DBStagingBytes: g.db, htmlAuthoringBodyGrant: g}
	return b == expected && g.org != uuid.Nil && g.document != uuid.Nil && g.working > 0 && g.db > 0
}

// Other concrete native owners borrow this SAME reader/header class. The
// wrapper only serializes the existing private grant under its original lock;
// it creates no token, size authority, SQL permit or new ownership category.
func (r *ApplicationHTMLAuthoringReaderV1) acquireOwnedRetainedBodyV1(ctx context.Context, raw, wire int64) (func(), error) {
	if r == nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.acquireRetainedBodyV1(ctx, raw, wire)
}
