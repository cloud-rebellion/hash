// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"math"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

const (
	// These are the complete supported canonical request wire bounds, including
	// default JSON escaping. They match the private closed signing codec V1.
	MaxApplicationRequestOriginBytesV1  = 395070
	MaxApplicationAcceptedIntentBytesV1 = 697810
)

// Cost metadata is data, not credential/operation/readiness/retirement proof.
// The private signer codec derives these lengths BEFORE body copy/hash/Marshal.
// RawContextBytes is the full retained original raw-string byte loan; arbitrary
// customer TEXT is not truncated or capped by a new document-content policy.
type ApplicationRequestPayloadCostV1 struct {
	OriginBytes, IntentBytes, RawContextBytes int64
}
type ApplicationRequestPayloadResourcesV1 struct {
	WorkingBytes, DBStagingBytes int64
}

// This fixed formula is a conservative declared codec allocation loan, not
// measured RSS or a bound on PostgreSQL heap. Extra authority/span/source/field
// processing, transport and durable89/90 debt retain their own admitted costs.
func ApplicationRequestPayloadResourcesForV1(b ApplicationRequestPayloadCostV1) (ApplicationRequestPayloadResourcesV1, error) {
	if !workBoundV1(b.OriginBytes, MaxApplicationRequestOriginBytesV1) || !workBoundV1(b.IntentBytes, MaxApplicationAcceptedIntentBytesV1) || b.RawContextBytes < 0 {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	// Supported body ceilings make this addition finite; subtraction before the
	// raw addition prevents even rejected public metadata from wrapping int64.
	bodies := b.OriginBytes + b.IntentBytes
	fixed := 8*bodies + 8192
	if b.RawContextBytes > math.MaxInt64-fixed {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	return ApplicationRequestPayloadResourcesV1{WorkingBytes: fixed + b.RawContextBytes, DBStagingBytes: bodies}, nil
}

// AcquireRequestPayloadV1 is the real fixed factory/session-owned codec seam.
// NewAdmissionV1 must already have created this session's ONE owned admission.
// This function does not read a body, dispatch SQL or authenticate caller scope.
// It runs no capacity wait; refusal under entity locks requires owned rollback
// before any outside-lock capacity retry. UUIDs are exact accounting scope only.
//
// The returned function ONLY closes the consumer in the admission's private
// registry. Cancellation, COMMIT, elapsed TTL, copied header, metadata PID
// absence and this function's return do not credit the shared coordinator.
// The owner must keep the actual admission and call its CloseV1/reconciliation
// outside locks after consumers close and the ORIGINAL session physically
// retires. The existing real client+observer fence governs transient release;
// immutable retained90 debt and commit disposition require separate evidence.
func (h *ApplicationSessionV1) AcquireRequestPayloadV1(ctx context.Context, scope ApplicationScopeV1, recipientID uuid.UUID, cost ApplicationRequestPayloadCostV1) (func(), error) {
	if !scope.valid() {
		return nil, applicationErrorV1(ctx, nil)
	}
	resources, err := ApplicationRequestPayloadResourcesForV1(cost)
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	return h.acquireRequestWorkV1(ctx, ApplicationBudgetV1{Phase: "locked-request-payload", OrgID: scope.OrgID, DocumentID: scope.DocumentID, AdmissionID: scope.AdmissionID, RecipientID: recipientID, RequestOriginBytes: cost.OriginBytes, RequestIntentBytes: cost.IntentBytes, RequestRawContextBytes: cost.RawContextBytes, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes})
}

// The cheap fixed scope header locks at most the supported100 parties and
// returns scalar lengths/IDs only. It must precede current raw hashing/body SQL.
// It does not require an active AdmissionID before that ID is read. These8MiB
// loans are conservative bounded metadata work allowances, not measured heaps.
const applicationRequestHeaderWorkingBytesV1 int64 = 8 << 20
const applicationRequestHeaderDBBytesV1 int64 = 8 << 20

func (h *ApplicationSessionV1) AcquireRequestHeaderV1(ctx context.Context, orgID, documentID, recipientID uuid.UUID) (func(), error) {
	return h.acquireRequestWorkV1(ctx, ApplicationBudgetV1{Phase: "locked-request-header", OrgID: orgID, DocumentID: documentID, RecipientID: recipientID, WorkingBytes: applicationRequestHeaderWorkingBytesV1, DBStagingBytes: applicationRequestHeaderDBBytesV1})
}

type ApplicationRequestJournalKindV1 string

const (
	ApplicationRequestJournalCaptureV1 ApplicationRequestJournalKindV1 = "capture-v1"
	ApplicationRequestJournalReadV1    ApplicationRequestJournalKindV1 = "read-v1"
)

type ApplicationRequestJournalCostV1 struct {
	Kind                                                                                                           ApplicationRequestJournalKindV1
	OriginBytes, IntentBytes, AuthorityBytes, SpanBytes, CurrentContextBytes, OriginalRawContextBytes, PolicyBytes int64
}

// CurrentContextBytes comes from the actual cheap M90 scoped header and
// includes its8192 fixed overhead plus exact raw name/basis/controller/org/via
// byte lengths. OriginalRawContextBytes is the private original receipt five
// raw-string len sum, admitted before pre-issuance comparisons/TrimSpace. The16x
// allowances also charge source-derived projected policy document HTML/variables
// and required recipient/field row bodies BEFORE those preserved policy reads.
// PolicyBytes is exact admitted metadata, not a new content cap. The allowances
// cover canonical87 production/clones/hash,
// driver BODYA capture/read/rebind and90 JSON/current-context/full-body checks.
// Logical DB demand is transient validation work; durable90 debt stays separate.
func ApplicationRequestJournalResourcesForV1(b ApplicationRequestJournalCostV1) (ApplicationRequestPayloadResourcesV1, error) {
	if (b.Kind != ApplicationRequestJournalCaptureV1 && b.Kind != ApplicationRequestJournalReadV1) || !workBoundV1(b.OriginBytes, MaxApplicationRequestOriginBytesV1) || !workBoundV1(b.IntentBytes, MaxApplicationAcceptedIntentBytesV1) ||
		!workBoundV1(b.AuthorityBytes, manualfit.MaxAuthorityBytesV1) || !workBoundV1(b.SpanBytes, manualfit.MaxSpanBytesV1) || b.CurrentContextBytes < 8192 || b.OriginalRawContextBytes < 0 || b.PolicyBytes < 0 {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	bodies := b.OriginBytes + b.IntentBytes + b.AuthorityBytes + b.SpanBytes
	if b.PolicyBytes > math.MaxInt64-bodies {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	policyBodies := bodies + b.PolicyBytes
	if b.OriginalRawContextBytes > math.MaxInt64-b.CurrentContextBytes {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	contextWork := b.CurrentContextBytes + b.OriginalRawContextBytes
	if policyBodies > (math.MaxInt64-(8<<20))/16-contextWork || policyBodies > (math.MaxInt64-b.CurrentContextBytes)/16 {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	return ApplicationRequestPayloadResourcesV1{WorkingBytes: 16*(policyBodies+contextWork) + (8 << 20), DBStagingBytes: 16*policyBodies + b.CurrentContextBytes}, nil
}
func (h *ApplicationSessionV1) AcquireRequestJournalV1(ctx context.Context, scope ApplicationScopeV1, recipientID uuid.UUID, cost ApplicationRequestJournalCostV1) (func(), error) {
	if !scope.valid() {
		return nil, applicationErrorV1(ctx, nil)
	}
	resources, err := ApplicationRequestJournalResourcesForV1(cost)
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	phase := "locked-request-capture"
	if cost.Kind == ApplicationRequestJournalReadV1 {
		phase = "locked-request-read"
	}
	return h.acquireRequestWorkV1(ctx, ApplicationBudgetV1{Phase: phase, OrgID: scope.OrgID, DocumentID: scope.DocumentID, AdmissionID: scope.AdmissionID, RecipientID: recipientID, RequestOriginBytes: cost.OriginBytes, RequestIntentBytes: cost.IntentBytes, RequestAuthorityBytes: cost.AuthorityBytes, RequestSpanBytes: cost.SpanBytes, RequestCurrentContextBytes: cost.CurrentContextBytes, RequestOriginalRawContextBytes: cost.OriginalRawContextBytes, RequestPolicyBytes: cost.PolicyBytes, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes})
}

// All fixed request kinds share this actual owner and private loan registry.
// No caller release callback, independent coordinator or physical-proof flag.
func (h *ApplicationSessionV1) acquireRequestWorkV1(ctx context.Context, b ApplicationBudgetV1) (func(), error) {
	if h == nil || h.state == nil || !applicationContextV1(ctx) || b.OrgID == uuid.Nil || b.DocumentID == uuid.Nil || b.RecipientID == uuid.Nil {
		return nil, applicationErrorV1(ctx, nil)
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.admission
	if s.factory == nil || s.factory.work == nil || s.factory.work.coordinator == nil || s.observer || s.org != b.OrgID || s.document != b.DocumentID ||
		s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) ||
		a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone ||
		(s.callbackActive && ctx.Value(applicationSessionCallbackKeyV1{}) != s) ||
		(ctx.Value(applicationSessionCallbackKeyV1{}) != nil && ctx.Value(applicationSessionCallbackKeyV1{}) != s) {
		return nil, applicationErrorV1(ctx, nil)
	}
	// a.acquire was installed only by fixed owned NewAdmissionV1. This short
	// nonblocking coordinator call runs no SQL/network or caller callback.
	closeConsumer, err := a.admit(ctx, b)
	if err != nil {
		return nil, applicationErrorV1(ctx, err)
	}
	if ctx.Err() != nil {
		closeConsumer()
		return nil, applicationErrorV1(ctx, nil)
	}
	return closeConsumer, nil
}
