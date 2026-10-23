// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"

	"github.com/bright-interaction/hash/internal/ordinarypage"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// WorkAdmissionV1 is a fixed versioned cost adapter around the ONE coordinator
// shared by this application process. It validates exact input bounds, phase
// fields and formulas, rather than accepting arbitrary reported WorkingBytes.
// It grants no credential, provider-origin, durable storage or Sign authority.
type WorkAdmissionV1 struct{ coordinator *workguard.CoordinatorV1 }

func NewWorkAdmissionV1(c *workguard.CoordinatorV1) (*WorkAdmissionV1, error) {
	if c == nil {
		return nil, workguard.ErrUnavailableV1
	}
	return &WorkAdmissionV1{coordinator: c}, nil
}
func workBoundV1(n, max int64) bool { return n > 0 && n <= max }
func (a *WorkAdmissionV1) acquire(ctx context.Context, org uuid.UUID, cost workguard.VectorV1) (func(), error) {
	if a == nil || a.coordinator == nil {
		return nil, workguard.ErrUnavailableV1
	}
	g, err := a.coordinator.TryAcquireV1(ctx, org, cost)
	if err != nil {
		return nil, err
	}
	return g.Close, nil
}

// ApplicationV1 holds only retained-parent and DB-staging costs. One source
// receipt may own many later page borrowers: physical worker/session/stream
// slots MUST have separate lifetime grants, or a one-slot deployment cannot
// make progress. SQL loans retain these costs through actual server retirement.
func (a *WorkAdmissionV1) ApplicationV1(ctx context.Context, b ApplicationBudgetV1) (func(), error) {
	return a.applicationV1(ctx, b, nil)
}

// Only the native signer reader bridge uses this private companion. It runs
// identical budget validation before the one original coordinator decision.
func (a *WorkAdmissionV1) applicationSignerReadWithDenialV1(ctx context.Context, b ApplicationBudgetV1, denial *workguard.AdmissionDenialV1) (func(), error) {
	if a == nil || a.coordinator == nil || denial == nil || (b.Phase != "locked-signer-read-header" && b.Phase != "locked-signer-read-body") {
		return nil, workguard.ErrUnavailableV1
	}
	return a.applicationV1(ctx, b, denial)
}

// Fixed native fresh-audit companion: the same budget validator and atomic
// coordinator decision, with only its immutable numeric refusal observation.
func (a *WorkAdmissionV1) applicationAuditWithDenialV1(ctx context.Context, b ApplicationBudgetV1, denial *workguard.AdmissionDenialV1) (func(), error) {
	if a == nil || a.coordinator == nil || denial == nil || b.Phase != "locked-html-fresh-event" {
		return nil, workguard.ErrUnavailableV1
	}
	return a.applicationV1(ctx, b, denial)
}

func (a *WorkAdmissionV1) applicationV1(ctx context.Context, b ApplicationBudgetV1, denial *workguard.AdmissionDenialV1) (func(), error) {
	if b.OrgID == uuid.Nil || b.DocumentID == uuid.Nil || (b.AdmissionID == uuid.Nil && b.Phase != "locked-request-header" && b.Phase != "locked-html-fresh-creation" && b.Phase != "locked-html-authoring-header" && b.Phase != "locked-html-authoring-read" && b.Phase != "locked-html-template-write" && b.Phase != "locked-signer-read-header" && b.Phase != "locked-signer-read-body" && b.Phase != "locked-html-fresh-event" && b.Phase != "locked-pdf-layout-fresh-events" && b.Phase != "locked-automation-fresh-events" && b.Phase != "locked-package-send-fresh-events" && b.Phase != "locked-package-send-outbox-returns" && b.Phase != "owned-html-revision-source" && b.Phase != "locked-html-authoring-retained-body" && b.Phase != "locked-html-send-collections" && b.Phase != "locked-html-send-eidas" && b.Phase != "locked-html-send-plan-policy") {
		return nil, workguard.ErrUnavailableV1
	}
	var expected ApplicationBudgetV1
	expected.Phase = b.Phase
	expected.OrgID = b.OrgID
	expected.DocumentID = b.DocumentID
	expected.AdmissionID = b.AdmissionID
	componentsMax := int64(4*MaxComponentBytesV1 + MaxRenderRecipeBytesV1 + (16 << 10))
	switch b.Phase {
	case "locked-html-send-collections":
		if b.htmlSendCollectionGrant == nil || !b.htmlSendCollectionGrant.validBudgetV1(ctx, a, b) {
			return nil, workguard.ErrUnavailableV1
		}
		return a.acquire(ctx, b.OrgID, workguard.VectorV1{ParentBytes: b.WorkingBytes, DBStagingBytes: b.DBStagingBytes})
	case "locked-html-send-plan-policy":
		if b.htmlSendPlanPolicyGrant == nil || !b.htmlSendPlanPolicyGrant.validBudgetV1(ctx, a, b) {
			return nil, workguard.ErrUnavailableV1
		}
		return a.acquire(ctx, b.OrgID, workguard.VectorV1{ParentBytes: b.WorkingBytes})
	case "locked-html-send-eidas":
		if b.htmlSendEIDASGrant == nil || !b.htmlSendEIDASGrant.validBudgetV1(ctx, a, b) {
			return nil, workguard.ErrUnavailableV1
		}
		return a.acquire(ctx, b.OrgID, workguard.VectorV1{ParentBytes: b.WorkingBytes, DBStagingBytes: b.DBStagingBytes})
	case "locked-html-authoring-retained-body":
		if b.htmlAuthoringBodyGrant == nil || !b.htmlAuthoringBodyGrant.validBudgetV1(ctx, a, b) {
			return nil, workguard.ErrUnavailableV1
		}
		return a.acquire(ctx, b.OrgID, workguard.VectorV1{ParentBytes: b.WorkingBytes, DBStagingBytes: b.DBStagingBytes})
	case "owned-html-revision-source":
		g := b.htmlRevisionSourceGrant
		if b.AdmissionID != uuid.Nil || !g.validV1(ctx, b.OrgID, b.DocumentID) {
			return nil, workguard.ErrUnavailableV1
		}
		expected.htmlRevisionSourceGrant = g
		expected.WorkingBytes = g.parentBytes
	case "locked-package-send-outbox-returns":
		g := b.packageSendOutboxGrant
		if b.AdmissionID != uuid.Nil || g == nil || !g.validBudgetV1(ctx, a, b) {
			return nil, workguard.ErrUnavailableV1
		}
		return a.acquire(ctx, b.OrgID, workguard.VectorV1{ParentBytes: b.WorkingBytes, DBStagingBytes: b.DBStagingBytes})
	case "locked-package-send-fresh-events":
		g := b.packageSendAuditGrant
		if b.AdmissionID != uuid.Nil || g == nil || !g.validBudgetV1(ctx, a, b) {
			return nil, workguard.ErrUnavailableV1
		}
		r, err := packageSendAuditBatchResourcesV1(b.PackageSendAuditEventCount, b.HTMLAuditRawBytes, b.HTMLAuditWireBytes, b.HTMLAuditNodes)
		if err != nil {
			return nil, err
		}
		expected.packageSendAuditGrant = g
		expected.PackageSendAuditEventCount = b.PackageSendAuditEventCount
		expected.HTMLAuditRawBytes = b.HTMLAuditRawBytes
		expected.HTMLAuditWireBytes = b.HTMLAuditWireBytes
		expected.HTMLAuditNodes = b.HTMLAuditNodes
		expected.WorkingBytes = r.WorkingBytes
		expected.DBStagingBytes = r.DBStagingBytes
	case "locked-automation-fresh-events":
		g := b.automationAuditGrant
		if b.AdmissionID != uuid.Nil || g == nil || !g.validBudgetV1(ctx, a, b) {
			return nil, workguard.ErrUnavailableV1
		}
		r, err := automationAuditBatchResourcesV1(b.AutomationAuditEventCount, b.HTMLAuditRawBytes, b.HTMLAuditWireBytes, b.HTMLAuditNodes)
		if err != nil {
			return nil, err
		}
		expected.automationAuditGrant = g
		expected.AutomationAuditEventCount = b.AutomationAuditEventCount
		expected.HTMLAuditRawBytes = b.HTMLAuditRawBytes
		expected.HTMLAuditWireBytes = b.HTMLAuditWireBytes
		expected.HTMLAuditNodes = b.HTMLAuditNodes
		expected.WorkingBytes = r.WorkingBytes
		expected.DBStagingBytes = r.DBStagingBytes
	case "locked-pdf-layout-fresh-events":
		g := b.pdfLayoutAuditGrant
		if b.AdmissionID != uuid.Nil || g == nil || !g.validBudgetV1(ctx, a, b) {
			return nil, workguard.ErrUnavailableV1
		}
		r, err := pdfLayoutAuditBatchResourcesV1(b.PDFLayoutAuditEventCount, b.HTMLAuditRawBytes, b.HTMLAuditWireBytes, b.HTMLAuditNodes)
		if err != nil {
			return nil, err
		}
		expected.pdfLayoutAuditGrant = g
		expected.PDFLayoutAuditEventCount = b.PDFLayoutAuditEventCount
		expected.HTMLAuditRawBytes = b.HTMLAuditRawBytes
		expected.HTMLAuditWireBytes = b.HTMLAuditWireBytes
		expected.HTMLAuditNodes = b.HTMLAuditNodes
		expected.WorkingBytes = r.WorkingBytes
		expected.DBStagingBytes = r.DBStagingBytes
	case "locked-html-fresh-event":
		if b.AdmissionID != uuid.Nil {
			return nil, workguard.ErrUnavailableV1
		}
		r, err := htmlAuditResourcesV1(b.HTMLAuditRawBytes, b.HTMLAuditWireBytes, b.HTMLAuditNodes)
		if err != nil {
			return nil, err
		}
		expected.HTMLAuditRawBytes = b.HTMLAuditRawBytes
		expected.HTMLAuditWireBytes = b.HTMLAuditWireBytes
		expected.HTMLAuditNodes = b.HTMLAuditNodes
		expected.WorkingBytes = r.WorkingBytes
		expected.DBStagingBytes = r.DBStagingBytes
	case "locked-html-authoring-header", "locked-html-authoring-read", "locked-html-template-write", "locked-signer-read-header", "locked-signer-read-body":
		if b.AdmissionID != uuid.Nil || ((b.Phase == "locked-html-authoring-header" || b.Phase == "locked-signer-read-header") && (b.HTMLAuthoringRawBytes != 0 || b.HTMLAuthoringWireBytes != 0)) {
			return nil, workguard.ErrUnavailableV1
		}
		r, err := htmlAuthoringResourcesV1(b.HTMLAuthoringRawBytes, b.HTMLAuthoringWireBytes)
		if err != nil {
			return nil, err
		}
		expected.HTMLAuthoringRawBytes = b.HTMLAuthoringRawBytes
		expected.HTMLAuthoringWireBytes = b.HTMLAuthoringWireBytes
		expected.WorkingBytes, expected.DBStagingBytes = r.WorkingBytes, r.DBStagingBytes
	case "locked-html-fresh-creation":
		if b.AdmissionID != uuid.Nil {
			return nil, workguard.ErrUnavailableV1
		}
		r, err := htmlCreationFixedResourcesV1(b.HTMLInputRawBytes, b.HTMLInputWireBytes, b.HTMLSourceWireBytes)
		if err != nil {
			return nil, err
		}
		expected.HTMLInputRawBytes = b.HTMLInputRawBytes
		expected.HTMLInputWireBytes = b.HTMLInputWireBytes
		expected.HTMLSourceWireBytes = b.HTMLSourceWireBytes
		expected.WorkingBytes = r.WorkingBytes
		expected.DBStagingBytes = r.DBStagingBytes

	case "locked-request-header":
		if b.RecipientID == uuid.Nil || b.AdmissionID != uuid.Nil {
			return nil, workguard.ErrUnavailableV1
		}
		expected.RecipientID = b.RecipientID
		expected.WorkingBytes = applicationRequestHeaderWorkingBytesV1
		expected.DBStagingBytes = applicationRequestHeaderDBBytesV1
	case "locked-request-capture", "locked-request-read":
		if b.RecipientID == uuid.Nil {
			return nil, workguard.ErrUnavailableV1
		}
		kind := ApplicationRequestJournalCaptureV1
		if b.Phase == "locked-request-read" {
			kind = ApplicationRequestJournalReadV1
		}
		r, err := ApplicationRequestJournalResourcesForV1(ApplicationRequestJournalCostV1{Kind: kind, OriginBytes: b.RequestOriginBytes, IntentBytes: b.RequestIntentBytes, AuthorityBytes: b.RequestAuthorityBytes, SpanBytes: b.RequestSpanBytes, CurrentContextBytes: b.RequestCurrentContextBytes, OriginalRawContextBytes: b.RequestOriginalRawContextBytes, PolicyBytes: b.RequestPolicyBytes})
		if err != nil {
			return nil, err
		}
		expected.RecipientID = b.RecipientID
		expected.RequestOriginBytes = b.RequestOriginBytes
		expected.RequestIntentBytes = b.RequestIntentBytes
		expected.RequestAuthorityBytes = b.RequestAuthorityBytes
		expected.RequestSpanBytes = b.RequestSpanBytes
		expected.RequestCurrentContextBytes = b.RequestCurrentContextBytes
		expected.RequestOriginalRawContextBytes = b.RequestOriginalRawContextBytes
		expected.RequestPolicyBytes = b.RequestPolicyBytes
		expected.WorkingBytes = r.WorkingBytes
		expected.DBStagingBytes = r.DBStagingBytes
	case "locked-request-payload":
		if b.RecipientID == uuid.Nil {
			return nil, workguard.ErrUnavailableV1
		}
		r, err := ApplicationRequestPayloadResourcesForV1(ApplicationRequestPayloadCostV1{OriginBytes: b.RequestOriginBytes, IntentBytes: b.RequestIntentBytes, RawContextBytes: b.RequestRawContextBytes})
		if err != nil {
			return nil, err
		}
		expected.RecipientID = b.RecipientID
		expected.RequestOriginBytes = b.RequestOriginBytes
		expected.RequestIntentBytes = b.RequestIntentBytes
		expected.RequestRawContextBytes = b.RequestRawContextBytes
		expected.WorkingBytes = r.WorkingBytes
		expected.DBStagingBytes = r.DBStagingBytes
	case "locked-basis", "locked-ready", "locked-cold-ready":
		if !workBoundV1(b.StoredBasisBytes, MaxCanonicalBytesV1) || !workBoundV1(b.ComponentBytes, componentsMax) {
			return nil, workguard.ErrUnavailableV1
		}
		expected.StoredBasisBytes = b.StoredBasisBytes
		expected.ComponentBytes = b.ComponentBytes
		expected.WorkingBytes = 16*(b.StoredBasisBytes+b.ComponentBytes) + (8 << 20)
		if b.Phase == "locked-basis" {
			if !workBoundV1(b.SourceBytes, sanitize.MaxPDFBytes) {
				return nil, workguard.ErrUnavailableV1
			}
			expected.SourceBytes = b.SourceBytes
		}
		if b.Phase == "locked-cold-ready" {
			if b.OriginalPDFBytes < 0 || b.OriginalPDFBytes > 50<<20 || b.OriginalPlanBytes < 0 || b.OriginalPlanBytes > 8<<20 || (b.OriginalPDFBytes == 0) != (b.OriginalPlanBytes == 0) {
				return nil, workguard.ErrUnavailableV1
			}
			expected.OriginalPDFBytes = b.OriginalPDFBytes
			expected.OriginalPlanBytes = b.OriginalPlanBytes
			expected.WorkingBytes += 4 * (b.OriginalPDFBytes + b.OriginalPlanBytes)
			expected.DBStagingBytes = 16 * (b.StoredBasisBytes + b.ComponentBytes)
		}
	case "locked-original-read", "locked-original-capture", "cold-fragment":
		if !workBoundV1(b.OriginalPDFBytes, ordinarypage.MaxPDFBytesV1) || !workBoundV1(b.OriginalPlanBytes, ordinarypage.MaxPlanBytesV1) {
			return nil, workguard.ErrUnavailableV1
		}
		expected.OriginalPDFBytes = b.OriginalPDFBytes
		expected.OriginalPlanBytes = b.OriginalPlanBytes
		expected.WorkingBytes = 4*(b.OriginalPDFBytes+b.OriginalPlanBytes) + (8 << 20)
		if b.Phase == "locked-original-capture" {
			expected.DBStagingBytes = b.OriginalPDFBytes + b.OriginalPlanBytes
		}
	case "generation-source", "cold-source":
		if !workBoundV1(b.SourceBytes, sanitize.MaxPDFBytes) || !workBoundV1(b.StoredBasisBytes, MaxCanonicalBytesV1) {
			return nil, workguard.ErrUnavailableV1
		}
		expected.SourceBytes = b.SourceBytes
		expected.StoredBasisBytes = b.StoredBasisBytes
		expected.WorkingBytes = 4*b.SourceBytes + 16*b.StoredBasisBytes + (8 << 20)
	case "generation-page":
		expected.OriginalPDFBytes = ordinarypage.MaxPDFBytesV1
		expected.OriginalPlanBytes = ordinarypage.MaxPlanBytesV1
		expected.DBStagingBytes = ordinarypage.MaxPDFBytesV1 + ordinarypage.MaxPlanBytesV1
		expected.WorkingBytes = 8*ordinarypage.MaxPackageBytesV1 + 8*ordinarypage.MaxPlanBytesV1 + (32 << 20)
	default:
		return nil, workguard.ErrUnavailableV1
	}
	if b != expected {
		return nil, workguard.ErrUnavailableV1
	}
	cost := workguard.VectorV1{ParentBytes: expected.WorkingBytes, DBStagingBytes: expected.DBStagingBytes}
	if denial != nil {
		grant, observed, err := a.coordinator.TryAcquireWithDenialV1(ctx, b.OrgID, cost)
		*denial = observed
		if err != nil {
			return nil, err
		}
		return grant.Close, nil
	}
	return a.acquire(ctx, b.OrgID, cost)
}

// OrdinaryV1 grants retained parent buffers. The parser's separate fixed worker
// grant is acquired immediately before dispatch and not retained in a receipt.
func (a *WorkAdmissionV1) OrdinaryV1(ctx context.Context, b OrdinaryInspectionBudgetV1) (func(), error) {
	if b.OrgID == uuid.Nil || b.DocumentID == uuid.Nil {
		return nil, workguard.ErrUnavailableV1
	}
	expected := OrdinaryInspectionBudgetV1{Phase: b.Phase, OrgID: b.OrgID, DocumentID: b.DocumentID}
	switch b.Phase {
	case "source":
		if !workBoundV1(b.SourceBytes, sanitize.MaxPDFBytes) || !workBoundV1(b.CanonicalBytes, MaxCanonicalBytesV1) {
			return nil, workguard.ErrUnavailableV1
		}
		expected.SourceBytes = b.SourceBytes
		expected.CanonicalBytes = b.CanonicalBytes
		expected.MemoryBytes = 4*b.SourceBytes + 16*b.CanonicalBytes + (8 << 20)
	case "fragment":
		if b.PackageBytes < ordinarypage.PackageHeaderBytesV1 || b.PackageBytes > ordinarypage.MaxPackageBytesV1 {
			return nil, workguard.ErrUnavailableV1
		}
		expected.PackageBytes = b.PackageBytes
		expected.MemoryBytes = 4*b.PackageBytes + 4*ordinarypage.MaxPDFBytesV1 + 4*ordinarypage.MaxPlanBytesV1 + (8 << 20)
	case "cold-fragment":
		if !workBoundV1(b.SourceBytes, ordinarypage.MaxPDFBytesV1) || !workBoundV1(b.PlanBytes, ordinarypage.MaxPlanBytesV1) {
			return nil, workguard.ErrUnavailableV1
		}
		expected.SourceBytes = b.SourceBytes
		expected.PlanBytes = b.PlanBytes
		expected.MemoryBytes = 4*(b.SourceBytes+b.PlanBytes) + (8 << 20)
	default:
		return nil, workguard.ErrUnavailableV1
	}
	if b != expected {
		return nil, workguard.ErrUnavailableV1
	}
	return a.acquire(ctx, b.OrgID, workguard.VectorV1{ParentBytes: expected.MemoryBytes})
}

// PDFWorkerV1 reserves the fixed Linux worker's 2GiB virtual-address ceiling,
// not its 384MiB GC target or measured RSS. Its owner releases only after that
// actual worker has returned and joined. Unknown physical work stays charged.
func (a *WorkAdmissionV1) PDFWorkerV1(ctx context.Context, b OrdinaryInspectionWorkerBudgetV1) (func(), error) {
	if b.OrgID == uuid.Nil || b.DocumentID == uuid.Nil || (b.Phase != "source" && b.Phase != "fragment") {
		return nil, workguard.ErrUnavailableV1
	}
	return a.acquire(ctx, b.OrgID, workguard.VectorV1{PDFWorkers: 1, ChildAddressBytes: 2 << 30})
}

// These separate physical-lifetime seams belong to the eventual full driver.
// Call BEFORE connection/stream/dispatch. Returning from a logical transaction
// or cancelling a request is insufficient retirement proof; retain the release
// until the actual session/stream/remote request has positively retired. Current
// application body adapters do not wire these seams or establish that proof.
func (a *WorkAdmissionV1) SQLSessionV1(ctx context.Context, org uuid.UUID) (func(), error) {
	return a.acquire(ctx, org, workguard.VectorV1{SQLSessions: 1})
}
func (a *WorkAdmissionV1) ProviderStreamV1(ctx context.Context, org uuid.UUID) (func(), error) {
	return a.acquire(ctx, org, workguard.VectorV1{ProviderStreams: 1})
}
func (a *WorkAdmissionV1) RendererRequestV1(ctx context.Context, org uuid.UUID) (func(), error) {
	return a.acquire(ctx, org, workguard.VectorV1{RendererRequests: 1})
}
