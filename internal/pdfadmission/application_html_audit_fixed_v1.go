// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These concrete capture inventories follow WithPreparedV1, ownedaudit.LogV1
// and BeginPublicationV1/PublishJoinedV1. They are finite retained logical
// source/control estimates, not compiler closure layout or measured heap/RSS.
// Dynamic maps/strings/Marshal/hash/pgx/DB demand remain in the original
// 16raw+32wire+256nodes and16wire terms. Hook fanout execution/transport slots
// remain the separate downstream responsibility already stated by audit.Logger;
// the original payload consumer remains until ALL real hooks have joined.
type htmlAuditAppendCaptureInventoryV1 struct {
	Owner    *ApplicationHTMLAuditEventConsumerV1
	Context  context.Context
	Mutex    *sync.Mutex
	Active   *bool
	Previous []byte
	Stamp    pgtype.Timestamptz
}
type htmlAuditLogCaptureInventoryV1 struct {
	Entry   audit.Entry
	Pending *audit.PendingEvent
}
type htmlAuditPublishCaptureInventoryV1 struct {
	Owner     *ApplicationHTMLAuditEventConsumerV1
	Entry     audit.Entry
	EventID   uuid.UUID
	Remaining *atomic.Int64
	LastUse   func()
}
type htmlAuditFixedComponentV1 struct {
	Name  string
	Bytes int64
}

// Actual bounded record/capture/header inventory. No historical Event payload
// is loaded by the chain-head query: its real scalar row is explicitly listed.
// The checked existing Go64 allocation/rounding helper is reused; this does
// not introduce a new allocator model, input limit or runtime profile.
func htmlAuditFixedComponentsV1() [20]htmlAuditFixedComponentV1 {
	return [20]htmlAuditFixedComponentV1{
		{"native event consumer", int64(unsafe.Sizeof(ApplicationHTMLAuditEventConsumerV1{}))},
		{"two prepared borrows", 2 * int64(unsafe.Sizeof(ApplicationHTMLAuditPreparedV1{}))},
		{"three detached audit entries", 3 * int64(unsafe.Sizeof(audit.Entry{}))},
		{"three pending event values", 3 * int64(unsafe.Sizeof(audit.PendingEvent{}))},
		{"scalar owned chain head and scan", 2 * int64(unsafe.Sizeof(generated.GetOwnedHTMLAuditChainHeadV1Row{}))},
		{"two identity insert parameters", 2 * int64(unsafe.Sizeof(generated.InsertEventIdentityV1Params{}))},
		{"payload measurement parameters", int64(unsafe.Sizeof(generated.MeasureHTMLSnapshotEventPayloadV1Params{}))},
		{"actual payload measurement receipt", int64(unsafe.Sizeof(generated.HtmlSnapshotEventPayloadSizesV1{}))},
		{"actual hash input", int64(unsafe.Sizeof(audit.HashInput{}))},
		{"native budget and loan", int64(unsafe.Sizeof(ApplicationBudgetV1{})) + int64(unsafe.Sizeof(applicationLoanV1{}))},
		{"append closure captures and working copy", 2 * int64(unsafe.Sizeof(htmlAuditAppendCaptureInventoryV1{}))},
		{"logger closure captures and working copy", 2 * int64(unsafe.Sizeof(htmlAuditLogCaptureInventoryV1{}))},
		{"publication captures and working copy", 2 * int64(unsafe.Sizeof(htmlAuditPublishCaptureInventoryV1{}))},
		{"finite function value headers", 8 * int64(unsafe.Sizeof((func())(nil)))},
		{"query argument interface slots", 2 * 16 * int64(unsafe.Sizeof(any(nil)))},
		{"slice and interface headers", 8*int64(unsafe.Sizeof([]byte(nil))) + 8*int64(unsafe.Sizeof(any(nil)))},
		{"detached scalar identities", 8 * int64(unsafe.Sizeof(uuid.UUID{}))},
		{"parsed address and finite timestamps", int64(unsafe.Sizeof(netip.Addr{})) + 2*int64(unsafe.Sizeof(pgtype.Timestamptz{}))},
		{"append and publication controls", 2*int64(unsafe.Sizeof(sync.Mutex{})) + 2*int64(unsafe.Sizeof(sync.Once{})) + int64(unsafe.Sizeof(atomic.Int64{}))},
		{"fixed digest results", 4 * int64(unsafe.Sizeof([sha256.Size]byte{}))},
	}
}
func htmlAuditFixedResourcesV1() (int64, error) {
	total := int64(0)
	for _, component := range htmlAuditFixedComponentsV1() {
		if component.Name == "" || component.Bytes <= 0 || !htmlStoredRetentionAllocV1(&total, component.Bytes) {
			return 0, ErrHTMLAuditEventV1
		}
	}
	fixed, err := htmlStoredRetentionFinishV1(total)
	if err != nil || fixed < 1 {
		return 0, ErrHTMLAuditEventV1
	}
	return fixed, nil
}
