// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are private schema/resource and native-consumer lifetime unit checks.
// They grant no PostgreSQL authority and are not provider/Send acceptance.
func TestPackageSendAuditBatchExactShapesV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, mode := range []string{"101 actual invitation shapes", "retained expiry shapes", "unstarted abort shape"} {
		t.Run(mode, func(t *testing.T) {
			g := &applicationPackageSendAuditBatchV1{ip: "127.0.0.1", attemptText: uuid.NewString(), packageText: uuid.NewString(), revisionText: "7", manifestText: strings.Repeat("a", 64), commitmentText: strings.Repeat("b", 64), basis: "contract", retainText: "2031-01-01T00:00:00Z", noticeText: "2026-10-18T12:00:00.123456Z"}
			switch mode {
			case "101 actual invitation shapes":
				g.recipientCount, g.eventCount = 101, 102
				g.work = &ApplicationHTMLSendWorkV1{sourceRecipients: make([]*generated.Recipient, 101)}
				for i := range g.work.sourceRecipients {
					g.work.sourceRecipients[i] = &generated.Recipient{ID: uuid.New(), Email: "party@example.test", Role: "signer"}
				}
			case "retained expiry shapes":
				g.noInvite, g.eventCount = true, 2
			case "unstarted abort shape":
				g.aborting, g.eventCount = true, 1
			}
			var total htmlAuditShapeV1
			var parent, db int64
			for i := 0; i < g.eventCount; i++ {
				purpose, recipient, shape, err := g.shapeV1(ctx, i)
				if err != nil {
					t.Fatal(err)
				}
				actual, actualRecipient, keys, values, n, err := g.fieldsV1(i)
				if err != nil || purpose != actual || recipient != actualRecipient {
					t.Fatal("fixed field identity differs", err)
				}
				payload := make(map[string]any, n)
				for j := 0; j < n; j++ {
					payload[keys[j]] = values[j]
				}
				native, err := htmlAuditPayloadShapeV1(ctx, purpose, payload)
				if err != nil {
					t.Fatal(err)
				}
				for _, text := range [...]string{purpose.KindV1(), g.ip, ""} {
					if err = native.text(text, false); err != nil {
						t.Fatal(err)
					}
				}
				if err = native.add(192, 4096, 16); err != nil || native != shape {
					t.Fatal("private schema differs from native event accounting", err, native, shape)
				}
				each, err := htmlAuditResourcesV1(shape.raw, shape.wire, shape.nodes)
				if err != nil {
					t.Fatal(err)
				}
				parent += each.WorkingBytes
				db += each.DBStagingBytes
				if err = total.add(shape.raw, shape.wire, shape.nodes); err != nil {
					t.Fatal(err)
				}
			}
			resources, err := packageSendAuditBatchResourcesV1(int64(g.eventCount), total.raw, total.wire, total.nodes)
			controls := 2*int64(unsafe.Sizeof(applicationPackageSendAuditBatchV1{})) + 2*int64(g.eventCount)*int64(unsafe.Sizeof(applicationPackageSendAuditSlotV1{}))
			if err != nil || resources.WorkingBytes != parent+controls || resources.DBStagingBytes != db {
				t.Fatal("aggregate changed original per-event costs", err, resources, parent, db, controls)
			}
		})
	}
}
func TestPackageSendAuditBatchResourceOverflowRefusesV1(t *testing.T) {
	for _, input := range [][4]int64{{0, 0, 0, 0}, {-1, 1, 2, 1}, {math.MaxInt64, 0, math.MaxInt64, math.MaxInt64}, {2, math.MaxInt64, 4, 2}, {2, 0, math.MaxInt64, 2}, {2, 0, 4, math.MaxInt64}} {
		if _, err := packageSendAuditBatchResourcesV1(input[0], input[1], input[2], input[3]); err == nil {
			t.Fatal("overflow or invalid aggregate was admitted", input)
		}
	}
}
func TestPackageSendAuditBatchPublishedChildOwnsLoanV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	h := &ApplicationSessionV1{state: &applicationOwnedSessionV1{}}
	ctx = context.WithValue(ctx, applicationSessionCallbackKeyV1{}, h.state)
	closed := 0
	g := &applicationPackageSendAuditBatchV1{session: h, callbackDone: ctx.Done(), actor: pgtype.UUID{Bytes: uuid.New(), Valid: true}, ip: "127.0.0.1", opening: true, active: 1, close: func() { closed++ }, work: &ApplicationHTMLSendWorkV1{}, plan: &applicationPackageSendRetentionPlanV1{}, intent: &generated.SendSealingIntent{}, eventCount: 1}
	g.self = g
	g.budget = ApplicationBudgetV1{OrgID: uuid.New(), DocumentID: uuid.New()}
	g.slots = make([]applicationPackageSendAuditSlotV1, 1)
	slot := &g.slots[0]
	*slot = applicationPackageSendAuditSlotV1{batch: g, index: 0, purpose: HTMLAuditPackageDocumentSentV1, shape: htmlAuditShapeV1{raw: 1, wire: 2, nodes: 1}, ready: true}
	slot.self = slot
	copied := *slot
	if _, err := copied.acquireV1(ctx, h, slot.purpose, g.budget.OrgID, g.budget.DocumentID, pgtype.UUID{}, g.actor, slot.purpose.KindV1(), g.ip, "", slot.shape); err == nil || g.opened != 0 {
		t.Fatal("copied private slot minted a child")
	}
	forged := *slot
	forged.self = &forged
	if _, err := forged.acquireV1(ctx, h, slot.purpose, g.budget.OrgID, g.budget.DocumentID, pgtype.UUID{}, g.actor, slot.purpose.KindV1(), g.ip, "", slot.shape); err == nil || g.opened != 0 {
		t.Fatal("unregistered private slot minted a child")
	}
	childClose, err := slot.acquireV1(ctx, h, slot.purpose, g.budget.OrgID, g.budget.DocumentID, pgtype.UUID{}, g.actor, slot.purpose.KindV1(), g.ip, "", slot.shape)
	if err != nil || g.opened != 1 {
		t.Fatal("original private child bookkeeping failed", err)
	}
	owner := &ApplicationHTMLAuditEventConsumerV1{closeConsumer: childClose, published: true, payload: map[string]any{"actual_lifetime_unit": "still borrowed"}}
	owner.self = owner
	slot.owner = owner
	g.closeConsumerV1()
	cancel()
	if closed != 0 || g.released || g.opened != 1 || owner.closed {
		t.Fatal("request close/cancel retired an active published child")
	}
	g.mu.Lock()
	g.active--
	closeLoan := g.releaseIfCompleteV1()
	detached := g.work == nil && g.plan == nil && g.intent == nil
	g.mu.Unlock()
	if closeLoan != nil || closed != 0 || !detached {
		t.Fatal("plan lifetime was used as published-child retirement")
	}
	owner.mu.Lock()
	owner.publicationDone = true
	owner.mu.Unlock()
	owner.CloseConsumerV1()
	if closed != 1 || !g.released || g.opened != 0 || g.slots != nil {
		t.Fatal("actual native child last use did not close aggregate consumer", closed, g.opened)
	}
	owner.CloseConsumerV1()
	g.closeConsumerV1()
	childClose()
	if closed != 1 {
		t.Fatal("copied/repeated close credited aggregate twice", closed)
	}
}
