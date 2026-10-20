//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

// Actual native/global process owner + original fixed50 SQL oracle. The
// synthetic blocks rows exercise only recovery discovery, not unsupported
// native block-Send or a legal contract/signing acceptance claim.
func TestHTMLSendRecoveryScopesUseActualGlobalNativeOwnerE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	ctx, cancel := context.WithTimeout(f.ctx, 30*time.Second)
	defer cancel()
	for i := 0; i < 51; i++ {
		doc, err := f.q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Recovery scope " + uuid.NewString(), BlocksJson: []byte("{\"version\":1,\"blocks\":[]}"), VariablesJson: []byte("{}")})
		if err != nil {
			t.Fatal(err)
		}
		email := "bounded@example.test"
		if i == 0 {
			email = strings.Repeat("x", 256<<10)
		}
		if _, err = f.q.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{DocumentID: doc.ID, OrgID: f.org, ActorEmail: email, Via: "worker"}); err != nil {
			t.Fatal(err)
		}
		// Seed the same complete effective theme that genuine Send freezes before
		// leaving draft; discovery must not bypass the canonical sealing guard.
		theme, err := f.q.GetHTMLSendBrandingInputHeaderV1(ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: doc.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.q.FreezeHTMLSendBrandingV1(ctx, htmlSendFreezeFixtureV1(theme)); err != nil {
			t.Fatal(err)
		}
		frozen, err := f.q.GetDocumentBrandingOverride(ctx, doc.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err = branding.ValidateFrozenSnapshot(doc.ID, frozen); err != nil {
			t.Fatal("canonical recovery fixture branding", err)
		}
		if _, err = f.q.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: doc.ID, OrgID: f.org}); err != nil {
			t.Fatal(err)
		}
	}
	// The unchanged original full-row method is fixture oracle only. The native
	// application query itself fetches exactly two UUIDs and never these TEXTs.
	original, err := f.q.ListPendingSendSealingIntents(ctx, 50)
	if err != nil || len(original) != 50 {
		t.Fatalf("original fixed50 oracle: count=%d err=%v", len(original), err)
	}
	factory := f.s.HTMLCreationSessions
	scan, err := factory.ScanPendingHTMLSendRecoveryScopesV1(ctx)
	if scan != nil {
		defer scan.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := scan.ScopesV1()
	if err != nil || len(scopes) != 50 {
		t.Fatalf("native scopes count=%d err=%v", len(scopes), err)
	}
	for i, scope := range scopes {
		if scope.DocumentID != original[i].DocumentID || scope.OrgID != original[i].OrgID {
			t.Fatalf("original complete order diverged at %d", i)
		}
	}
	copyShell := *scan
	if _, err = copyShell.ScopesV1(); !errors.Is(err, pdfadmission.ErrHTMLSendWorkV1) {
		t.Fatalf("copied scope shell replay accepted: %v", err)
	}
	pending := factory.PendingV1()
	before := htmlAuthoringNativeSnapshotE2E(t, f.s)
	if pending.HTMLSendRecoveryScans != 1 || pending.WorkSessions != 0 || pending.ObserverSessions != 1 || before.Global.ParentBytes <= 0 || before.Global.DBStagingBytes <= 0 || before.Global.SQLSessions != 1 || before.Organisation != (workguard.VectorV1{}) || before.OrganisationGrants != 0 {
		t.Fatalf("process owner/retained consumer wrong: pending=%+v snapshot=%+v", pending, before)
	}
	if err = factory.CloseV1(ctx); !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
		t.Fatalf("live recovery consumer falsely retired: %v", err)
	}
	if after := htmlAuthoringNativeSnapshotE2E(t, f.s); after.Global != before.Global || after.GlobalGrants != before.GlobalGrants {
		t.Fatalf("factory shutdown credited live scope consumer: before=%+v after=%+v", before, after)
	}
	// Clear the sole actual view before signalling its real final consumer.
	scopes = nil
	copyShell.CloseConsumerV1()
	scan.CloseConsumerV1()
	after := htmlAuthoringNativeSnapshotE2E(t, f.s)
	if factory.PendingV1().HTMLSendRecoveryScans != 0 || after.Global != (workguard.VectorV1{SQLSessions: 1}) || after.GlobalGrants != 1 || after.Organisation != (workguard.VectorV1{}) {
		t.Fatalf("process scope loan leak/lost final observer: %+v pending=%+v", after, factory.PendingV1())
	}
	if _, err = factory.ScanPendingHTMLSendRecoveryScopesV1(ctx); !errors.Is(err, pdfadmission.ErrHTMLSendWorkV1) {
		t.Fatalf("closed factory scan accepted: %v", err)
	}
}
