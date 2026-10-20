//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"maps"
	"testing"
)

func TestHTMLAuthoringRecheckProfileDoesNotPromotePreparationCreditE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	ctx, cancel := context.WithTimeout(f.ctx, authoring.MutationTimeout)
	defer cancel()
	owner, err := f.s.openHTMLAuthoringV1(ctx, f.org, template.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.closeConsumerV1(ctx)
	defer owner.closeSQLV1(ctx)
	var first, second, third pdfadmission.HTMLAuthoringPreparedRetainedTemplateV1
	err = owner.session.WithTxV1(ctx, func(ctx context.Context, _ generated.DBTX) error {
		if _, _, err := owner.reader.ReadTemplateRevisionV1(ctx, template.ID, template.Version); err != nil {
			return err
		}
		check, err := owner.reader.CanonicalRetainedTemplateRecheckV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		first, err = owner.reader.PreparedRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		if _, err = owner.reader.CanonicalRetainedTemplateV1(ctx, template.ID, template.Version); !errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
			t.Fatalf("same-entry purpose upgrade replay accepted: %v", err)
		}
		// Only another genuine exact SQL read creates another one-delivery input.
		if _, _, err = owner.reader.ReadTemplateRevisionV1(ctx, template.ID, template.Version); err != nil {
			return err
		}
		before := htmlAuthoringNativeSnapshotE2E(t, f.s)
		full, err := owner.reader.CanonicalRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		after := htmlAuthoringNativeSnapshotE2E(t, f.s)
		// A fresh full producer acquires its own scratch and retained outputs;
		// it cannot adopt the earlier lower recheck credit. Its complete reservation
		// exceeds this threshold. Original recheck consumers stay held.
		if after.Organisation.ParentBytes-before.Organisation.ParentBytes <= 32<<20 {
			t.Fatalf("fresh full request adopted lower recheck credit: before=%+v after=%+v", before, after)
		}
		second, err = owner.reader.PreparedRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		if !bytes.Equal(check.MasterJSON, full.MasterJSON) || check.SHA256 != full.SHA256 || first.Compiled != second.Compiled || !maps.Equal(first.Defaults, second.Defaults) {
			t.Fatal("fixed profile changed immutable content/prepared identity")
		}
		if _, _, err = owner.reader.ReadTemplateRevisionV1(ctx, template.ID, template.Version); err != nil {
			return err
		}
		before = htmlAuthoringNativeSnapshotE2E(t, f.s)
		again, err := owner.reader.CanonicalRetainedTemplateRecheckV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		after = htmlAuthoringNativeSnapshotE2E(t, f.s)
		if delta := after.Organisation.ParentBytes - before.Organisation.ParentBytes; delta <= 0 || delta >= 1<<20 {
			t.Fatalf("full-to-recheck reuse did not price only tiny defensive projection: %d", delta)
		}
		third, err = owner.reader.PreparedRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		if !bytes.Equal(again.MasterJSON, full.MasterJSON) || third.Compiled != first.Compiled || !maps.Equal(third.Defaults, second.Defaults) {
			t.Fatal("fresh lower-purpose reuse changed exact prepared result")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.session.CommitV1(ctx); err != nil {
		t.Fatal(err)
	}
	if err = owner.closeSQLV1(ctx); err != nil {
		t.Fatal(err)
	}
	if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers == 0 {
		t.Fatalf("actual SQL retirement refunded live profile consumers: %+v", pending)
	}
	first = pdfadmission.HTMLAuthoringPreparedRetainedTemplateV1{}
	second = pdfadmission.HTMLAuthoringPreparedRetainedTemplateV1{}
	third = pdfadmission.HTMLAuthoringPreparedRetainedTemplateV1{}
	owner.closeConsumerV1(ctx)
	if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers != 0 {
		t.Fatalf("finished profile consumers retained: %+v", pending)
	}
}
