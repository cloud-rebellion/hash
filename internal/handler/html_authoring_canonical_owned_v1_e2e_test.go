//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

func TestHTMLAuthoringCanonicalUsesActualImmutableNativeModelsE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	ctx, cancel := context.WithTimeout(f.ctx, authoring.MutationTimeout)
	defer cancel()
	o, err := f.s.openHTMLAuthoringV1(ctx, f.org, template.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer o.closeConsumerV1(ctx)
	defer o.closeSQLV1(ctx)
	var canonical []byte
	err = o.session.WithTxV1(ctx, func(ctx context.Context, _ generated.DBTX) error {
		current, revision, err := o.reader.ReadTemplateRevisionV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		// Mutable public DB models cannot replace the already captured source.
		current.HtmlMasterJson[0] = 91
		revision.HtmlMasterJson[0] = 91
		current.HtmlContentSha256[0] ^= 255
		revision.ContentSha256[0] ^= 255
		content, err := o.reader.CanonicalCurrentTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		if content.SHA256 != hex.EncodeToString(template.HtmlContentSha256) || len(content.MasterJSON) == 0 || content.MasterJSON[0] != 123 {
			t.Fatal("actual immutable stored source/SHA changed")
		}
		canonical = content.MasterJSON
		if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers != 1 {
			t.Fatalf("actual model producer not retained: %+v", pending)
		}
		if _, err := o.reader.CanonicalCurrentTemplateV1(ctx, template.ID, template.Version); !errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
			t.Fatalf("one-shot producer repeated: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = o.session.CommitV1(ctx); err != nil {
		t.Fatal(err)
	}
	if err = o.closeSQLV1(ctx); err != nil {
		t.Fatal(err)
	}
	if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers != 1 {
		t.Fatalf("SQL retirement refunded live canonical result: %+v", pending)
	}
	if len(canonical) == 0 || canonical[0] != 123 {
		t.Fatal("retained canonical result lost after real SQL close")
	}
	o.closeConsumerV1(ctx)
	if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers != 0 {
		t.Fatalf("finished native source consumer remained: %+v", pending)
	}
}
