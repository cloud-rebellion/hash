//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

func TestHTMLAuthoringFreshReadsReuseOwnedPreparedTemplateE2E(t *testing.T) {
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
	var first, second pdfadmission.HTMLAuthoringPreparedRetainedTemplateV1
	var before htmlmaster.Result
	err = owner.session.WithTxV1(ctx, func(ctx context.Context, _ generated.DBTX) error {
		if _, _, err := owner.reader.ReadTemplateRevisionV1(ctx, template.ID, template.Version); err != nil {
			return err
		}
		canonical, err := owner.reader.CanonicalRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		// The unchanged pure helpers are the semantic oracle at the original point.
		originalMaster, err := htmlmaster.Decode(canonical.MasterJSON)
		if err != nil {
			return err
		}
		originalCompiled, err := htmlmaster.Compile(originalMaster)
		if err != nil {
			return err
		}
		var originalDefaults map[string]string
		if err = json.Unmarshal(canonical.DefaultsJSON, &originalDefaults); err != nil {
			return err
		}
		first, err = owner.reader.PreparedRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		before, err = originalCompiled.Materialize(htmlmaster.Input{Values: originalDefaults})
		if err != nil {
			return err
		}
		actual, err := first.Compiled.Materialize(htmlmaster.Input{Values: first.Defaults})
		if err != nil {
			return err
		}
		if actual.HTML != before.HTML || actual.ContentDigest != before.ContentDigest || !maps.Equal(first.Defaults, originalDefaults) || !slices.Equal(first.Values, originalMaster.Values) {
			t.Fatal("prepared result differs from unchanged original helpers")
		}
		first.Defaults["customer"] = "mutated returned defaults"
		first.Values[0].Name = "mutated_returned_definition"
		canonical.MasterJSON[0] = '['
		current, revision, err := owner.reader.ReadTemplateRevisionV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		// Actual SQL just read these independently charged rows; public mutation
		// cannot change the fixed snapshot selected for private exact-input reuse.
		current.HtmlMasterJson[0] = '['
		revision.HtmlMasterJson[0] = '['
		revision.ContentSha256[0] ^= 255
		again, err := owner.reader.CanonicalRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		second, err = owner.reader.PreparedRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		if second.Compiled != first.Compiled || !maps.Equal(second.Defaults, originalDefaults) || !slices.Equal(second.Values, originalMaster.Values) || !bytes.Equal(again.MasterJSON, originalCompiled.CanonicalJSON()) {
			t.Fatal("fresh exact read reran/replaced original immutable prepared result")
		}
		if _, err = owner.reader.CanonicalRetainedTemplateV1(ctx, template.ID, template.Version); !errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
			t.Fatalf("direct canonical replay accepted: %v", err)
		}
		if _, err = owner.reader.PreparedRetainedTemplateV1(ctx, template.ID, template.Version); !errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
			t.Fatalf("direct prepared replay accepted: %v", err)
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
	if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers < 1 {
		t.Fatalf("actual SQL retirement refunded live prepared consumers: %+v", pending)
	}
	if second.Compiled.Digest() != before.MasterDigest {
		t.Fatal("real prepared result lost after SQL join")
	}
	// End all actual test/result uses before closing the real route consumer.
	first = pdfadmission.HTMLAuthoringPreparedRetainedTemplateV1{}
	second = pdfadmission.HTMLAuthoringPreparedRetainedTemplateV1{}
	before = htmlmaster.Result{}
	owner.closeConsumerV1(ctx)
	if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers != 0 {
		t.Fatalf("finished prepared consumers retained: %+v", pending)
	}
}
