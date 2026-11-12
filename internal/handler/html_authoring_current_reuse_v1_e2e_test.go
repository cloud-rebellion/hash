//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

func TestHTMLAuthoringPairedCurrentReusesChargedRetainedCanonicalE2E(t *testing.T) {
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
	var currentContent htmlmaster.TemplateCommitment
	var prepared pdfadmission.HTMLAuthoringPreparedRetainedTemplateV1
	err = owner.session.WithTxV1(ctx, func(ctx context.Context, _ generated.DBTX) error {
		// Both genuine SQL source entries precede either producer. Registration-
		// time cache lookup alone cannot optimize this actual paired read.
		current, revision, err := owner.reader.ReadTemplateRevisionV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		retained, err := owner.reader.CanonicalRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		master, defaults := bytes.Clone(retained.MasterJSON), bytes.Clone(retained.DefaultsJSON)
		before := htmlAuthoringNativeSnapshotE2E(t, f.s)
		if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers != 1 {
			t.Fatalf("original retained producer not held: %+v", pending)
		}
		// Neither exposed result bytes nor mutable public SQL models can replace
		// the two already-captured private source snapshots or canonical result.
		retained.MasterJSON[0], retained.DefaultsJSON[0] = '[', '['
		current.HtmlMasterJson[0], revision.HtmlMasterJson[0] = '[', '['
		current.HtmlContentSha256[0] ^= 255
		revision.ContentSha256[0] ^= 255
		currentContent, err = owner.reader.CanonicalCurrentTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		after := htmlAuthoringNativeSnapshotE2E(t, f.s)
		orgCopy := after.Organisation.ParentBytes - before.Organisation.ParentBytes
		globalCopy := after.Global.ParentBytes - before.Global.ParentBytes
		if orgCopy <= 0 || orgCopy >= 1<<20 || globalCopy != orgCopy || after.GlobalGrants != before.GlobalGrants+1 || after.OrganisationGrants != before.OrganisationGrants+1 {
			t.Fatalf("CURRENT did not acquire a separate small copy loan: before=%+v after=%+v", before, after)
		}
		if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers != 2 {
			t.Fatalf("copy reused/refunded original producer ownership: %+v", pending)
		}
		if !bytes.Equal(currentContent.MasterJSON, master) || !bytes.Equal(currentContent.DefaultsJSON, defaults) || currentContent.SHA256 != hex.EncodeToString(template.HtmlContentSha256) {
			t.Fatal("CURRENT adopted mutated public bytes or changed exact content pins")
		}
		if _, err = owner.reader.CanonicalCurrentTemplateV1(ctx, template.ID, template.Version); !errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
			t.Fatalf("CURRENT one-delivery producer replay accepted: %v", err)
		}
		prepared, err = owner.reader.PreparedRetainedTemplateV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		if prepared.Compiled == nil || !bytes.Equal(prepared.Compiled.CanonicalJSON(), master) {
			t.Fatal("CURRENT copy replaced original retained preparation")
		}
		// A new real read exercises the reordered production DTO helper and its
		// original version/digest/approval checks, rather than only native methods.
		current, revision, err = owner.reader.ReadTemplateRevisionV1(ctx, template.ID, template.Version)
		if err != nil {
			return err
		}
		detail, err := toHTMLTemplateDetailResponseOwnedV1(ctx, owner.reader, current, revision)
		if err != nil {
			return err
		}
		if detail.HTMLApproval == nil || detail.HTMLApproval.Version != template.Version || detail.HTMLApproval.ContentSHA256 != currentContent.SHA256 || !bytes.Equal(detail.HTMLMasterJSON, master) {
			t.Fatal("paired detail changed canonical output or exact approval pins")
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
	if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers != 5 {
		t.Fatalf("SQL close refunded live canonical consumers: %+v", pending)
	}
	if snapshot := htmlAuthoringNativeSnapshotE2E(t, f.s); snapshot.Organisation.ParentBytes <= 32<<20 {
		t.Fatalf("original preparation charge retired before consumer close: %+v", snapshot)
	}
	if currentContent.MasterJSON[0] != '{' || prepared.Compiled == nil {
		t.Fatal("actual returned consumers lost after SQL close")
	}
	currentContent = htmlmaster.TemplateCommitment{}
	prepared = pdfadmission.HTMLAuthoringPreparedRetainedTemplateV1{}
	owner.closeConsumerV1(ctx)
	if pending := f.s.HTMLCreationSessions.PendingV1(); pending.HTMLCanonicalConsumers != 0 {
		t.Fatalf("closed canonical consumers retained: %+v", pending)
	}
	if snapshot := htmlAuthoringNativeSnapshotE2E(t, f.s); snapshot.Organisation.ParentBytes != 0 || snapshot.Organisation.DBStagingBytes != 0 {
		t.Fatalf("consumer close retained body/canonical loans: %+v", snapshot)
	}
}
