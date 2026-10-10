// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

func htmlPurgeFixture(t *testing.T) (*generated.Document, pgtype.Timestamptz) {
	t.Helper()
	doc, cutoff := protectedPurgeTestClaim()
	doc.TemplateID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.VariablesJson = []byte(`{}`)
	rebindHTMLPurgeFixture(t, doc)
	return doc, cutoff
}

func rebindHTMLPurgeFixture(t *testing.T, doc *generated.Document) {
	t.Helper()
	master, err := json.Marshal(htmlmaster.Master{SchemaVersion: 1, HTML: `<p>Approved inert contract</p>`})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(master, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson, err = htmlsource.New(htmlsource.Input{TemplateID: uuid.UUID(doc.TemplateID.Bytes), TemplateVersion: 1,
		TemplateContentSHA256: canonical.SHA256, MasterJSON: canonical.MasterJSON, DefaultVarsJSON: canonical.DefaultsJSON,
		TemplateApprovedBy: uuid.New(), TemplateApprovedAt: time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)}, doc)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHTMLSourcePurgeDeletesFreshTemplatedObjectByExactVersionBeforeRow(t *testing.T) {
	claim, cutoff := htmlPurgeFixture(t)
	if claim.HtmlReviewedBy.Valid {
		t.Fatal("fixture should prove unreviewed discarded drafts remain purgeable")
	}
	q := &protectedPurgeQueriesStub{doc: claim, fence: true, deleteRows: 1}
	objects := &purgeDeleterStub{}
	commits := 0
	q.deleteRow = func(context.Context) error {
		if objects.calls != 1 {
			t.Fatal("parent row deleted before fresh HTML source")
		}
		return nil
	}
	begin := func(context.Context) (softDeletePurgeTransaction, error) {
		return softDeletePurgeTransaction{queries: q, commit: func(context.Context) error { commits++; return nil }, rollback: func(context.Context) error { return nil }}, nil
	}
	rows, err := purgeClaimedSoftDeletedDocument(context.Background(), claim, cutoff, objects, begin)
	if err != nil || rows != 1 || commits != 1 || q.rowDeletes != 1 || objects.calls != 1 || objects.key != claim.PdfStorageKey.String || objects.version != claim.PdfStorageVersionID.String || !bytes.Equal(objects.digest, claim.PdfSha256) {
		t.Fatalf("HTML purge rows=%d commits=%d rowcalls=%d objects=%+v error=%v", rows, commits, q.rowDeletes, objects, err)
	}
}

func TestHTMLSourcePurgeInvalidProvenancePreservesRowAndObjectForReview(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"invalid JSON", func(d *generated.Document) { d.HtmlSourceJson = []byte(`{}`) }},
		{"JSON null", func(d *generated.Document) { d.HtmlSourceJson = []byte(`null`) }},
		{"changed variables", func(d *generated.Document) { d.VariablesJson = []byte(`{"unprinted":"value"}`) }},
		{"changed digest", func(d *generated.Document) { d.PdfSha256 = bytes.Repeat([]byte{1}, 32) }},
		{"changed version", func(d *generated.Document) { d.PdfStorageVersionID.String = "different-version" }},
		{"missing version", func(d *generated.Document) { d.PdfStorageVersionID.Valid = false }},
		{"missing template identity", func(d *generated.Document) { d.TemplateID.Valid = false }},
		{"changed source kind", func(d *generated.Document) { d.SourceKind = "blocks" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim, cutoff := htmlPurgeFixture(t)
			test.mutate(claim)
			q := &protectedPurgeQueriesStub{doc: claim, fence: true, deleteRows: 1}
			objects := &purgeDeleterStub{}
			commits := 0
			begin := func(context.Context) (softDeletePurgeTransaction, error) {
				return softDeletePurgeTransaction{queries: q, commit: func(context.Context) error { commits++; return nil }, rollback: func(context.Context) error { return nil }}, nil
			}
			rows, err := purgeClaimedSoftDeletedDocument(context.Background(), claim, cutoff, objects, begin)
			if !errors.Is(err, htmlsource.ErrInvalid) || rows != 0 || q.rowDeletes != 0 || objects.calls != 0 || commits != 0 {
				t.Fatalf("invalid provenance lost row/object: rows=%d rowcalls=%d objects=%d commits=%d error=%v", rows, q.rowDeletes, objects.calls, commits, err)
			}
			if _, err := purgeOwnedSourceVersion(claim); !errors.Is(err, htmlsource.ErrInvalid) {
				t.Fatalf("exact-version path skipped validation: %v", err)
			}
		})
	}
}

func TestHTMLSourcePurgeStillRequiresDocumentNamespaceAndVersionPin(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"foreign tenant namespace", func(d *generated.Document) {
			d.PdfStorageKey.String = "org/" + uuid.NewString() + "/documents/" + uuid.NewString() + ".pdf"
		}},
		{"shared template namespace", func(d *generated.Document) {
			d.PdfStorageKey.String = "org/" + d.OrgID.String() + "/templates/" + uuid.NewString() + ".pdf"
		}},
		{"malformed object UUID", func(d *generated.Document) {
			d.PdfStorageKey.String = "org/" + d.OrgID.String() + "/documents/not-a-uuid.pdf"
		}},
		{"missing evidence pin flag", func(d *generated.Document) { d.EvidenceVersionPinsRequired = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim, _ := htmlPurgeFixture(t)
			test.mutate(claim)
			rebindHTMLPurgeFixture(t, claim)
			objects := &purgeDeleterStub{}
			rowCalls := 0
			rows, err := cleanupClaimedSoftDeletedDocument(context.Background(), claim, objects, func(context.Context, *generated.Document) (int64, error) { rowCalls++; return 1, nil })
			if err == nil || rows != 0 || objects.calls != 0 || rowCalls != 0 {
				t.Fatalf("unsafe owned HTML source admitted: rows=%d objectcalls=%d rowcalls=%d error=%v", rows, objects.calls, rowCalls, err)
			}
		})
	}
}

func TestHTMLSourcePurgePreservesLegalAliasesAndLegacyTemplateSources(t *testing.T) {
	for _, alias := range []string{"final", "certificate", "audit payload", "audit signature", "legacy PDF template"} {
		t.Run(alias, func(t *testing.T) {
			claim, _ := htmlPurgeFixture(t)
			switch alias {
			case "final":
				claim.FinalPdfKey = claim.PdfStorageKey
			case "certificate":
				claim.AuditCertKey = claim.PdfStorageKey
			case "audit payload":
				claim.AuditPayloadKey = claim.PdfStorageKey
			case "audit signature":
				claim.AuditSignatureKey = claim.PdfStorageKey
			case "legacy PDF template":
				claim.HtmlSourceJson = nil
			}
			objects := &purgeDeleterStub{}
			rowCalls := 0
			rows, err := cleanupClaimedSoftDeletedDocument(context.Background(), claim, objects, func(context.Context, *generated.Document) (int64, error) { rowCalls++; return 1, nil })
			if err != nil || rows != 1 || rowCalls != 1 || objects.calls != 0 {
				t.Fatalf("shared/legal source deleted: rows=%d rowcalls=%d objectcalls=%d error=%v", rows, rowCalls, objects.calls, err)
			}
		})
	}
}

func TestHTMLSourcePurgeStorageFailureKeepsParentCleanupReference(t *testing.T) {
	claim, _ := htmlPurgeFixture(t)
	storageErr := errors.New("exact version deletion failed")
	objects := &purgeDeleterStub{err: storageErr}
	rowCalls := 0
	rows, err := cleanupClaimedSoftDeletedDocument(context.Background(), claim, objects, func(context.Context, *generated.Document) (int64, error) { rowCalls++; return 1, nil })
	if !errors.Is(err, storageErr) || rows != 0 || rowCalls != 0 || objects.calls != 1 {
		t.Fatalf("failed deletion lost cleanup parent: rows=%d rowcalls=%d objectcalls=%d error=%v", rows, rowCalls, objects.calls, err)
	}
}
