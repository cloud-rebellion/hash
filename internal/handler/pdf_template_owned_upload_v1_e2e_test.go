//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

// Actual migrated PG/native runtime/restricted PDF worker. Synthetic S3
// protocol peer only; no provider Object Lock or production capacity claim.
// The target cache is born exclusively from the actual upload INSERT owner.
func TestOwnedPDFTemplateFreshUploadNativeSourceE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	peer := &importStoragePeer{objects: make(map[string][]byte)}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	var err error
	q.f.s.Storage, err = storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-owned-template", SecretKey: "synthetic-owned-template-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	hook := newOwnedPlainAuditGateV1(audit.KindTemplateCreated)
	t.Cleanup(hook.unblock)
	q.f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
		if e.Kind != audit.KindTemplateCreated {
			return
		}
		hook.eventID = id
		hook.entry = e
		close(hook.started)
		<-hook.release
		close(hook.returned)
	})
	request := ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Actual clean source for reusable PDF template"))
	request.URL.Path = "/api/v1/templates"
	request.RequestURI = request.URL.Path
	response := newOwnedPlainResponseGateV1()
	t.Cleanup(response.unblock)
	done := make(chan struct{})
	go func() { defer close(done); q.f.s.Routes().ServeHTTP(response, request) }()
	ownedPlainAwaitV1(t, response.started, "actual template response")
	ownedPlainAwaitV1(t, hook.started, "actual org-only template audit hook")
	id, ok := hook.entry.Payload["template_id"].(uuid.UUID)
	if !ok || id == uuid.Nil || hook.eventID == uuid.Nil || hook.entry.OrgID != q.f.org || hook.entry.DocumentID != nil || hook.entry.RecipientID != nil || hook.entry.ActorUserID == nil || *hook.entry.ActorUserID != q.f.user.ID {
		t.Fatal("actual template audit scope/payload changed")
	}
	var exact bool
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT t.source_kind='pdf' AND t.created_by=$3
  AND c.org_id=t.org_id AND c.source_kind=t.source_kind AND c.template_created_at=t.created_at AND c.template_updated_at=t.updated_at AND c.template_version=t.version
  AND c.master_wire_bytes=COALESCE(octet_length(t.html_master_json::text),0)
  AND c.blocks_wire_bytes=COALESCE(octet_length(t.blocks_json::text),0)
  AND c.variables_wire_bytes=octet_length(t.variables_json::text)
  AND c.fields_wire_bytes=octet_length(t.fields_json::text)
  AND c.sanitization_wire_bytes=octet_length(t.pdf_sanitization_report::text)
  AND c.measurement_server_version_num=current_setting('server_version_num')::integer
  AND t.evidence_version_pin_required AND t.pdf_storage_version_id='import-version-1' AND length(t.pdf_sha256)=32
  FROM templates t JOIN pdf_template_source_sizes_v1 c ON c.template_id=t.id WHERE t.id=$1 AND t.org_id=$2`, id, q.f.org, q.f.user.ID).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("actual template upload did not create exact genuine M97", err)
	} //nolint:rawsql -- exact fresh uploaded source/cache oracle only
	ownedPlainAssertRetainedV1(t, q, "template response and joined hook")
	response.unblock()
	ownedPlainAwaitV1(t, done, "template response last use")
	if response.Code != 201 {
		t.Fatalf("actual native upload=%d %s", response.Code, response.Body.String())
	}
	ownedPlainAssertRetainedV1(t, q, "template hook after response last use")
	hook.unblock()
	ownedPlainAwaitV1(t, hook.returned, "template hook actual return")
	ownedCreationAssertDrainedV1(t, q, 1)
	assertImportStorageE2E(t, peer, 1, 0, 1)

	read := func() error {
		native, err := q.runtime.SessionsV1().OpenV1(q.f.ctx, q.f.org, uuid.New())
		if err != nil {
			return err
		}
		admission, err := native.NewAdmissionV1(q.f.ctx)
		if err != nil {
			_ = native.CloseV1(q.f.ctx)
			return err
		}
		var source *pdfadmission.ApplicationPDFTemplateSourceV1
		var reader *pdfadmission.ApplicationHTMLAuthoringReaderV1
		defer func() {
			if source != nil {
				source.CloseConsumerV1()
				source.CloseConsumerV1()
			}
			if reader != nil {
				reader.CloseConsumerV1()
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := native.CloseV1(cleanup); err != nil {
				t.Error(err)
			}
			if err := native.CloseV1(cleanup); err != nil {
				t.Error(err)
			}
			_, _ = admission.ReconcileCleanupV1(cleanup)
		}()
		return native.WithTxV1(q.f.ctx, func(call context.Context, _ generated.DBTX) error {
			var err error
			reader, err = native.NewHTMLAuthoringReaderV1(call)
			if err != nil {
				return err
			}
			source, err = native.NewPDFTemplateSourceV1(call, reader)
			if err != nil {
				return err
			}
			tpl, err := source.GetTemplateForShare(call, generated.GetTemplateForShareParams{ID: id, OrgID: q.f.org})
			if err != nil {
				return err
			}
			if tpl == nil || tpl.ID != id || tpl.SourceKind != "pdf" || len(tpl.PdfSanitizationReport) == 0 {
				return errors.New("native source returned a different actual template")
			}
			return nil
		})
	}
	if err := read(); err != nil {
		t.Fatal("genuine fresh template cannot be read natively", err)
	}
	ownedCreationAssertDrainedV1(t, q, 1)
	if tag, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM pdf_template_source_sizes_v1 WHERE template_id=$1 AND org_id=$2", id, q.f.org); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("delete exact actual cache for negative read", err)
	} //nolint:rawsql -- negative deletion only, never measurement insertion/repair
	if err := read(); !errors.Is(err, pdfadmission.ErrPDFTemplateSourceV1) {
		t.Fatal("missing genuine template cache did not refuse", err)
	}
	ownedCreationAssertDrainedV1(t, q, 1)
	var count int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM pdf_template_source_sizes_v1 WHERE template_id=$1 AND org_id=$2", id, q.f.org).Scan(&count); err != nil || count != 0 {
		t.Fatal("native normal read repaired missing template cache", err)
	} //nolint:rawsql -- continued exact absence witness
}
