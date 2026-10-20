//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/packageauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func packageLayoutArguments226(t *testing.T, v pdfadmission.DocumentPackageInventoryV1, transport string, members []pdfadmission.DocumentPackageInventoryMemberV1) string {
	t.Helper()
	rows := make([]map[string]any, len(members))
	for i, m := range members {
		rows[i] = map[string]any{"document_id": m.DocumentID.String(), "title": m.Title, "category": m.Category}
	}
	in := map[string]any{"expected_updated_at": v.UpdatedAt.UTC().Format(time.RFC3339Nano), "expected_package_id": v.PackageID, "expected_generation": v.Generation, "members": rows}
	if transport == "MCP" {
		in["document_id"] = v.DocumentID.String()
	}
	raw, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}
func packageLayoutRequest226(q *ownedPublicReadFixtureV1, ctx context.Context, transport string, root uuid.UUID, key, raw string) *http.Request {
	r := packageAPIRequest225(q, ctx, transport, "save_document_attachments", root, key, raw)
	if transport == "REST" {
		r.Method = http.MethodPatch
	}
	return r
}
func packageLayoutSubmit226(q *ownedPublicReadFixtureV1, transport string, root uuid.UUID, key, raw string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, packageLayoutRequest226(q, q.f.ctx, transport, root, key, raw))
	return w
}
func packageLayoutView226(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID) pdfadmission.DocumentPackageInventoryV1 {
	t.Helper()
	var v pdfadmission.DocumentPackageInventoryV1
	packageAPIReply225(t, packageAPISubmit225(q, "REST", "get_document_attachments", root, "", ""), "REST", http.StatusOK, &v)
	return v
}
func packageLayoutPins226(t *testing.T, q *ownedPublicReadFixtureV1, v pdfadmission.DocumentPackageInventoryV1) map[uuid.UUID]string {
	t.Helper()
	pkg, e := uuid.Parse(v.PackageID)
	if e != nil {
		t.Fatal(e)
	}
	generation, e := strconv.ParseInt(v.Generation, 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := q.f.q.ListDocumentAttachmentDraftsV1(q.f.ctx, generated.ListDocumentAttachmentDraftsV1Params{PackageID: pkg, OrgID: q.f.org, ExpectedGeneration: generation})
	if e != nil {
		t.Fatal(e)
	}
	out := map[uuid.UUID]string{}
	for _, r := range rows {
		r.Ordinal = 0
		r.Title = ""
		r.Category = ""
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		out[r.MemberDocumentID] = string(b)
	}
	return out
}
func TestDocumentPackageStaffLayoutV1E2E(t *testing.T) {
	q := newOwnedDocumentPackageMeasurementFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if e := malwarescan.Configure(q.f.ctx, "", "development"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := malwarescan.Configure(context.Background(), "", "development"); e != nil {
			t.Error(e)
		}
	})
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, PDFCreationSessions: q.runtime.SessionsV1(), Storage: q.f.s.Storage, Billing: q.f.s.Billing, PublicURL: q.f.s.PublicURL})
	key, _ := mintAuthoringMCPE2E(t, q.f)
	root := packageImported220(t, q, "Main layout agreement")
	a := packageImported220(t, q, "NDA")
	b := packageImported220(t, q, "DPA")
	c := packageImported220(t, q, "SLA")
	packageCreate223(t, q, root, a, b, c)
	original := packageLayoutView226(t, q, root.ID)
	pins := packageLayoutPins226(t, q, original)
	current := original
	apply := func(t *testing.T, transport string, desired []pdfadmission.DocumentPackageInventoryMemberV1, delta int64) {
		t.Helper()
		before := current
		requests := q.storagePeer.requests.Load()
		var out packageauthoring.OutcomeV1
		packageAPIReply225(t, packageLayoutSubmit226(q, transport, root.ID, key.Plaintext, packageLayoutArguments226(t, before, transport, desired)), transport, http.StatusOK, &out)
		if out.State != "committed" || out.Layout == nil || out.Layout.ChangedRows != delta || out.Layout.EventID == uuid.Nil || out.ReconciliationRequired {
			t.Fatal("layout durable outcome", out)
		}
		oldGen, e := strconv.ParseInt(before.Generation, 10, 64)
		if e != nil {
			t.Fatal(e)
		}
		current = packageLayoutView226(t, q, root.ID)
		if out.Layout.Generation != oldGen+delta || current.Generation != strconv.FormatInt(out.Layout.Generation, 10) || current.PackageID != before.PackageID || !current.UpdatedAt.Equal(out.Layout.UpdatedAt) || !current.UpdatedAt.After(before.UpdatedAt) || len(current.Members) != len(desired) {
			t.Fatal("post-trigger clock/generation differs", out, current)
		}
		actualPins := packageLayoutPins226(t, q, current)
		for i, m := range current.Members {
			if m.DocumentID != desired[i].DocumentID || m.Ordinal != int16(i+1) || m.Title != desired[i].Title || m.Category != desired[i].Category || actualPins[m.DocumentID] != pins[m.DocumentID] {
				t.Fatal("layout changed frozen pins/order/labels", m)
			}
		}
		event, e := q.f.q.GetEventByID(q.f.ctx, out.Layout.EventID)
		if e != nil || event.Kind != "document.attachments_updated" || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != q.f.user.ID {
			t.Fatal("fixed layout audit", event, e)
		}
		var payload struct {
			Schema        string
			Before, After []map[string]any
		}
		if e = json.Unmarshal(event.PayloadHashed, &payload); e != nil || payload.Schema != "hash-attachment-layout-v1" || len(payload.Before) != len(before.Members) || len(payload.After) != len(desired) {
			t.Fatal("complete prior/new audit layouts", e)
		}
		if requests != q.storagePeer.requests.Load() {
			t.Fatal("metadata edit contacted provider")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	}
	t.Run("REST relabel reorder and detach preserve selected pins after source deletion", func(t *testing.T) {
		if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Later deleted source',metadata_redaction_report='{\"later\":true}',deleted_at=clock_timestamp() WHERE id=$1 AND org_id=$2", b.ID, q.f.org); e != nil {
			t.Fatal(e)
		}
		desired := []pdfadmission.DocumentPackageInventoryMemberV1{current.Members[1], current.Members[0]}
		desired[0].Title = "DPA - agreed edition"
		desired[0].Category = "Custom compliance"
		apply(t, "REST", desired, 3)
	})
	t.Run("MCP deferred unique permutation swap preserves all pins", func(t *testing.T) {
		apply(t, "MCP", []pdfadmission.DocumentPackageInventoryMemberV1{current.Members[1], current.Members[0]}, 2)
	})
	t.Run("unchanged save has no clock generation or audit mutation", func(t *testing.T) {
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		var out packageauthoring.OutcomeV1
		packageAPIReply225(t, packageLayoutSubmit226(q, "REST", root.ID, "", packageLayoutArguments226(t, current, "REST", current.Members)), "REST", http.StatusOK, &out)
		if out.State != "unchanged" || out.Layout == nil || out.Layout.ChangedRows != 0 || out.Layout.EventID != uuid.Nil || before != packageFullState223(t, q) || requests != q.storagePeer.requests.Load() {
			t.Fatal("no-op wrote or fetched", out)
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	for _, transport := range []string{"REST", "MCP"} {
		t.Run(transport+" strict duplicate unknown and numeric inputs refuse", func(t *testing.T) {
			raw := packageLayoutArguments226(t, current, transport, current.Members)
			var decoded map[string]json.RawMessage
			if e := json.Unmarshal([]byte(raw), &decoded); e != nil {
				t.Fatal(e)
			}
			duplicated := strings.Replace(raw, `"members":[`, `"members":[{"document_id":"`+a.ID.String()+`","document_id":"`+a.ID.String()+`","title":"NDA","category":""},`, 1)
			for _, bad := range []string{duplicated, strings.TrimSuffix(raw, "}") + `,"pdf_key":"caller-pin"}`, strings.TrimSuffix(raw, "}") + `,"members":[]}`, strings.Replace(raw, `"expected_generation":"`+current.Generation+`"`, `"expected_generation":`+current.Generation, 1)} {
				before := packageFullState223(t, q)
				requests := q.storagePeer.requests.Load()
				packageAPIRefused225(t, q, packageLayoutSubmit226(q, transport, root.ID, key.Plaintext, bad), transport, http.StatusBadRequest, before, requests)
			}
		})
		t.Run(transport+" stale root observation refuses without mutation", func(t *testing.T) {
			before := packageFullState223(t, q)
			requests := q.storagePeer.requests.Load()
			packageAPIRefused225(t, q, packageLayoutSubmit226(q, transport, root.ID, key.Plaintext, packageLayoutArguments226(t, original, transport, current.Members)), transport, http.StatusConflict, before, requests)
		})
		t.Run(transport+" cannot add an unselected identity through layout", func(t *testing.T) {
			desired := append([]pdfadmission.DocumentPackageInventoryMemberV1{}, current.Members...)
			desired = append(desired, pdfadmission.DocumentPackageInventoryMemberV1{DocumentID: uuid.New(), Title: "Unselected", Category: ""})
			before := packageFullState223(t, q)
			requests := q.storagePeer.requests.Load()
			packageAPIRefused225(t, q, packageLayoutSubmit226(q, transport, root.ID, key.Plaintext, packageLayoutArguments226(t, current, transport, desired)), transport, http.StatusConflict, before, requests)
		})
		t.Run(transport+" original credential revoked at real root wait", func(t *testing.T) {
			waitKey, keyID := mintAuthoringMCPE2E(t, q.f)
			blocked, pid := ownedReadHolderV1(t, q, root.ID, false)
			ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
			result := make(chan *httptest.ResponseRecorder, 1)
			joined := false
			defer func() {
				cancel()
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = blocked.Rollback(cleanup)
				if !joined {
					select {
					case <-result:
					case <-cleanup.Done():
						t.Error("layout request did not join")
					}
				}
			}()
			req := packageLayoutRequest226(q, ctx, transport, root.ID, waitKey.Plaintext, packageLayoutArguments226(t, current, transport, nil))
			router := q.f.s.Routes()
			go func() { w := httptest.NewRecorder(); router.ServeHTTP(w, req); result <- w }()
			ownedReadWaitV1(t, q, pid, "GetHTMLRevisionDocumentReadHeaderV1")
			if transport == "REST" {
				if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"}); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "owner"}); e != nil {
						t.Error(e)
					}
				}()
			} else {
				if _, e := q.f.q.DeleteAPIKey(q.f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: q.f.user.ID}); e != nil {
					t.Fatal(e)
				}
			}
			before := packageFullState223(t, q)
			requests := q.storagePeer.requests.Load()
			if e := blocked.Commit(q.f.ctx); e != nil {
				t.Fatal(e)
			}
			var w *httptest.ResponseRecorder
			select {
			case w = <-result:
				joined = true
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			packageAPIRefused225(t, q, w, transport, http.StatusForbidden, before, requests)
		})
	}
	t.Run("MCP late original key expiry rolls back layout and chained audit", func(t *testing.T) {
		expiring, keyID := mintAuthoringMCPE2E(t, q.f)
		if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE api_keys SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1 AND org_id=$2", keyID, q.f.org); e != nil {
			t.Fatal(e)
		}
		blocked, e := q.f.pool.Begin(q.f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = q.f.q.WithTx(blocked).AcquireOrgChainLock(q.f.ctx, q.f.org.String()); e != nil {
			_ = blocked.Rollback(q.f.ctx)
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
		result := make(chan *httptest.ResponseRecorder, 1)
		joined := false
		defer func() {
			cancel()
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_ = blocked.Rollback(cleanup)
			if !joined {
				select {
				case <-result:
				case <-cleanup.Done():
					t.Error("late layout request did not join")
				}
			}
		}()
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		req := packageLayoutRequest226(q, ctx, "MCP", root.ID, expiring.Plaintext, packageLayoutArguments226(t, current, "MCP", nil))
		router := q.f.s.Routes()
		go func() { w := httptest.NewRecorder(); router.ServeHTTP(w, req); result <- w }()
		awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "-- name: AcquireOrgChainLock", "advisory")
		expired := false
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if e = q.f.pool.QueryRow(q.f.ctx, "SELECT expires_at<=clock_timestamp() FROM api_keys WHERE id=$1", keyID).Scan(&expired); e != nil {
				t.Fatal(e)
			}
			if expired {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !expired {
			t.Fatal("actual key expiry not observed")
		}
		if e = blocked.Commit(q.f.ctx); e != nil {
			t.Fatal(e)
		}
		var w *httptest.ResponseRecorder
		select {
		case w = <-result:
			joined = true
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if fieldMCPTextE2E(t, w, true) != "the original login has expired" {
			t.Fatal("late original expiry not refused")
		}
		if before != packageFullState223(t, q) || requests != q.storagePeer.requests.Load() {
			t.Fatal("late expiry mutated or fetched")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	t.Run("selected subject privacy blocks even all-member removal", func(t *testing.T) {
		request, e := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: a.ID, Valid: true}, SubjectEmail: "synthetic@hash.example.test", SubjectName: "Synthetic participant", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			if _, e := q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: request.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); e != nil {
				t.Error(e)
			}
		}()
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		for _, transport := range []string{"REST", "MCP"} {
			packageAPIRefused225(t, q, packageLayoutSubmit226(q, transport, root.ID, key.Plaintext, packageLayoutArguments226(t, current, transport, nil)), transport, http.StatusConflict, before, requests)
		}
	})
	t.Run("document token with both scopes cannot edit its root", func(t *testing.T) {
		minted, e := auth.MintDocumentAgentKey()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = q.f.q.InsertDocAgentToken(q.f.ctx, generated.InsertDocAgentTokenParams{DocumentID: root.ID, OrgID: q.f.org, Name: "Synthetic layout confinement", Prefix: minted.Prefix, KeyHash: minted.Hash, Scopes: []string{"read", "write:authoring"}, CreatedBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}); e != nil {
			t.Fatal(e)
		}
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		packageAPIRefused225(t, q, packageLayoutSubmit226(q, "MCP", root.ID, minted.Plaintext, packageLayoutArguments226(t, current, "MCP", nil)), "MCP", http.StatusForbidden, before, requests)
	})
	t.Run("last detach preserves empty package and no-op remains stable", func(t *testing.T) {
		apply(t, "REST", nil, 2)
		if current.PackageID != original.PackageID || len(current.Members) != 0 {
			t.Fatal("empty header was deleted")
		}
		before := packageFullState223(t, q)
		var out packageauthoring.OutcomeV1
		packageAPIReply225(t, packageLayoutSubmit226(q, "MCP", root.ID, key.Plaintext, packageLayoutArguments226(t, current, "MCP", nil)), "MCP", http.StatusOK, &out)
		if out.State != "unchanged" || before != packageFullState223(t, q) {
			t.Fatal("empty no-op changed package", out)
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	t.Run("synthetic legacy NULL proof can be relabelled and detached", func(t *testing.T) {
		legacyRoot := packageImported220(t, q, "Legacy root")
		legacyMember := packageImported220(t, q, "Legacy annex")
		p := packageCreate223(t, q, legacyRoot, legacyMember)
		// Construct only the historical NULL shape in this isolated synthetic DB.
		// Every other trigger remains enabled, then the exact report guard is restored.
		tx, e := q.f.pool.Begin(q.f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(context.Background())
		for _, sql := range []string{"ALTER TABLE document_attachment_drafts_v1 DISABLE TRIGGER zz_document_attachment_intake_report_guard_v1", "UPDATE document_attachment_drafts_v1 SET pdf_intake_report=NULL,pdf_intake_report_sha256=NULL WHERE package_id=$1 AND org_id=$2", "ALTER TABLE document_attachment_drafts_v1 ENABLE TRIGGER zz_document_attachment_intake_report_guard_v1"} {
			if strings.HasPrefix(sql, "UPDATE") {
				_, e = tx.Exec(q.f.ctx, sql, p.ID, q.f.org)
			} else {
				_, e = tx.Exec(q.f.ctx, sql)
			}
			if e != nil {
				t.Fatal(e)
			}
		}
		if e = tx.Commit(q.f.ctx); e != nil {
			t.Fatal(e)
		}
		v := packageLayoutView226(t, q, legacyRoot.ID)
		if !v.RequiresReselection || len(v.Members) != 1 {
			t.Fatal("legacy fixture not marked", v)
		}
		beforePins := packageLayoutPins226(t, q, v)
		desired := append([]pdfadmission.DocumentPackageInventoryMemberV1{}, v.Members...)
		desired[0].Title = "Historical agreed annex"
		requests := q.storagePeer.requests.Load()
		var out packageauthoring.OutcomeV1
		packageAPIReply225(t, packageLayoutSubmit226(q, "REST", legacyRoot.ID, "", packageLayoutArguments226(t, v, "REST", desired)), "REST", http.StatusOK, &out)
		v = packageLayoutView226(t, q, legacyRoot.ID)
		if out.State != "committed" || !v.RequiresReselection || packageLayoutPins226(t, q, v)[legacyMember.ID] != beforePins[legacyMember.ID] {
			t.Fatal("legacy NULL pins changed", out, v)
		}
		packageAPIReply225(t, packageLayoutSubmit226(q, "MCP", legacyRoot.ID, key.Plaintext, packageLayoutArguments226(t, v, "MCP", nil)), "MCP", http.StatusOK, &out)
		v = packageLayoutView226(t, q, legacyRoot.ID)
		if out.State != "committed" || len(v.Members) != 0 || v.PackageID != p.ID.String() || requests != q.storagePeer.requests.Load() {
			t.Fatal("legacy last detach failed", out, v)
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	t.Run("oversized real layout request refuses before provider", func(t *testing.T) {
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		packageAPIRefused225(t, q, packageLayoutSubmit226(q, "REST", root.ID, "", strings.Repeat(" ", 16385)), "REST", http.StatusRequestEntityTooLarge, before, requests)
	})

}
