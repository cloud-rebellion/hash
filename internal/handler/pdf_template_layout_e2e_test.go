//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func layoutFixtureJSONE2E() json.RawMessage {
	return json.RawMessage(`{"version":1,"parties":[{"role":"provider","label":"Provider"},{"role":"client","label":"Client"}],"fields":[{"party_role":"provider","type":"signature","page":1,"x_pct":10,"y_pct":70,"w_pct":25,"h_pct":8,"required":true,"label":"Provider signature"},{"party_role":"client","type":"signature","page":1,"x_pct":55,"y_pct":70,"w_pct":25,"h_pct":8,"required":true,"label":"Client signature"}]}`)
}

func setupNamedPDFLayoutE2E(t *testing.T) (lifecycleAuthorizationFixture, *generated.Template) {
	t.Helper()
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	request := ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Synthetic named-party PDF template"))
	request.URL.Path = "/api/v1/templates"
	request.RequestURI = request.URL.Path
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("actual named-template upload=%d %s", response.Code, response.Body.String())
	}
	var uploaded templateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &uploaded); err != nil || uploaded.ID == uuid.Nil {
		t.Fatal("actual named-template upload omitted identity", err)
	}
	response = updateNamedPDFLayoutE2E(t, f, uploaded.ID, q.cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("actual named-template layout update=%d %s", response.Code, response.Body.String())
	}
	template, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: uploaded.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	ownedPDFTemplateExactSourceV1(t, q, template.ID)
	ownedPlainAssertDrainedV1(t, q)
	return f, template
}
func updateNamedPDFLayoutE2E(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"fields_json": layoutFixtureJSONE2E()})
	if err != nil {
		t.Fatal(err)
	}
	return submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/templates/"+id.String(), string(raw), cookie)
}

// This PDF-layout-only factory preserves the original credential helpers and
// explicitly supplies their actual production native source factory.
func enableOwnedPDFLayoutMCPE2E(f lifecycleAuthorizationFixture) {
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Versions: versions.New(f.q), Billing: f.s.Billing, PDFCreationSessions: f.s.HTMLCreationSessions, PublicURL: f.s.PublicURL})
}
func namedPDFLayoutCredentialE2E(t *testing.T, f lifecycleAuthorizationFixture, transport string, expires bool) (string, uuid.UUID, time.Time) {
	t.Helper()
	credential, id, expiry := documentCreationCredentialE2E(t, f, transport, expires)
	if transport == "mcp" {
		enableOwnedPDFLayoutMCPE2E(f)
	}
	return credential, id, expiry
}

// Explicitly prepare only the actual custom quota-plan fixture before its
// target routes run. No target reader repairs catalog measurements.
func prepareNamedPDFLayoutPlanE2E(t *testing.T, f lifecycleAuthorizationFixture, slug string) {
	t.Helper()
	var plan uuid.UUID
	if err := f.pool.QueryRow(f.ctx, "SELECT id FROM billing_plans WHERE slug=$1", slug).Scan(&plan); err != nil || plan == uuid.Nil {
		t.Fatal("actual custom plan scalar identity unavailable", err)
	} //nolint:rawsql -- scalar fixture identity only
	owner, err := f.s.HTMLCreationSessions.ControlledMeasurePlanSourceV1(f.ctx, plan)
	if owner != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := owner.CloseV1(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil || owner == nil {
		t.Fatal("explicit custom plan source preparation failed", err)
	}
	receipt, err := owner.ReceiptV1()
	if err != nil || receipt.Kind != "plan" || receipt.SourceID != plan || receipt.OrgID != uuid.Nil || receipt.WireBytes <= 0 || receipt.ServerVersionNum != 160015 || !receipt.CreatedAt.Valid || !receipt.MeasuredAt.Valid {
		t.Fatal("custom plan source lacks exact acknowledged M95 receipt", err)
	}
	owner.CloseConsumerV1()
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err = owner.CloseV1(cleanup); err != nil {
		t.Fatal(err)
	}
	if err = owner.CloseV1(cleanup); err != nil {
		t.Fatal("custom plan close is not idempotent", err)
	}
	if err = f.s.HTMLCreationSessions.ReconcileCleanupV1(cleanup); err != nil {
		t.Fatal(err)
	}
	pending := f.s.HTMLCreationSessions.PendingV1()
	if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.HTMLInputProducers != 0 || pending.CatalogMaintenance != 0 || pending.ObserverSessions != 2 {
		t.Fatal("explicit actual custom source work was not joined", pending)
	}
}

func layoutCreationArgsE2E(tpl *generated.Template) map[string]any {
	args := documentCreationArgsE2E(tpl)
	args["expected_template_version"] = tpl.Version
	args["parties"] = []pdflayout.Binding{{Role: "client", Name: "New Client", Email: "new-client@example.test", Locale: "sv-SE"}, {Role: "provider", Name: "New Provider", Email: "new-provider@example.test", Locale: "en"}}
	return args
}

func TestPDFLayoutInstantiationCreatesFreshPartiesAndFieldsE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f, tpl := setupNamedPDFLayoutE2E(t)
			credential, _, _ := namedPDFLayoutCredentialE2E(t, f, transport, false)
			var previousIDs = map[uuid.UUID]bool{}
			for i := 0; i < 2; i++ {
				args := layoutCreationArgsE2E(tpl)
				args["name"] = fmt.Sprintf("Fresh PDF layout %d", i)
				doc := loadPDFLayoutCreatedE2E(t, f, transport, submitDocumentCreationE2E(f, f.ctx, transport, credential, args), args["name"].(string))
				if doc.RoutingMode != "parallel" || doc.PdfStorageKey != tpl.PdfStorageKey || doc.PdfStorageVersionID != tpl.PdfStorageVersionID {
					t.Fatal("layout source or parallel routing drifted")
				}
				recs, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
				if err != nil {
					t.Fatal(err)
				}
				fields, err := f.q.ListFieldsByDocument(f.ctx, doc.ID)
				if err != nil {
					t.Fatal(err)
				}
				if len(recs) != 2 || len(fields) != 2 {
					t.Fatalf("recipients=%d fields=%d", len(recs), len(fields))
				}
				roles := map[uuid.UUID]string{}
				for _, rec := range recs {
					if rec.DocumentID != doc.ID || previousIDs[rec.ID] || len(rec.MagicTokenHash) == 0 || rec.Status != "pending" {
						t.Fatal("stale or uncredentialed recipient copied")
					}
					previousIDs[rec.ID] = true
					roles[rec.ID] = rec.Role
					if rec.Role == "client" && (rec.Name != "New Client" || rec.Email != "new-client@example.test" || rec.Locale != "sv") {
						t.Fatal("fresh party identity not preserved")
					}
				}
				for _, field := range fields {
					if !field.RecipientID.Valid || roles[uuid.UUID(field.RecipientID.Bytes)] == "" || field.Type != "signature" || !field.Required || field.Value.Valid {
						t.Fatal("layout fields not bound to fresh draft parties")
					}
				}
				var events int
				if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind IN ('recipient.created','document.field_added','document.created')`, doc.ID).Scan(&events); err != nil || events != 5 {
					t.Fatalf("atomic layout audit count=%d %v", events, err)
				}
			}
		})
	}
}

func loadPDFLayoutCreatedE2E(t *testing.T, f lifecycleAuthorizationFixture, transport string, w *httptest.ResponseRecorder, name string) *generated.Document {
	t.Helper()
	if transport == "mcp" {
		assertLifecycleMCPResultE2E(t, w, false)
	} else if w.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	var id uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM documents WHERE org_id=$1 AND name=$2`, f.org, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestPDFLayoutInstantiationRefusesStaleIncompleteAndQuotaBindingsE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, failure := range []string{"missing-version", "stale-version", "missing-party", "duplicate-party", "unknown-party", "bad-email", "recipient-quota"} {
			t.Run(transport+"/"+failure, func(t *testing.T) {
				f, tpl := setupNamedPDFLayoutE2E(t)
				credential, _, _ := namedPDFLayoutCredentialE2E(t, f, transport, false)
				args := layoutCreationArgsE2E(tpl)
				want := http.StatusBadRequest
				switch failure {
				case "missing-version":
					delete(args, "expected_template_version")
				case "stale-version":
					args["expected_template_version"] = tpl.Version - 1
					want = http.StatusPreconditionFailed
				case "missing-party":
					args["parties"] = args["parties"].([]pdflayout.Binding)[:1]
				case "duplicate-party":
					parties := args["parties"].([]pdflayout.Binding)
					parties[1].Role = "client"
				case "unknown-party":
					args["parties"].([]pdflayout.Binding)[1].Role = "stranger"
				case "bad-email":
					args["parties"].([]pdflayout.Binding)[0].Email = "not-an-address"
				case "recipient-quota":
					slug := "layout-quota-" + uuid.NewString()
					if _, err := f.pool.Exec(f.ctx, `INSERT INTO billing_plans(slug,name,document_quota_monthly,recipient_quota_monthly,features_json) VALUES($1,'Layout quota',100,2,'{"mcp":true}')`, slug); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), `DELETE FROM billing_plans WHERE slug=$1`, slug) })
					prepareNamedPDFLayoutPlanE2E(t, f, slug)
					f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: slug, ReviewRef: "synthetic-layout-quota"}})
					if transport == "mcp" {
						enableOwnedPDFLayoutMCPE2E(f)
					}
					want = http.StatusPaymentRequired
				}
				before := f.snapshot(t)
				w := submitDocumentCreationE2E(f, f.ctx, transport, credential, args)
				assertDocumentCreationRefusedE2E(t, f, transport, w, want, "", before)
			})
		}
	}
}

func TestPDFLayoutInstantiationRechecksTemplateAndFinalCredentialE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, wait := range []string{"updated-template", "expired-audit"} {
			t.Run(transport+"/"+wait, func(t *testing.T) {
				f, tpl := setupNamedPDFLayoutE2E(t)
				credential, _, expiry := namedPDFLayoutCredentialE2E(t, f, transport, wait == "expired-audit")
				before := f.snapshot(t)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if err = f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
					t.Fatal(err)
				}
				var actualUpdate chan *httptest.ResponseRecorder
				if wait == "updated-template" {
					// The real public writer owns its real parent UPDATE lock and fresh M97
					// while waiting at the original org audit lock. No caller Tx/cache is used.
					actualUpdate = make(chan *httptest.ResponseRecorder, 1)
					cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
					raw, err := json.Marshal(map[string]any{"fields_json": layoutFixtureJSONE2E()})
					if err != nil {
						t.Fatal(err)
					}
					go func() {
						actualUpdate <- submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/templates/"+tpl.ID.String(), string(raw), cookie)
					}()
					awaitSessionOperationLockE2E(t, f.ctx, f.pool, "pg_advisory_xact_lock", "advisory")
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					result <- submitDocumentCreationE2E(f, f.ctx, transport, credential, layoutCreationArgsE2E(tpl))
				}()
				marker, lock := "-- name: GetPDFTemplateSourceHeaderForShareV1", "transactionid"
				if wait == "expired-audit" {
					marker, lock = "pg_advisory_xact_lock", "advisory"
				}
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, marker, lock)
				want := http.StatusPreconditionFailed
				if wait == "expired-audit" {
					expireDocumentCreationCredentialE2E(t, f, transport, credential, expiry)
					want = http.StatusUnauthorized
				}
				if err = blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if actualUpdate != nil {
					response := receiveSessionOperationE2E(t, actualUpdate)
					if response.Code != http.StatusOK {
						t.Fatalf("actual concurrent named-template update=%d %s", response.Code, response.Body.String())
					}
					current, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: tpl.ID, OrgID: f.org})
					if err != nil || current.Version != tpl.Version+1 {
						t.Fatal("genuine concurrent template writer did not advance the real version", err)
					}
				}
				assertDocumentCreationRefusedE2E(t, f, transport, receiveSessionOperationE2E(t, result), want, "", before)
			})
		}
	}
}

func setupSavePDFLayoutE2E(t *testing.T) (lifecycleAuthorizationFixture, savePDFTemplateInput) {
	t.Helper()
	q, input := newOwnedPDFLayoutCaptureFixtureV1(t)
	return q.f, input
}

func layoutNumberE2E(value int64) pgtype.Numeric {
	return pgtype.Numeric{Int: big.NewInt(value), Valid: true}
}

func submitSavePDFLayoutE2E(f lifecycleAuthorizationFixture, in savePDFTemplateInput, cookie string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(in)
	return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/pdf-template", string(body), cookie)
}

func TestPDFLayoutSaveUsesLockedDesignWithoutPriorIdentityE2E(t *testing.T) {
	f, in := setupSavePDFLayoutE2E(t)
	before := f.snapshot(t)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	w := submitSavePDFLayoutE2E(f, in, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("save=%d %s", w.Code, w.Body.String())
	}
	var template templateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &template); err != nil {
		t.Fatal(err)
	}
	if template.PageCount != 1 || template.PDFSHA256 == "" || template.SourceKind != "pdf" {
		t.Fatal("verified source identity/page count lost")
	}
	for _, party := range in.Parties {
		if strings.Contains(string(template.FieldsJSON), party.RecipientID.String()) || strings.Contains(string(template.FieldsJSON), "Prior Person") || strings.Contains(string(template.FieldsJSON), "@example.test") {
			t.Fatal("prior identity leaked into reusable layout")
		}
	}
	stored, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: template.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if stored.PdfStorageKey != f.doc.PdfStorageKey || stored.PdfStorageVersionID != f.doc.PdfStorageVersionID || !stored.EvidenceVersionPinRequired {
		t.Fatal("source pin changed")
	}
	if before == f.snapshot(t) {
		t.Fatal("template event missing")
	}
	args := layoutCreationArgsE2E(stored)
	created := loadCreatedDocumentE2E(t, f, "rest", submitDocumentCreationE2E(f, f.ctx, "rest", cookie, args))
	recs, err := f.q.ListRecipientsByDocument(f.ctx, created.ID)
	if err != nil || len(recs) != 2 {
		t.Fatalf("saved design did not instantiate %v", err)
	}
	for _, rec := range recs {
		for _, party := range in.Parties {
			if rec.ID == party.RecipientID || strings.HasPrefix(rec.Name, "Prior") {
				t.Fatal("old identity cloned")
			}
		}
	}
}

func TestPDFLayoutSaveRefusesUnseenDesignOrCapturedEvidenceE2E(t *testing.T) {
	for _, failure := range []string{"stale-stamp", "stale-fields", "foreign-recipient", "duplicate-slots", "fillable", "captured"} {
		t.Run(failure, func(t *testing.T) {
			f, in := setupSavePDFLayoutE2E(t)
			want := http.StatusBadRequest
			switch failure {
			case "stale-stamp":
				in.ExpectedUpdatedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
				want = http.StatusPreconditionFailed
			case "stale-fields":
				in.ExpectedFieldIDs[0] = uuid.New()
				want = http.StatusPreconditionFailed
			case "foreign-recipient":
				in.Parties[0].RecipientID = f.recipient.ID
				want = http.StatusPreconditionFailed
			case "duplicate-slots":
				in.Parties[1].Role = in.Parties[0].Role
			case "fillable":
				if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET type='text' WHERE id=$1`, in.ExpectedFieldIDs[0]); err != nil {
					t.Fatal(err)
				}
			case "captured":
				if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET value='' WHERE id=$1`, in.ExpectedFieldIDs[0]); err != nil {
					t.Fatal(err)
				}
				want = http.StatusConflict
			}
			before := templateMutationSnapshotE2E(t, f)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			w := submitSavePDFLayoutE2E(f, in, cookie)
			if w.Code != want {
				t.Fatalf("save=%d want%d %s", w.Code, want, w.Body.String())
			}
			if templateMutationSnapshotE2E(t, f) != before {
				t.Fatal("refused save mutated source, template, audit or outbox")
			}
		})
	}
}

func TestPDFLayoutSaveRechecksOriginalSessionAfterParentAndAuditWaitE2E(t *testing.T) {
	for _, wait := range []string{"parent-demotion", "audit-expiry"} {
		t.Run(wait, func(t *testing.T) {
			f, in := setupSavePDFLayoutE2E(t)
			before := templateMutationSnapshotE2E(t, f)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if wait == "parent-demotion" {
				if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
					t.Fatal(err)
				}
			}
			ttl := time.Hour
			if wait == "audit-expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitSavePDFLayoutE2E(f, in, cookie) }()
			marker, lock := "-- name: GetHTMLRevisionDocumentReadHeaderV1", "transactionid"
			if wait == "audit-expiry" {
				marker, lock = "pg_advisory_xact_lock", "advisory"
			}
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, marker, lock)
			want := http.StatusForbidden
			if wait == "parent-demotion" {
				if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
					t.Fatal(err)
				}
			} else {
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want = http.StatusUnauthorized
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			w := receiveSessionOperationE2E(t, result)
			if w.Code != want {
				t.Fatalf("save=%d want%d %s", w.Code, want, w.Body.String())
			}
			if templateMutationSnapshotE2E(t, f) != before {
				t.Fatal("late invalid credential committed layout")
			}
		})
	}
}

func TestPDFLayoutSaveRejectsSourceOrFieldDriftDuringInspectionE2E(t *testing.T) {
	for _, change := range []string{"source-version", "source-digest", "field-delete"} {
		t.Run(change, func(t *testing.T) {
			f, in := setupSavePDFLayoutE2E(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitSavePDFLayoutE2E(f, in, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetHTMLRevisionDocumentReadHeaderV1", "transactionid")
			switch change {
			case "source-version":
				_, err = blocked.Exec(f.ctx, `UPDATE documents SET pdf_storage_version_id='unreviewed-new-version' WHERE id=$1`, f.doc.ID)
			case "source-digest":
				digest := sha256.Sum256([]byte("different source"))
				_, err = blocked.Exec(f.ctx, `UPDATE documents SET pdf_sha256=$2 WHERE id=$1`, f.doc.ID, digest[:])
			case "field-delete":
				_, err = blocked.Exec(f.ctx, `DELETE FROM document_fields WHERE id=$1`, in.ExpectedFieldIDs[0])
			}
			if err != nil {
				t.Fatal(err)
			}
			before := layoutSaveSnapshotE2E(t, f, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			w := receiveSessionOperationE2E(t, result)
			if w.Code != http.StatusPreconditionFailed {
				t.Fatalf("drift save=%d %s", w.Code, w.Body.String())
			}
			if layoutSaveSnapshotE2E(t, f, f.pool) != before {
				t.Fatal("source drift save committed template or event")
			}
		})
	}
}

func layoutSaveSnapshotE2E(t *testing.T, f lifecycleAuthorizationFixture, db generated.DBTX) string {
	t.Helper()
	var state string
	if err := db.QueryRow(f.ctx, `SELECT jsonb_build_object('templates',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]'::jsonb) FROM templates t WHERE org_id=$1),'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e WHERE org_id=$1),'fields',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.id),'[]'::jsonb) FROM document_fields x JOIN documents d ON d.id=x.document_id WHERE d.org_id=$1))::text`, f.org).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestPDFLayoutMaterializationAuditFailureRollsBackAllPartiesAndFieldsE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f, tpl := setupNamedPDFLayoutE2E(t)
			credential, _, _ := namedPDFLayoutCredentialE2E(t, f, transport, false)
			function := "hash_layout_audit_fail_" + strings.ReplaceAll(f.org.String(), "-", "")
			trigger := function + "_trg"
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION "%s"() RETURNS trigger LANGUAGE plpgsql AS $body$ BEGIN IF NEW.org_id='%s'::uuid AND NEW.kind='document.field_added' THEN RAISE EXCEPTION 'synthetic layout field audit failure'; END IF; RETURN NEW; END $body$`, function, f.org)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE TRIGGER "%s" BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION "%s"()`, trigger, function)); err != nil {
				t.Fatal(err)
			}
			cleanup := func() {
				_, _ = f.pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS "%s" ON events`, trigger))
				_, _ = f.pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS "%s"()`, function))
			}
			t.Cleanup(cleanup)
			before := f.snapshot(t)
			layoutBefore := layoutSaveSnapshotE2E(t, f, f.pool)
			w := submitDocumentCreationE2E(f, f.ctx, transport, credential, layoutCreationArgsE2E(tpl))
			assertDocumentCreationRefusedE2E(t, f, transport, w, http.StatusInternalServerError, "", before)
			if layoutSaveSnapshotE2E(t, f, f.pool) != layoutBefore {
				t.Fatal("partial fields or events committed after audit failure")
			}
			cleanup()
			loadPDFLayoutCreatedE2E(t, f, transport, submitDocumentCreationE2E(f, f.ctx, transport, credential, layoutCreationArgsE2E(tpl)), "Authorized sales draft")
		})
	}
}

func TestPDFLayoutSaveRechecksOriginalSessionAfterVerifiedStorageWaitE2E(t *testing.T) {
	f, in := setupSavePDFLayoutE2E(t)
	body, err := readDocumentArtifact(f.ctx, f.s.Storage, f.doc, f.doc.PdfStorageKey.String, f.doc.PdfSha256, f.doc.PdfStorageVersionID)
	if err != nil {
		t.Fatal(err)
	}
	peer := &fieldBrowserStoragePeer{bucket: "hash-import-fixture", version: f.doc.PdfStorageVersionID.String, objects: map[string][]byte{f.doc.PdfStorageKey.String: body}, reads: make(map[string]int)}
	entered, resume := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/hash-import-fixture/"+f.doc.PdfStorageKey.String {
			close(entered)
			select {
			case <-resume:
			case <-r.Context().Done():
				return
			}
		}
		peer.ServeHTTP(w, r)
	}))
	defer server.Close()
	f.s.Storage, err = storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-layout", SecretKey: "synthetic-layout-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	before := templateMutationSnapshotE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- submitSavePDFLayoutE2E(f, in, cookie) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("source verification did not enter the real storage wait")
	}
	awaitSessionCookieExpiryE2E(t, f.s, cookie)
	close(resume)
	w := receiveSessionOperationE2E(t, result)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("storage expiry save=%d %s", w.Code, w.Body.String())
	}
	if templateMutationSnapshotE2E(t, f) != before {
		t.Fatal("expired original session committed source layout")
	}
}
