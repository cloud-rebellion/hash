//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Genuine original manual-source→two fresh prior identities→assigned signature
// fields. No document/template/field/cache row is inserted by a test fixture.
func newOwnedPDFLayoutCaptureFixtureV1(t *testing.T) (*ownedPublicReadFixtureV1, savePDFTemplateInput) {
	t.Helper()
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Billing: f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: f.s.PublicURL})
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Synthetic reusable two-party PDF")))
	if response.Code != http.StatusCreated {
		t.Fatalf("actual source import=%d %s", response.Code, response.Body.String())
	}
	var imported struct {
		Document documentResponse `json:"document"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &imported); err != nil || imported.Document.ID == uuid.Nil {
		t.Fatal(err)
	}
	key, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
	input := savePDFTemplateInput{Name: "Reusable parties"}
	for i, role := range []string{"provider", "client"} {
		raw, err := json.Marshal(map[string]any{"name": "Prior Person " + role, "email": "prior-" + role + "@example.test", "role": "signer", "locale": "en", "order_index": i})
		if err != nil {
			t.Fatal(err)
		}
		response = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+imported.Document.ID.String()+"/recipients", string(raw), q.cookie)
		if response.Code != http.StatusCreated {
			t.Fatalf("actual prior party=%d %s", response.Code, response.Body.String())
		}
		var recipient recipientResponse
		if err = json.Unmarshal(response.Body.Bytes(), &recipient); err != nil || recipient.ID == uuid.Nil {
			t.Fatal(err)
		}
		response = httptest.NewRecorder()
		f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "MCP", "add_document_field", key.Plaintext, map[string]any{"document_id": imported.Document.ID.String(), "recipient_id": recipient.ID.String(), "type": "signature", "page": 1, "x_pct": 1000 + 4500*i, "y_pct": 7000, "w_pct": 2500, "h_pct": 800, "required": "true", "label": strings.ToUpper(role[:1]) + role[1:] + " signature"}, nil))
		fieldMCPTextE2E(t, response, false)
		input.Parties = append(input.Parties, savePDFTemplateParty{RecipientID: recipient.ID, Role: role, Label: strings.ToUpper(role[:1]) + role[1:]})
	}
	document, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: imported.Document.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, document.ID)
	if err != nil || len(fields) != 2 {
		t.Fatal(err)
	}
	for _, field := range fields {
		input.ExpectedFieldIDs = append(input.ExpectedFieldIDs, field.ID)
	}
	input.ExpectedUpdatedAt = document.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)
	q.f.doc = document
	ownedPlainAssertDrainedV1(t, q)
	return q, input
}

type ownedPDFLayoutProviderGateV1 struct {
	entered, resume chan struct{}
	once, enterOnce sync.Once
}

func newOwnedPDFLayoutProviderGateV1() *ownedPDFLayoutProviderGateV1 {
	return &ownedPDFLayoutProviderGateV1{entered: make(chan struct{}), resume: make(chan struct{})}
}
func (g *ownedPDFLayoutProviderGateV1) unblock() { g.once.Do(func() { close(g.resume) }) }
func TestOwnedPDFLayoutCaptureActualSourceExportReuseAndLastUseE2E(t *testing.T) {
	q, in := newOwnedPDFLayoutCaptureFixtureV1(t)
	f := q.f
	original, err := json.Marshal(f.doc)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := f.q.ListRecipientsByDocument(f.ctx, f.doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := readDocumentArtifact(f.ctx, f.s.Storage, f.doc, f.doc.PdfStorageKey.String, f.doc.PdfSha256, f.doc.PdfStorageVersionID)
	if err != nil {
		t.Fatal(err)
	}
	// Same real source bytes/version under an exact bounded HTTP peer, adding a
	// controlled actual body wait only. No source pin or DB/cache row is rewritten.
	peer := &fieldBrowserStoragePeer{bucket: "hash-import-fixture", version: f.doc.PdfStorageVersionID.String, objects: map[string][]byte{f.doc.PdfStorageKey.String: body}, reads: make(map[string]int)}
	var provider atomic.Pointer[ownedPDFLayoutProviderGateV1]
	objects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/hash-import-fixture/"+f.doc.PdfStorageKey.String {
			if gate := provider.Load(); gate != nil {
				gate.enterOnce.Do(func() { close(gate.entered) })
				<-gate.resume
			}
		}
		peer.ServeHTTP(w, r)
	}))
	t.Cleanup(objects.Close)
	f.s.Storage, err = storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-layout-capture", SecretKey: "synthetic-layout-capture-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	q.f = f
	var current atomic.Pointer[ownedPlainAuditGateV1]
	f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, entry audit.Entry) {
		g := current.Load()
		if g == nil || entry.Kind != audit.KindTemplateCreated || entry.DocumentID == nil || *entry.DocumentID != f.doc.ID {
			return
		}
		g.eventID = id
		g.entry = entry
		close(g.started)
		<-g.release
		close(g.returned)
	})
	var latest *generated.Template
	for _, order := range []string{"body-first", "hook-first"} {
		t.Run(order, func(t *testing.T) {
			hook := newOwnedPlainAuditGateV1(audit.KindTemplateCreated)
			current.Store(hook)
			t.Cleanup(hook.unblock)
			response := newOwnedPlainResponseGateV1()
			t.Cleanup(response.unblock)
			done := make(chan struct{})
			raw, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/documents/"+f.doc.ID.String()+"/pdf-template", bytes.NewReader(raw)).WithContext(f.ctx)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", f.s.PublicURL)
			request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
			go func() { defer close(done); f.s.Routes().ServeHTTP(response, request) }()
			ownedPlainAwaitV1(t, response.started, "actual saved template body")
			if response.Code != http.StatusCreated {
				response.unblock()
				ownedPlainAwaitV1(t, done, "actual refused saved-template response")
				t.Fatalf("actual layout export=%d %s", response.Code, response.Body.String())
			}
			ownedPlainAwaitV1(t, hook.started, "actual document-scoped template.created hook")
			id, ok := hook.entry.Payload["template_id"].(uuid.UUID)
			if !ok || id == uuid.Nil || id == f.doc.ID {
				t.Fatal("capture did not allocate genuine fresh independent template identity")
			}
			latest, err = f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: id, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			if latest.PdfStorageKey != f.doc.PdfStorageKey || latest.PdfStorageVersionID != f.doc.PdfStorageVersionID || latest.EvidenceVersionPinRequired != f.doc.EvidenceVersionPinsRequired || !bytes.Equal(latest.PdfSha256, f.doc.PdfSha256) || !latest.PageCount.Valid || latest.PageCount.Int32 != 1 || latest.CreatedBy != f.user.ID || latest.Name != in.Name || len(latest.PdfSanitizationReport) != 0 {
				t.Fatal("saved template changed exact original source/name/pagecount/provenance")
			}
			layout, err := pdflayout.Parse(latest.FieldsJson, 1)
			if err != nil || layout == nil || len(layout.Parties) != 2 || len(layout.Fields) != 2 {
				t.Fatal("original identity-free export layout changed", err)
			}
			for _, recipient := range prior {
				for _, private := range []string{recipient.ID.String(), recipient.Name, recipient.Email, hex.EncodeToString(recipient.MagicTokenHash)} {
					if private != "" && bytes.Contains(latest.FieldsJson, []byte(private)) {
						t.Fatal("prior recipient identity/token leaked into reusable template")
					}
				}
			}
			for _, field := range in.ExpectedFieldIDs {
				if bytes.Contains(latest.FieldsJson, []byte(field.String())) {
					t.Fatal("prior field identity leaked into reusable template")
				}
			}
			ownedPDFTemplateExactSourceV1(t, q, latest.ID)
			if hook.entry.OrgID != f.org || hook.entry.ActorUserID == nil || *hook.entry.ActorUserID != f.user.ID || hook.entry.RecipientID != nil || len(hook.entry.Payload) != 6 || hook.entry.Payload["source_kind"] != "pdf" || hook.entry.Payload["name"] != in.Name || hook.entry.Payload["layout_version"] != 1 || hook.entry.Payload["party_count"] != 2 || hook.entry.Payload["field_count"] != 2 {
				t.Fatal("original document-scoped saved-template event changed")
			}
			event, err := f.q.GetEventByID(f.ctx, hook.eventID)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := audit.RecomputeEventRowHash(event)
			hookRaw, marshalErr := json.Marshal(hook.entry.Payload)
			if err != nil || marshalErr != nil || !bytes.Equal(hash, event.RowHash) || !bytes.Equal(hookRaw, event.PayloadHashed) {
				t.Fatal("original saved-template chain/hash/hook bytes changed", err, marshalErr)
			}
			var exact bool
			if err = f.pool.QueryRow(f.ctx, "SELECT document_id=$2 AND org_id=$3 AND payload_wire_bytes=$4 AND measurement_server_version_num=current_setting('server_version_num')::integer FROM html_snapshot_event_payload_sizes_v1 WHERE event_id=$1", event.ID, f.doc.ID, f.org, int64(len(event.PayloadJson))).Scan(&exact); err != nil || !exact {
				t.Fatal("actual saved-template event lacks fresh exact M94", err)
			} //nolint:rawsql -- actual original event source/cache oracle
			snapshot, err := q.runtime.SnapshotV1(f.org)
			pending := q.runtime.SessionsV1().PendingV1()
			if err != nil || snapshot.Global.ParentBytes <= 0 || snapshot.Global.DBStagingBytes <= 0 || snapshot.Global.ProviderStreams != 0 || pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 2 {
				t.Fatal("both actual source/capture admissions ended before response and hook", snapshot, pending, err)
			}
			if order == "body-first" {
				response.unblock()
				ownedPlainAwaitV1(t, done, "saved template HTTP last use")
				ownedPlainAssertRetainedV1(t, q, "both actual captured sources while hook remains")
				hook.unblock()
				ownedPlainAwaitV1(t, hook.returned, "saved template hook return")
			} else {
				hook.unblock()
				ownedPlainAwaitV1(t, hook.returned, "saved template hook before HTTP last use")
				ownedPlainAssertRetainedV1(t, q, "actual template/source while serializer remains")
				response.unblock()
				ownedPlainAwaitV1(t, done, "saved template serializer return")
			}
			current.Store(nil)
			ownedPlainAssertDrainedV1(t, q)
			actual, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(actual)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("save mutated original PDF source/document", err)
			}
		})
	}
	// Saved design is usable immediately with wholly fresh actual parties/fields.
	bindings := []pdflayout.Binding{{Role: "client", Name: "Fresh Client", Email: "fresh-client@example.test", Locale: "sv-SE"}, {Role: "provider", Name: "Fresh Provider", Email: "fresh-provider@example.test", Locale: "en"}}
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, ownedPDFMaterializationRequestV1(t, q, "REST", "", latest, bindings, "Fresh from exported template"))
	if response.Code != http.StatusCreated {
		t.Fatalf("actual saved-template reuse=%d %s", response.Code, response.Body.String())
	}
	var created documentResponse
	if err = json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	fresh, err := f.q.ListRecipientsByDocument(f.ctx, created.ID)
	if err != nil || len(fresh) != 2 {
		t.Fatal(err)
	}
	for _, recipient := range fresh {
		for _, old := range prior {
			if recipient.ID == old.ID || recipient.Name == old.Name || recipient.Email == old.Email || bytes.Equal(recipient.MagicTokenHash, old.MagicTokenHash) {
				t.Fatal("template reuse cloned old recipient authority")
			}
		}
	}
	ownedPlainAssertDrainedV1(t, q)
	// Exact original observed-field precondition rejects without source/template/
	// cache/audit writes; its normal body read never derives a missing cache.
	invalid := in
	invalid.ExpectedFieldIDs = append([]uuid.UUID(nil), in.ExpectedFieldIDs...)
	invalid.ExpectedFieldIDs[0] = uuid.New()
	before := templateMutationSnapshotE2E(t, f)
	raw, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	response = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/pdf-template", string(raw), q.cookie)
	if response.Code != http.StatusPreconditionFailed || templateMutationSnapshotE2E(t, f) != before {
		t.Fatal("original observed-field refusal/atomicity changed", response.Code, response.Body.String())
	}
	ownedPlainAssertDrainedV1(t, q)
	// A real source GET blocks while the native inspection SQL is already joined.
	// Taking the actual draft FOR UPDATE now proves no pre-inspection parent lock
	// crosses provider/worker work. The later real parent wait rechecks live role.
	gate := newOwnedPDFLayoutProviderGateV1()
	provider.Store(gate)
	t.Cleanup(gate.unblock)
	raw, err = json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/pdf-template", string(raw), q.cookie)
	}()
	ownedPlainAwaitV1(t, gate.entered, "actual capture verified source provider wait")
	snapshot, err := q.runtime.SnapshotV1(f.org)
	pending := q.runtime.SessionsV1().PendingV1()
	if err != nil || snapshot.Global.ProviderStreams != 1 || snapshot.Global.ParentBytes <= 0 || pending.WorkSessions != 0 || pending.HTMLAdmissions != 1 {
		t.Fatal("actual source provider/body owner not retained after unlocked SQL join", snapshot, pending, err)
	}
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	var locked uuid.UUID
	if err = blocked.QueryRow(f.ctx, "SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", f.doc.ID, f.org).Scan(&locked); err != nil || locked != f.doc.ID {
		t.Fatal("inspection held draft lock across provider wait", err)
	} //nolint:rawsql -- actual independent parent-lock witness, never source authority
	gate.unblock()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetHTMLRevisionDocumentReadHeaderV1", "transactionid")
	provider.Store(nil)
	if _, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if tag, err := f.pool.Exec(f.ctx, "DELETE FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2", f.doc.ID, f.org); err != nil || tag.RowsAffected() != 1 {
		t.Fatal(err)
	} //nolint:rawsql -- explicit negative measurement removal only
	before = templateMutationSnapshotE2E(t, f)
	if err = blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	response = receiveSessionOperationE2E(t, result)
	if response.Code != http.StatusForbidden || templateMutationSnapshotE2E(t, f) != before {
		t.Fatal("original live-role-before-cache refusal/atomicity changed", response.Code, response.Body.String())
	}
	ownedPlainAssertDrainedV1(t, q)
	if _, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	peer.mu.Lock()
	reads := peer.reads[f.doc.PdfStorageKey.String]
	peer.mu.Unlock()
	raw, err = json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	response = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/pdf-template", string(raw), q.cookie)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("missing original source cache did not refuse", response.Code, response.Body.String())
	}
	peer.mu.Lock()
	afterReads := peer.reads[f.doc.PdfStorageKey.String]
	peer.mu.Unlock()
	var absent int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM document_signing_policy_sizes_v1 WHERE document_id=$1", f.doc.ID).Scan(&absent); err != nil || absent != 0 || afterReads != reads || templateMutationSnapshotE2E(t, f) != before {
		t.Fatal("normal source inspection repaired cache, read provider before admission or mutated source", absent, reads, afterReads, err)
	}
	ownedPlainAssertDrainedV1(t, q) //nolint:rawsql -- continued exact absence oracle
}
