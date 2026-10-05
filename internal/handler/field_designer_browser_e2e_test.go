//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The storage fixture is a bounded loopback S3 protocol peer. Real storage.New
// and GetVerifiedVersion check the persisted version and SHA-256 before Go
// serves the PDF to the real built frontend. This is rendered authoring
// acceptance, not immutable storage, SMTP or production readiness evidence.
func TestRenderedFieldDesignerMutationsStayScopedE2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Skip("set HASH_BROWSER_E2E=1 with built frontend and cached Chromium")
	}
	ctx, pool, q, s, org, owner := setupDSRE2E(t)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM orgs WHERE id=$1`, org); err != nil {
			t.Error(err)
		}
	})
	const bucket, version = "hash-field-fixture", "field-browser-1"
	objects := map[string][]byte{
		"org/" + org.String() + "/documents/field-A.pdf": fieldBrowserPDF("Synthetic field browser PDF A"),
		"org/" + org.String() + "/documents/field-B.pdf": fieldBrowserPDF("Synthetic field browser PDF B"),
	}
	peer := &fieldBrowserStoragePeer{bucket: bucket, version: version, objects: objects, reads: make(map[string]int)}
	storageServer := httptest.NewServer(peer)
	defer storageServer.Close()
	endpoint := strings.TrimPrefix(storageServer.URL, "http://")
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("synthetic storage fixture must bind to loopback")
	}
	storageConfig := storage.Config{
		Endpoint: endpoint, Region: "us-east-1", Bucket: bucket,
		AccessKey: "synthetic-field-access", SecretKey: "synthetic-field-secret", UseSSL: false,
	}
	// Main's production transport guard remains active. The documented local
	// development opt-in applies only to this bounded synthetic loopback peer.
	if _, err := storage.New(ctx, storageConfig); err == nil {
		t.Fatal("storage admitted plaintext loopback without explicit development opt-in")
	}
	storageConfig.AllowInsecureDevelopmentEndpoint = true
	s.Storage, err = storage.New(ctx, storageConfig)
	if err != nil {
		t.Fatal(err)
	}
	seed := func(label string) (*generated.Document, *generated.Recipient) {
		key := "org/" + org.String() + "/documents/field-" + label + ".pdf"
		digest := sha256.Sum256(objects[key])
		doc, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{
			OrgID: org, SenderID: owner, Name: "Field designer " + label + " " + uuid.NewString(),
			PdfStorageKey: pgtype.Text{String: key, Valid: true}, PdfSha256: digest[:],
			PdfStorageVersionID: pgtype.Text{String: version, Valid: true}, EvidenceVersionPinsRequired: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, hash, err := auth.MintMagicToken()
		if err != nil {
			t.Fatal(err)
		}
		recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@field-browser.test", Name: "Field recipient " + label, Locale: "en", MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
		if err != nil {
			t.Fatal(err)
		}
		return doc, recipient
	}
	a, recipientA := seed("A")
	b, recipientB := seed("B")
	user, err := q.GetUser(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	// Prove the peer's bytes and the real digest guard before browser traffic.
	for key, body := range objects {
		digest := sha256.Sum256(body)
		verified, err := s.Storage.GetVerifiedVersion(ctx, key, version, digest[:])
		if err != nil || !bytes.Equal(verified, body) {
			t.Fatalf("synthetic version-pinned source verification: %v", err)
		}
	}
	if _, err := s.Storage.GetVerifiedVersion(ctx, a.PdfStorageKey.String, version, make([]byte, sha256.Size)); err == nil {
		t.Fatal("real storage client accepted a source with the wrong committed digest")
	}
	readsBefore := peer.readCounts()
	root, err := filepath.Abs("../../frontend/build")
	if err != nil {
		t.Fatal(err)
	}
	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("build frontend before browser fixture")
	}
	s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(root))
	s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if info, err := os.Stat(filepath.Join(root, clean)); err == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	hold := &fieldBrowserAuditHold{pool: pool, q: q, org: org, documentBID: b.ID}
	server := httptest.NewUnstartedServer(nil)
	s.PublicURL = "https://" + server.Listener.Addr().String()
	mux := http.NewServeMux()
	control := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil {
				http.Error(w, "fixture owner session required", http.StatusUnauthorized)
				return
			}
			raw, err := s.Cookies.Verify(cookie.Value)
			var session auth.SessionPayload
			if err != nil || json.Unmarshal(raw, &session) != nil || session.UserID != owner || session.Generation != user.SessionGeneration {
				http.Error(w, "fixture owner session required", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("POST /__fixture/audit-hold", control(hold.acquire))
	mux.HandleFunc("GET /__fixture/audit-wait", control(hold.waiting))
	mux.HandleFunc("POST /__fixture/audit-release", control(hold.releaseHTTP))
	mux.Handle("/", s.Routes())
	server.Config.Handler = mux
	server.StartTLS()
	defer func() {
		if err := hold.release(); err != nil {
			t.Error(err)
		}
		server.Close()
	}()
	payload, err := json.Marshal(auth.SessionPayload{UserID: owner, Generation: user.SessionGeneration})
	if err != nil {
		t.Fatal(err)
	}
	cookie := s.Cookies.Mint(payload, time.Hour)
	recipientCName := "Field refresh signer C"
	recipientCEmail := uuid.NewString() + "@field-browser.test"
	fixture, err := json.Marshal(map[string]any{
		"base": server.URL, "cookieName": SessionCookieName, "cookie": cookie,
		"documentAID": a.ID.String(), "documentBID": b.ID.String(), "documentAName": a.Name, "documentBName": b.Name,
		"recipientAID": recipientA.ID.String(), "recipientBID": recipientB.ID.String(),
		"recipientCName": recipientCName, "recipientCEmail": recipientCEmail,
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "bun", "scripts/verify-browser-field-designer.ts")
	cmd.Dir = "../../frontend"
	cmd.Stdin = bytes.NewReader(fixture)
	output, err := cmd.CombinedOutput()
	t.Log(strings.ReplaceAll(string(output), cookie, "[redacted-session]"))
	if err != nil {
		t.Fatalf("rendered PDF field authoring: %v", err)
	}
	receiptBytes, err := os.ReadFile("/private/tmp/hash-browser-field-designer-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Result           string            `json:"result"`
		DocumentAID      uuid.UUID         `json:"documentAID"`
		DocumentBID      uuid.UUID         `json:"documentBID"`
		DeletedFieldBID  uuid.UUID         `json:"deletedFieldBID"`
		FinalFieldBID    uuid.UUID         `json:"finalFieldBID"`
		FinalFieldB      json.RawMessage   `json:"finalFieldB"`
		NewRecipientBID  uuid.UUID         `json:"newRecipientBID"`
		CascadedFieldBID uuid.UUID         `json:"cascadedFieldBID"`
		RecipientSync    bool              `json:"recipientSyncWithoutRemount"`
		Canvas           bool              `json:"realPdfCanvasRendered"`
		CreatePreview    bool              `json:"createPreviewSameDesigner"`
		DeletePreview    bool              `json:"deletePreviewSameDesigner"`
		LateRead         bool              `json:"lateInitialReadIsolated"`
		LateSave         bool              `json:"lateSubmittedSaveIsolated"`
		Edge             bool              `json:"edgePlacementFitsPage"`
		BrowserErrors    []json.RawMessage `json:"browserErrors"`
		CSPViolations    []json.RawMessage `json:"cspViolations"`
		Mutations        []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"mutations"`
	}
	if json.Unmarshal(receiptBytes, &receipt) != nil || receipt.Result != "pass" || receipt.DocumentAID != a.ID || receipt.DocumentBID != b.ID || receipt.DeletedFieldBID == uuid.Nil || receipt.FinalFieldBID == uuid.Nil || receipt.DeletedFieldBID == receipt.FinalFieldBID || !receipt.Canvas || !receipt.CreatePreview || !receipt.DeletePreview || !receipt.LateRead || !receipt.LateSave || !receipt.Edge || len(receipt.BrowserErrors) != 0 || len(receipt.CSPViolations) != 0 {
		t.Fatal("rendered field designer omitted a valid receipt")
	}
	if receipt.NewRecipientBID == uuid.Nil || receipt.NewRecipientBID == recipientA.ID || receipt.NewRecipientBID == recipientB.ID || receipt.CascadedFieldBID == uuid.Nil || receipt.CascadedFieldBID == receipt.DeletedFieldBID || receipt.CascadedFieldBID == receipt.FinalFieldBID || !receipt.RecipientSync {
		t.Fatal("rendered recipient and field refresh journey omitted its scoped deletion receipt")
	}
	fieldsA, err := q.ListFieldsByDocument(ctx, a.ID)
	if err != nil || len(fieldsA) != 1 {
		t.Fatalf("A field count=%d error=%v", len(fieldsA), err)
	}
	fieldsB, err := q.ListFieldsByDocument(ctx, b.ID)
	if err != nil || len(fieldsB) != 1 || fieldsB[0].ID != receipt.FinalFieldBID {
		t.Fatalf("B field count=%d or receipt identity differs: %v", len(fieldsB), err)
	}
	fieldBrowserAssertPlacement(t, fieldsA[0], a.ID, recipientA.ID, "signature", "Signature", 30, 30, 26, 7, .2)
	fieldBrowserAssertPlacement(t, fieldsB[0], b.ID, recipientB.ID, "text", "Text", 82, 96, 18, 4, 0)
	wantDTO, err := json.Marshal(fieldToDTO(fieldsB[0]))
	if err != nil {
		t.Fatal(err)
	}
	var actualDTO, expectedDTO any
	if json.Unmarshal(receipt.FinalFieldB, &actualDTO) != nil || json.Unmarshal(wantDTO, &expectedDTO) != nil || !reflect.DeepEqual(actualDTO, expectedDTO) {
		t.Fatal("browser's final B DTO differs from the independently read stored field")
	}
	hold.mu.Lock()
	snapshots := hold.fieldsBeforeHold
	hold.mu.Unlock()
	if len(snapshots) != 2 || len(snapshots[0]) != 0 || len(snapshots[1]) != 2 {
		t.Fatal("fixture did not observe the original committed B fields before both actual audit waits")
	}
	var deletedOriginal *generated.DocumentField
	for _, field := range snapshots[1] {
		if field.ID == receipt.DeletedFieldBID {
			deletedOriginal = field
		}
	}
	if deletedOriginal == nil {
		t.Fatal("deleted B field did not exist in the real database before its deletion")
	}
	fieldBrowserAssertPlacement(t, deletedOriginal, b.ID, recipientB.ID, "signature", "Signature", 25, 25, 26, 7, .2)
	if _, err := q.GetFieldOwnerDoc(ctx, generated.GetFieldOwnerDocParams{ID: deletedOriginal.ID, OrgID: org}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted B field remains addressable: %v", err)
	}
	if _, err := q.GetFieldOwnerDoc(ctx, generated.GetFieldOwnerDocParams{ID: receipt.CascadedFieldBID, OrgID: org}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("new C recipient's assigned field did not cascade: %v", err)
	}
	if _, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: receipt.NewRecipientBID, OrgID: org}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted C recipient remains addressable: %v", err)
	}
	for _, docID := range []uuid.UUID{a.ID, b.ID} {
		rows, err := q.ListRecipientsByDocument(ctx, docID)
		if err != nil || len(rows) != 1 {
			t.Fatalf("field designer left extra recipients after C deletion: count=%d error=%v", len(rows), err)
		}
	}
	expectedMutations := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/documents/" + b.ID.String() + "/fields"},
		{http.MethodPost, "/api/v1/documents/" + b.ID.String() + "/fields"},
		{http.MethodDelete, "/api/v1/fields/" + receipt.DeletedFieldBID.String()},
		{http.MethodPost, "/api/v1/documents/" + a.ID.String() + "/fields"},
		{http.MethodPost, "/api/v1/documents/" + b.ID.String() + "/recipients"},
		{http.MethodPost, "/api/v1/documents/" + b.ID.String() + "/fields"},
		{http.MethodDelete, "/api/v1/documents/" + b.ID.String() + "/recipients/" + receipt.NewRecipientBID.String()},
	}
	if len(receipt.Mutations) != len(expectedMutations) {
		t.Fatal("browser dispatched unexpected authoring or lifecycle writes")
	}
	for i, want := range expectedMutations {
		if receipt.Mutations[i].Method != want.method || receipt.Mutations[i].Path != want.path {
			t.Fatalf("browser mutation %d differs from the exact field and recipient actions", i)
		}
	}
	events, err := q.ListChainedEventsPageForOrg(ctx, generated.ListChainedEventsPageForOrgParams{OrgID: org, PageLimit: 100})
	if err != nil || len(events) != 7 {
		t.Fatalf("field browser committed audit count=%d error=%v", len(events), err)
	}
	for i, want := range []struct {
		docID, fieldID  uuid.UUID
		kind, fieldType string
	}{
		{b.ID, deletedOriginal.ID, "document.field_added", "signature"},
		{b.ID, fieldsB[0].ID, "document.field_added", "text"},
		{b.ID, deletedOriginal.ID, "document.field_deleted", "signature"},
		{a.ID, fieldsA[0].ID, "document.field_added", "signature"},
	} {
		event := events[i]
		var payload map[string]any
		if json.Unmarshal(event.PayloadJson, &payload) != nil || event.Kind != want.kind || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != owner || !event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != want.docID || payload["field_id"] != want.fieldID.String() || payload["type"] != want.fieldType || payload["via"] != "rest" {
			t.Fatalf("persisted field browser audit %d lost canonical actor, operation or immutable field scope", i)
		}
	}
	for i, kind := range []string{audit.KindRecipientCreated, "document.field_added", audit.KindRecipientDeleted} {
		event := events[i+4]
		var payload map[string]any
		if json.Unmarshal(event.PayloadJson, &payload) != nil || event.Kind != kind || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != owner || !event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != b.ID || payload["via"] != "rest" {
			t.Fatalf("recipient refresh audit %d lost original actor or B scope", i)
		}
		if i == 1 {
			if payload["field_id"] != receipt.CascadedFieldBID.String() || payload["type"] != "signature" {
				t.Fatal("created C signature has no exact committed field audit")
			}
		} else if !event.RecipientID.Valid || uuid.UUID(event.RecipientID.Bytes) != receipt.NewRecipientBID || payload["name"] != recipientCName || payload["email"] != recipientCEmail || payload["role"] != "signer" {
			t.Fatal("recipient deletion lost the immutable created C identity in its audit chain")
		}
	}
	fieldBrowserVerifyChain(t, events)
	for _, original := range []*generated.Document{a, b} {
		current, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: original.ID, OrgID: org})
		if err != nil || !reflect.DeepEqual(current, original) {
			t.Fatalf("field designer changed the draft parent, source digest/version or content: %v", err)
		}
	}
	for _, original := range []*generated.Recipient{recipientA, recipientB} {
		current, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: original.ID, OrgID: org})
		if err != nil || !reflect.DeepEqual(current, original) {
			t.Fatalf("field designer changed recipient identity, routing or credentials: %v", err)
		}
	}
	readsAfter := peer.readCounts()
	for key := range objects {
		if readsAfter[key] <= readsBefore[key] {
			t.Fatal("rendered designer did not read both real version-pinned PDF sources")
		}
	}
	peer.mu.Lock()
	invalid, bucketChecks, lifecycleWrites := peer.invalid, peer.bucketChecks, peer.lifecycleWrites
	peer.mu.Unlock()
	if invalid != 0 || bucketChecks < 1 || lifecycleWrites != 1 {
		t.Fatalf("S3 fixture protocol invalid/bucket/lifecycle requests=%d/%d/%d", invalid, bucketChecks, lifecycleWrites)
	}
	var deliveries, intents, signatures int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM email_deliveries WHERE to_email=ANY($1::text[])),
		(SELECT count(*) FROM send_sealing_intents WHERE org_id=$2),
		(SELECT count(*) FROM signatures WHERE document_id=ANY($3::uuid[]))`, []string{recipientA.Email, recipientB.Email, recipientCEmail, user.Email}, org, []uuid.UUID{a.ID, b.ID}).Scan(&deliveries, &intents, &signatures); err != nil {
		t.Fatal(err)
	}
	if deliveries != 0 || intents != 0 || signatures != 0 {
		t.Fatal("field authoring dispatched a lifecycle or signing operation")
	}
}

func fieldBrowserPDF(text string) []byte {
	// All text is a fixed ASCII fixture constant, with no customer input.
	stream := "BT /F1 18 Tf 72 720 Td (" + text + ") Tj ET\n"
	objects := []string{
		`<< /Type /Catalog /Pages 2 0 R >>`,
		`<< /Type /Pages /Kids [3 0 R] /Count 1 >>`,
		`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>`,
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream),
		`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`,
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}

type fieldBrowserStoragePeer struct {
	mu                                     sync.Mutex
	bucket, version                        string
	objects                                map[string][]byte
	reads                                  map[string]int
	invalid, bucketChecks, lifecycleWrites int
}

func (p *fieldBrowserStoragePeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/"+p.bucket || r.URL.Path == "/"+p.bucket+"/" {
		p.mu.Lock()
		switch {
		case r.Method == http.MethodHead && len(r.URL.Query()) == 0:
			p.bucketChecks++
			p.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		case r.Method == http.MethodPut && r.URL.Query().Has("lifecycle"):
			p.lifecycleWrites++
			p.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		default:
			p.invalid++
			p.mu.Unlock()
			http.Error(w, "unsupported synthetic bucket operation", http.StatusBadRequest)
			return
		}
	}
	key := strings.TrimPrefix(r.URL.Path, "/"+p.bucket+"/")
	body, exists := p.objects[key]
	if !exists || !strings.HasPrefix(r.URL.Path, "/"+p.bucket+"/") || (r.Method != http.MethodGet && r.Method != http.MethodHead) || r.URL.Query().Get("versionId") != p.version {
		p.mu.Lock()
		p.invalid++
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<Error><Code>NoSuchVersion</Code><Message>synthetic exact source version required</Message></Error>`))
		return
	}
	if r.Method == http.MethodGet {
		p.mu.Lock()
		p.reads[key]++
		p.mu.Unlock()
	}
	digest := sha256.Sum256(body)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("ETag", `"`+hex.EncodeToString(digest[:])+`"`)
	w.Header().Set("X-Amz-Version-Id", p.version)
	http.ServeContent(w, r, filepath.Base(key), time.Date(2026, time.October, 5, 12, 0, 0, 0, time.UTC), bytes.NewReader(body))
}

func (p *fieldBrowserStoragePeer) readCounts() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	counts := make(map[string]int, len(p.reads))
	for key, count := range p.reads {
		counts[key] = count
	}
	return counts
}

type fieldBrowserAuditHold struct {
	mu               sync.Mutex
	pool             *pgxpool.Pool
	q                *generated.Queries
	org              uuid.UUID
	tx               pgx.Tx
	pid              int32
	documentBID      uuid.UUID
	fieldsBeforeHold [][]*generated.DocumentField
}

func (h *fieldBrowserAuditHold) acquire(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tx != nil {
		http.Error(w, "fixture audit lock already held", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	defer cancel()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		http.Error(w, "fixture audit transaction unavailable", http.StatusInternalServerError)
		return
	}
	if err := h.q.WithTx(tx).AcquireOrgChainLock(ctx, h.org.String()); err != nil {
		_ = fieldBrowserRollback(tx)
		http.Error(w, "fixture audit lock unavailable", http.StatusInternalServerError)
		return
	}
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		_ = fieldBrowserRollback(tx)
		http.Error(w, "fixture audit holder unavailable", http.StatusInternalServerError)
		return
	}
	fields, err := h.q.ListFieldsByDocument(ctx, h.documentBID)
	if err != nil {
		_ = fieldBrowserRollback(tx)
		http.Error(w, "fixture field snapshot unavailable", http.StatusInternalServerError)
		return
	}
	h.fieldsBeforeHold = append(h.fieldsBeforeHold, fields)
	h.tx, h.pid = tx, pid
	w.WriteHeader(http.StatusNoContent)
}

func (h *fieldBrowserAuditHold) waiting(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	pid := h.pid
	h.mu.Unlock()
	if pid == 0 {
		w.WriteHeader(http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	var waiting bool
	if err := h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE $1=ANY(pg_blocking_pids(a.pid)) AND position('-- name: AcquireOrgChainLock' in a.query)>0)`, pid).Scan(&waiting); err != nil {
		http.Error(w, "fixture audit wait unavailable", http.StatusInternalServerError)
		return
	}
	if !waiting {
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *fieldBrowserAuditHold) releaseHTTP(w http.ResponseWriter, _ *http.Request) {
	if err := h.release(); err != nil {
		http.Error(w, "fixture audit release failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *fieldBrowserAuditHold) release() error {
	h.mu.Lock()
	tx := h.tx
	h.tx, h.pid = nil, 0
	h.mu.Unlock()
	if tx == nil {
		return nil
	}
	return fieldBrowserRollback(tx)
}

func fieldBrowserRollback(tx pgx.Tx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return tx.Rollback(ctx)
}

// Keep the browser's audit assertions on the actual persisted chain rows,
// rather than relying on a client-side toast or field-list receipt alone.
func fieldBrowserVerifyChain(t *testing.T, events []*generated.Event) {
	t.Helper()
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	result := verifier.Result()
	if !result.OK || !result.Complete || result.TotalChecked != len(events) {
		t.Fatalf("rendered field mutation audit chain failed: %+v", result)
	}
}

func fieldBrowserAssertPlacement(t *testing.T, row *generated.DocumentField, documentID, recipientID uuid.UUID, kind, label string, x, y, width, height, tolerance float64) {
	t.Helper()
	if row == nil || row.DocumentID != documentID || !row.RecipientID.Valid || uuid.UUID(row.RecipientID.Bytes) != recipientID || row.Type != kind || !row.Label.Valid || row.Label.String != label || row.Page != 1 || !row.Required || row.Value.Valid || row.CompletedAt.Valid || math.Abs(numericToFloat(row.XPct)-x) > tolerance || math.Abs(numericToFloat(row.YPct)-y) > tolerance || numericToFloat(row.WPct) != width || numericToFloat(row.HPct) != height {
		t.Fatal("stored field placement differs from the rendered page, selected recipient or default tool rectangle")
	}
}
