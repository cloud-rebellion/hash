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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

type packageBrowserMember256 struct {
	ID     uuid.UUID `json:"id"`
	SHA256 string    `json:"sha256"`
	Bytes  int64     `json:"bytes"`
	Pages  int32     `json:"pages"`
}
type packageBrowserParty256 struct {
	Token       string    `json:"token,omitempty"`
	RecipientID uuid.UUID `json:"recipientID"`
	FieldID     uuid.UUID `json:"fieldID"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
}
type packageBrowserWorkerResult256 struct {
	meta pdfadmission.HTMLSendPackageIntentMetadataV1
	err  error
}

func packageBrowserPrivate256(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 65536 {
		return errors.New("bounded private package handoff required")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(raw)
	closeErr := f.Close()
	if n != len(raw) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	return errors.Join(writeErr, closeErr)
}

// This worker observes a real public Send intent, then runs the same native
// queue program as the application. It never creates an intent or invitation.
// Errors are returned to the test's main goroutine; its actual last use is joined.
func packageBrowserWorker256(ctx context.Context, q *ownedPublicReadFixtureV1, root uuid.UUID, client *storage.Client, cfg pdfadmission.PackageSendCompletionConfigV1) packageBrowserWorkerResult256 {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		var pending int
		if err := q.f.pool.QueryRow(ctx, "SELECT count(*)::integer FROM document_package_send_attempts_v1 WHERE document_id=$1 AND org_id=$2", root, q.f.org).Scan(&pending); err != nil {
			return packageBrowserWorkerResult256{err: err}
		}
		if pending > 1 {
			return packageBrowserWorkerResult256{err: errors.New("browser repeated native Send intent")}
		}
		if pending == 1 {
			break
		}
		select {
		case <-ctx.Done():
			return packageBrowserWorkerResult256{err: ctx.Err()}
		case <-tick.C:
		}
	}
	batch, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(ctx, pdfadmission.PackageSendRecoveryCursorV1{})
	if err != nil || batch == nil {
		return packageBrowserWorkerResult256{err: errors.Join(err, errors.New("native browser queue scan failed"))}
	}
	defer batch.CloseConsumerV1()
	var result packageBrowserWorkerResult256
	called := false
	more, err := batch.WithNextSendV1(client, cfg, func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
		if called || !v.RetentionVerified || !v.CompletionVerified || v.Status != "sent" || v.Attempt.Capture.DocumentID != root || v.Attempt.Capture.MemberCount != 3 {
			return errors.New("real browser Send omitted exact retained package effects")
		}
		called = true
		result.meta = pdfadmission.HTMLSendPackageIntentMetadataV1{AttemptID: v.Attempt.AttemptID, Capture: v.Attempt.Capture, CreatedAt: v.Attempt.CreatedAt, Article13NoticeEpochAt: v.Attempt.Article13NoticeEpochAt, RetainUntil: v.Attempt.RetainUntil}
		return nil
	})
	if err != nil || !more || !called {
		result.err = errors.Join(err, errors.New("real browser Send did not finish"))
	}
	return result
}

// Separate from the staff editor's Add/preview/layout/undo/detach control.
// Actual public Send, native retention/invitations, visible package review and
// both signatures must complete before the backend accepts any browser receipt.
func TestPublicPackageFullCeremonyWithExternalBrowser256E2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Skip("explicit owned package browser required")
	}
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_PDF_WORKER_PATH", "HASH_E2E_RENDERER_URL"} {
		if os.Getenv(name) == "" {
			t.Fatalf("selected package browser requires %s", name)
		}
	}
	base, err := url.Parse(os.Getenv("HASH_SIGNER_PDF_BROWSER_BASE"))
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		t.Fatal("exact private HTTPS origin required")
	}
	front, input, done, artifacts := os.Getenv("HASH_SIGNER_PDF_BROWSER_FRONTEND"), os.Getenv("HASH_SIGNER_PDF_BROWSER_INPUT"), os.Getenv("HASH_SIGNER_PDF_BROWSER_DONE"), os.Getenv("HASH_SIGNER_PDF_BROWSER_ARTIFACTS")
	for _, path := range []string{front, input, done, artifacts} {
		if !filepath.IsAbs(path) {
			t.Fatal("absolute owned browser paths required")
		}
	}
	invites := filepath.Join(filepath.Dir(input), "ceremony-private256.json")
	if input == done || input == invites || done == invites {
		t.Fatal("distinct private browser handoffs required")
	}
	for _, path := range []string{input, done, invites} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("fresh private handoffs required")
		}
	}
	target, err := url.Parse(os.Getenv("HASH_E2E_RENDERER_URL"))
	if err != nil || target.Scheme != "http" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		t.Fatal("private actual renderer origin required")
	}
	probe, err := (&http.Client{Timeout: 5 * time.Second}).Get(target.String() + "/version")
	if err != nil {
		t.Fatal("actual renderer unavailable")
	}
	version, readErr := io.ReadAll(io.LimitReader(probe.Body, 256))
	_ = probe.Body.Close()
	if readErr != nil || probe.StatusCode != 200 || strings.TrimSpace(string(version)) != "8.36.0-hash.5" {
		t.Fatal("actual renderer version differs")
	}
	image := os.Getenv("HASH_E2E_RENDERER_IMAGE_ID")
	if !strings.HasPrefix(image, "sha256:") || len(image) != 71 {
		t.Fatal("root-bound renderer image required")
	}
	if b, e := hex.DecodeString(strings.TrimPrefix(image, "sha256:")); e != nil || len(b) != 32 {
		t.Fatal("invalid renderer image pin")
	}
	q := newOwnedAttachmentBrowserFixture228(t, base.String(), target.String())
	q.template = createBrandedDesignE2E(t, q.f, q.cookie)
	ownedCreationPrepareProPlanV1(t, q)
	if err := malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	root := packageImported220(t, q, "Browser services agreement")
	dpa := packageImported220(t, q, "Browser DPA")
	nda := packageImported220(t, q, "Browser NDA")
	parties := make([]packageBrowserParty256, 0, 2)
	for i, role := range []string{"provider", "customer"} {
		name := "Browser " + role
		raw, _ := json.Marshal(map[string]any{"email": role + "@package-browser.test", "name": name, "role": role, "locale": "en"})
		response := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/recipients", string(raw), q.cookie)
		var party recipientResponse
		if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &party) != nil || party.ID == uuid.Nil {
			t.Fatal("public browser recipient creation failed", response.Code)
		}
		field := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(field, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{"document_id": root.ID.String(), "type": "signature", "recipient_id": party.ID.String(), "page": 1, "required": true, "label": "Signature " + role, "x_pct": 20, "y_pct": 55 + 20*i, "w_pct": 45, "h_pct": 10}, nil))
		var output struct {
			ID uuid.UUID `json:"id"`
		}
		if field.Code != 201 || json.Unmarshal(field.Body.Bytes(), &output) != nil || output.ID == uuid.Nil {
			t.Fatal("public browser signature placement failed", field.Code)
		}
		parties = append(parties, packageBrowserParty256{RecipientID: party.ID, FieldID: output.ID, Name: name, Role: role})
	}
	root = packageLatest223(t, q, root.ID)
	originals := []*generated.Document{root, dpa, nda}
	keys := make(map[string]struct{}, 3)
	members := make([]packageBrowserMember256, 0, 3)
	for _, doc := range originals {
		if !doc.PdfStorageKey.Valid || !doc.PdfStorageVersionID.Valid || len(doc.PdfSha256) != 32 {
			t.Fatal("actual import lacks exact version tuple")
		}
		if _, dup := keys[doc.PdfStorageKey.String]; dup {
			t.Fatal("original key reused")
		}
		keys[doc.PdfStorageKey.String] = struct{}{}
		var intake struct {
			SchemaVersion int               `json:"schema_version"`
			Items         []sanitize.Report `json:"items"`
		}
		if json.Unmarshal(doc.MetadataRedactionReport, &intake) != nil || intake.SchemaVersion != 2 || len(intake.Items) != 1 || intake.Items[0].PDF == nil || intake.Items[0].PDF.PagesAfter != 1 || intake.Items[0].PDF.OutputSHA256 != hex.EncodeToString(doc.PdfSha256) {
			t.Fatal("genuine imported PDF intake tuple missing")
		}
		q.storagePeer.mu.Lock()
		raw := bytes.Clone(q.storagePeer.objects[doc.PdfStorageKey.String])
		q.storagePeer.mu.Unlock()
		digest := sha256.Sum256(raw)
		if len(raw) == 0 || !bytes.Equal(digest[:], doc.PdfSha256) || intake.Items[0].BytesAfter != int64(len(raw)) {
			t.Fatal("exact native import differs from actual stored PDF")
		}
		members = append(members, packageBrowserMember256{ID: doc.ID, SHA256: hex.EncodeToString(doc.PdfSha256), Bytes: int64(len(raw)), Pages: int32(intake.Items[0].PDF.PagesAfter)})
	}
	peer := &completedPackagePeer248{main: &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}, mainKey: root.PdfStorageKey.String, originalKeys: keys, until: make(map[string]time.Time)}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-package-browser", SecretKey: "synthetic-package-browser-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	q.f.s.Storage = client
	q.f.s.Send.Storage = client
	q.f.s.Sign.Storage = client
	for i, doc := range []*generated.Document{dpa, nda} {
		inventory := packageLayoutView226(t, q, root.ID)
		raw, _ := json.Marshal(map[string]any{"member_document_id": doc.ID.String(), "expected_updated_at": inventory.UpdatedAt, "expected_member_updated_at": doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_package_id": inventory.PackageID, "expected_generation": inventory.Generation, "ordinal": i + 1, "title": []string{"Data processing agreement", "Nondisclosure agreement"}[i], "category": []string{"DPA", "NDA"}[i]})
		selected := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/attachments", string(raw), q.cookie)
		if selected.Code != 201 {
			t.Fatal("public browser package selection failed", selected.Code)
		}
	}
	initial := packageLayoutView226(t, q, root.ID)
	initialPins := packageLayoutPins226(t, q, initial)
	if len(initial.Members) != 2 {
		t.Fatal("both actual annexes required")
	}
	beforeRetention := peer.main.counts240()
	shell, err := os.ReadFile(filepath.Join(front, "index.html"))
	if err != nil {
		t.Fatal("current built frontend required")
	}
	q.f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(front))
	q.f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if st, e := os.Stat(filepath.Join(front, clean)); e == nil && !st.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(front, "index.html"))
	})
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal("private package HTTPS unavailable")
	}
	server.Config.Handler = q.f.s.Routes()
	server.StartTLS()
	defer server.Close()
	if until, ok := q.f.ctx.Deadline(); !ok || time.Until(until) < 155*time.Second {
		t.Fatal("original fixture has insufficient browser budget")
	}
	workerCtx, cancelWorker := context.WithCancel(q.f.ctx)
	workerResults := make(chan packageBrowserWorkerResult256, 1)
	workerDone := make(chan struct{})
	cfg := packageCompletionConfig241(t, q)
	go func() {
		defer close(workerDone)
		workerResults <- packageBrowserWorker256(workerCtx, q, root.ID, client, cfg)
	}()
	defer func() {
		cancelWorker()
		select {
		case <-workerDone:
		case <-time.After(10 * time.Second):
			t.Error("original package worker last use did not join")
		}
	}()
	packet := map[string]any{"schema": 1, "base": base.String(), "rootID": root.ID, "dpaID": dpa.ID, "ndaID": nda.ID, "members": members, "parties": parties, "session": map[string]string{"name": SessionCookieName, "value": q.cookie}, "rendererImage": image}
	if err := packageBrowserPrivate256(input, packet); err != nil {
		t.Fatal("private package bootstrap failed")
	}
	defer os.Remove(input)
	defer os.Remove(invites)
	var meta pdfadmission.HTMLSendPackageIntentMetadataV1
	handoff := false
	deadline := time.NewTimer(150 * time.Second)
	defer deadline.Stop()
	wake := time.NewTicker(100 * time.Millisecond)
	defer wake.Stop()
	waiting := true
	for waiting {
		select {
		case result := <-workerResults:
			if handoff || result.err != nil || result.meta.AttemptID == uuid.Nil {
				t.Fatal("real browser package worker failed", result.err)
			}
			<-workerDone
			meta = result.meta
			packageCompletionActualEffects241(t, q, meta, "sent", 2)
			for i := range parties {
				parties[i].Token = signerPackageToken242(t, q, parties[i].RecipientID)
			}
			if err := packageBrowserPrivate256(invites, map[string]any{"schema": 1, "rootID": root.ID, "attemptID": meta.AttemptID, "parties": parties, "manifestSHA256": hex.EncodeToString(meta.Capture.CanonicalSHA256[:]), "legalSHA256": hex.EncodeToString(meta.Capture.CommitmentSHA256[:])}); err != nil {
				t.Fatal("private actual invitation handoff failed")
			}
			handoff = true
		case <-wake.C:
			doneFile, err := os.Open(done)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal("private browser completion unavailable")
			}
			raw, readErr := io.ReadAll(io.LimitReader(doneFile, 1025))
			err = errors.Join(readErr, doneFile.Close())
			if err != nil || len(raw) > 1024 {
				t.Fatal("bounded browser completion required")
			}
			var result struct {
				ExitCode int  `json:"exit_code"`
				Verified bool `json:"verified"`
			}
			var exact map[string]json.RawMessage
			if json.Unmarshal(raw, &result) != nil || json.Unmarshal(raw, &exact) != nil || len(exact) != 2 || result.ExitCode != 0 || !result.Verified || !handoff {
				t.Fatal("external package browser rejected ceremony")
			}
			waiting = false
		case <-deadline.C:
			t.Fatal("original package browser acceptance timed out")
		case <-q.f.ctx.Done():
			t.Fatal("original package fixture expired")
		}
	}
	<-workerDone
	completed := packageLatest223(t, q, root.ID)
	if completed.Status != "completed" || !completed.CompletionEffectiveAt.Valid || !completed.FinalPdfVersionID.Valid || !completed.AuditCertVersionID.Valid {
		t.Fatal("browser omitted actual terminal publication")
	}
	for _, doc := range originals {
		current := packageLatest223(t, q, doc.ID)
		if current.PdfStorageKey != doc.PdfStorageKey || current.PdfStorageVersionID != doc.PdfStorageVersionID || !bytes.Equal(current.PdfSha256, doc.PdfSha256) {
			t.Fatal("browser changed an exact original PDF")
		}
	}
	var finalGeneration int64
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT draft_generation FROM document_packages_v1 WHERE id=$1 AND document_id=$2 AND org_id=$3", meta.Capture.PackageID, root.ID, q.f.org).Scan(&finalGeneration); err != nil {
		t.Fatal(err)
	}
	finalInventory := initial
	finalInventory.Generation = strconv.FormatInt(finalGeneration, 10)
	if pins := packageLayoutPins226(t, q, finalInventory); len(pins) != 2 || pins[dpa.ID] != initialPins[dpa.ID] || pins[nda.ID] != initialPins[nda.ID] {
		t.Fatal("browser changed selected original pins")
	}
	var responses, reports, signatures, deliveries, confirmations, captures int
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT
 (SELECT count(*)::integer FROM document_package_responses_v1 WHERE document_id=$1),
 (SELECT count(*)::integer FROM document_participant_reports_v1 r JOIN documents d ON d.id=r.document_id AND d.org_id=r.org_id WHERE d.id=$1 AND d.org_id=$2 AND r.completion_effective_at=d.completion_effective_at AND r.final_pdf_sha256=d.final_pdf_sha AND r.audit_cert_sha256=d.audit_cert_sha256 AND r.audit_payload_sha256=d.audit_payload_sha256 AND r.audit_signature_sha256=d.audit_signature_sha256),
 (SELECT count(*)::integer FROM signatures WHERE document_id=$1),
 (SELECT count(*)::integer FROM document_participant_report_deliveries_v1 WHERE document_id=$1 AND org_id=$2),
 (SELECT count(*)::integer FROM document_lawful_basis_confirmations WHERE document_id=$1 AND org_id=$2),
 (SELECT count(*)::integer FROM document_package_captures_v1 WHERE document_id=$1 AND org_id=$2)`, root.ID, q.f.org).Scan(&responses, &reports, &signatures, &deliveries, &confirmations, &captures); err != nil || responses != 2 || reports != 1 || signatures != 2 || deliveries != 3 || confirmations != 1 || captures != 1 {
		t.Fatal("browser ceremony receipts incomplete", err, responses, reports, signatures, deliveries, confirmations, captures)
	}
	confirmed, err := q.f.q.GetDocumentLawfulBasisConfirmation(q.f.ctx, generated.GetDocumentLawfulBasisConfirmationParams{DocumentID: root.ID, OrgID: q.f.org})
	if err != nil || confirmed == nil || confirmed.LawfulBasis != "contract" || !confirmed.ConfirmedBy.Valid || uuid.UUID(confirmed.ConfirmedBy.Bytes) != q.f.user.ID || strings.TrimSpace(confirmed.ControllerName) == "" || strings.TrimSpace(confirmed.ControllerContact) == "" {
		t.Fatal("actual controller instruction/disclosure missing", err)
	}
	report, err := readDocumentArtifact(q.f.ctx, client, completed, completed.AuditCertKey.String, completed.AuditCertSha256, completed.AuditCertVersionID)
	if err != nil || !bytes.HasPrefix(report, []byte("%PDF-")) {
		t.Fatal("exact mandatory report unavailable", err)
	}
	payload, err := readDocumentArtifact(q.f.ctx, client, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
	if err != nil {
		t.Fatal(err)
	}
	detached, err := readDocumentArtifact(q.f.ctx, client, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
	if err != nil || !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(detached)) {
		t.Fatal("mandatory report detached signature failed", err)
	}
	rows, err := q.f.q.ListChainedEventsPageForOrg(q.f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: q.f.org, PageLimit: 1000})
	if err != nil || len(rows) == 0 || len(rows) >= 1000 {
		t.Fatal("full browser chain unavailable", err)
	}
	chain := audit.NewChainVerifier()
	chain.VerifyPage(rows)
	if result := chain.Result(); !result.OK || !result.Complete {
		t.Fatal("actual package browser chain invalid")
	}
	afterRetention := peer.main.counts240()
	if afterRetention[2]-beforeRetention[2] < 6 || afterRetention[3]-beforeRetention[3] < 3 || afterRetention[4]-beforeRetention[4] < 3 {
		t.Fatal("every original policy was not read/extended/re-read")
	}
	peer.main.mu.Lock()
	providerErr := peer.main.failure
	for key := range keys {
		if peer.main.until[key].Before(meta.RetainUntil) {
			providerErr = errors.Join(providerErr, errors.New("original retention omitted"))
		}
	}
	peer.main.mu.Unlock()
	if providerErr != nil {
		t.Fatal("strict native package protocol failed", providerErr)
	}
	q.assertObserversOnlyV1(t)
	if err := os.MkdirAll(artifacts, 0700); err != nil {
		t.Fatal(err)
	}
	safe := map[string]any{"schema": 1, "passed": true, "root_id": root.ID, "attempt_id": meta.AttemptID, "captured_package_id": meta.Capture.PackageID, "captured_generation": strconv.FormatInt(meta.Capture.DraftGeneration, 10), "captured_root_updated_at": meta.Capture.RootUpdatedAt.UTC().Format(time.RFC3339Nano), "members": members, "responses": responses, "signatures": signatures, "reports": reports, "deliveries": deliveries, "controller_confirmations": confirmations, "captures": captures, "organization_chain_verified": true, "originals_unchanged": true, "actual_worker_joined": true, "retention_verified": true, "detached_report_signature_verified": true, "final_pdf_sha256": hex.EncodeToString(completed.FinalPdfSha), "audit_cert_sha256": hex.EncodeToString(completed.AuditCertSha256), "renderer_image": image, "scope": "Actual controlled browser/public Send/package consent/signatures/archive. Synthetic auth/storage/mail delivery boundary only; no configured service or release acceptance."}
	if err := packageBrowserPrivate256(filepath.Join(artifacts, "package-browser-backend256.json"), safe); err != nil {
		t.Fatal(err)
	}
}
