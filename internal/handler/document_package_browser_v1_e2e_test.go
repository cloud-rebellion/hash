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
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sanitize"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/bright-interaction/hash/internal/workguard"
	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Separate staff fixture; original signing tests and four-minute lifetime retained.
func newOwnedAttachmentBrowserFixture228(t *testing.T, publicURL, rendererURL string) *ownedPublicReadFixtureV1 {
	const withLifecycleDocument = false // fresh current-native fixture, no unrelated legacy document
	t.Helper()
	birth := browserFixtureContext368(t) // before isolated DB, pool and native authority exist
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_PDF_WORKER_PATH"} {
		if os.Getenv(name) == "" {
			t.Fatalf("selected owned public signer fixture requires %s", name)
		}
	}
	dsn, err := url.Parse(os.Getenv("HASH_E2E_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	params := dsn.Query()
	params.Set("statement_timeout", "5000")
	params.Set("lock_timeout", "3000")
	params.Set("idle_in_transaction_session_timeout", "15000")
	dsn.RawQuery = params.Encode()
	t.Setenv("HASH_E2E_DB_URL", dsn.String())
	database := isolateHTMLTemplateDatabaseE2E(t)
	isolatedDSN := os.Getenv("HASH_E2E_DB_URL")
	application := ""
	// Registered before the base pool: its actual Close runs first. This one
	// independent synthetic-admin witness never credits runtime resources.
	t.Cleanup(func() {
		if application == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cfg, err := pgx.ParseConfig(isolatedDSN)
		if err != nil {
			t.Error(err)
			return
		}
		cfg.RuntimeParams["application_name"] = "hash_owned_read_independent_witness"
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Error("independent backend witness", err)
			return
		}
		defer func() {
			closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = conn.Close(closeCtx)
		}()
		var count int
		if err := conn.QueryRow(ctx, "SELECT count(*)::integer FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", application).Scan(&count); err != nil || count != 0 {
			t.Errorf("fixture pool/native backends survived joined close: count=%d err=%v", count, err)
		} //nolint:rawsql -- exact unique test pool/factory backend witness only
	})
	var f lifecycleAuthorizationFixture
	if withLifecycleDocument {
		f = setupLifecycleAuthorizationE2E(t, "owner", false, false)
	} else {
		ctx, pool, q, s, org, id := setupDSRBrowserBirth368E2E(t, birth)
		user, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: id, OrgID: org, Role: "owner"})
		if err != nil {
			t.Fatal(err)
		}
		f = lifecycleAuthorizationFixture{ctx: ctx, pool: pool, q: q, s: s, org: org, user: user}
	}
	application = f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	// The original four-minute browser owner was created before migration and
	// pool/runtime birth. Do not reparent or extend an admitted90s fixture.
	ctx := f.ctx
	f.s.PublicURL = publicURL
	// Same whole-disposable-estate cleanup as the existing authoring fixtures;
	// this does not weaken immutable history guards or authorize production erase.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var actual string
		if err := f.pool.QueryRow(ctx, "SELECT current_database()").Scan(&actual); err != nil || actual != database || !strings.HasPrefix(actual, "hash_html_e2e_") {
			t.Error("refuse non-owned history disposal", err)
			return
		}
		if _, err := f.pool.Exec(ctx, "TRUNCATE orgs CASCADE"); err != nil {
			t.Error(err)
		} //nolint:rawsql -- all rows in this unique synthetic DB
	})
	// Controlled logical-work integration profile, matching the existing
	// authoring fixture. Retained stored-template compilations alone raise the
	// two-reader Parent overlap floor above448MiB. Actual peaks remain checked
	// below; this is not a production default or physical capacity claim.
	// One actual shared SDK stream is enabled for the new concrete Send Client.
	// Byte/DB/grant caps are unchanged; this synthetic protocol slot proves no
	// live provider Object Lock or physical process/provider capacity.
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, ChildAddressBytes: 2 << 30, PDFWorkers: 1, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, ChildAddressBytes: 2 << 30, PDFWorkers: 1, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1}, MaxGrants: 128, MaxOrganisationGrants: 64}
	runtime, err := pdfadmission.NewWorkRuntimeV1(f.pool, limits, int64(f.pool.Config().MaxConns)+8)
	if err != nil {
		t.Fatal(err)
	}
	f.s.HTMLCreationSessions = runtime.SessionsV1()
	q := &ownedPublicReadFixtureV1{f: f, runtime: runtime}
	pdfapi.DisableConfigDir()
	if err := sanitize.ConfigurePDFWorker(ctx, os.Getenv("HASH_E2E_PDF_WORKER_PATH"), "production"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sanitize.ConfigurePDFWorker(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: "pro", ReviewRef: "synthetic owned-read qualification entitlement"}})
	f.s.Versions = versions.New(f.q)
	peer := &htmlCreationStorageE2E{importStoragePeer: &importStoragePeer{objects: make(map[string][]byte)}}
	q.storagePeer = peer
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	f.s.Storage, err = storage.New(ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-owned-read", SecretKey: "synthetic-owned-read-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	theme := branding.NewResolver(f.q)
	f.s.BrandingResolver = theme
	f.s.OperatorName = "Synthetic owned-read operator"
	f.s.PrivacyContact = "privacy@hash.example.test"
	f.s.SupervisoryAuthority = "Synthetic authority"
	f.s.PrivacyPolicyURL = f.s.PublicURL + "/legal/privacy"
	f.s.Sign = &sign.Engine{Pool: f.pool, Queries: f.q, WorkRuntime: runtime, Storage: f.s.Storage, PDF: render.NewGotenberg(rendererURL), Audit: f.s.Audit, Mailer: dispatch.QueueingMailer{Q: f.q}, Signer: signer, BaseURL: f.s.PublicURL, OrgName: f.s.OperatorName, BrandingCSS: func(ctx context.Context, doc *generated.Document) (string, error) {
		b, err := theme.ResolveFrozen(ctx, doc.ID)
		if err != nil {
			return "", err
		}
		return b.CSSVariables(), nil
	}}
	if err := f.s.Sign.InitializeWorkRuntimeV1(); err != nil {
		t.Fatal(err)
	}
	f.s.Send = &sendengine.Engine{Pool: f.pool, Queries: f.q, Storage: f.s.Storage, WorkRuntime: runtime, Audit: f.s.Audit, Mailer: dispatch.QueueingMailer{Q: f.q}, Resolver: resolver.New(f.q, ownedFrozenReadSourceV1{fetches: &q.fetches}), PublicURL: f.s.PublicURL, OrgName: f.s.OperatorName}
	q.f = f
	q.cookie = dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := f.s.Sign.CloseWorkRuntimeRequestsV1(cleanup); err != nil {
			t.Error("journal cleanup", err)
		}
		observers := runtime.SessionsV1().PendingV1().ObserverSessions
		t.Logf("native runtime before original cleanup: %+v", runtime.SessionsV1().StartStateE2EV1())
		err := runtime.CloseV1(cleanup)
		t.Logf("native runtime after original cleanup: %+v", runtime.SessionsV1().StartStateE2EV1())
		pending := runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.SignerScopes != 0 || pending.SignerReaders != 0 || pending.ObserverSessions != observers {
			t.Errorf("retained actual runtime cleanup wrong: %+v", pending)
		}
		if observers > 0 && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Errorf("last observer debt falsely resolved: %v", err)
		} else if observers == 0 && err != nil {
			t.Error(err)
		}
		snap, snapErr := runtime.SnapshotV1(f.org)
		expected := workguard.VectorV1{SQLSessions: int64(observers)}
		if snapErr != nil || snap.Global != expected || snap.GlobalGrants != int64(observers) {
			t.Errorf("observer grants lost or real work leaked: %+v err=%v", snap, snapErr)
		}
	})
	return q
}

func TestDocumentPackageStaffEditorWithExternalBrowser228E2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Skip("explicit external signer browser fixture required")
	}
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_PDF_WORKER_PATH", "HASH_E2E_RENDERER_URL"} {
		if os.Getenv(name) == "" {
			t.Fatalf("selected real signer browser fixture requires %s", name)
		}
	}
	base, err := url.Parse(os.Getenv("HASH_SIGNER_PDF_BROWSER_BASE"))
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		t.Fatal("signer browser fixture requires exact loopback HTTPS origin")
	}
	root, inputPath, donePath, artifacts := os.Getenv("HASH_SIGNER_PDF_BROWSER_FRONTEND"), os.Getenv("HASH_SIGNER_PDF_BROWSER_INPUT"), os.Getenv("HASH_SIGNER_PDF_BROWSER_DONE"), os.Getenv("HASH_SIGNER_PDF_BROWSER_ARTIFACTS")
	for _, path := range []string{root, inputPath, donePath, artifacts} {
		if !filepath.IsAbs(path) {
			t.Fatal("signer browser fixture requires absolute task-owned paths")
		}
	}
	if inputPath == donePath {
		t.Fatal("private input and completion paths must differ")
	}
	for _, path := range []string{inputPath, donePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("signer browser handoff paths must be fresh")
		}
	}
	target, err := url.Parse(os.Getenv("HASH_E2E_RENDERER_URL"))
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		t.Fatal("explicit real renderer origin required")
	}
	imageID := os.Getenv("HASH_E2E_RENDERER_IMAGE_ID")
	if len(imageID) != 71 || !strings.HasPrefix(imageID, "sha256:") {
		t.Fatal("selected fixture requires root-recorded actual renderer image ID")
	}
	if raw, err := hex.DecodeString(strings.TrimPrefix(imageID, "sha256:")); err != nil || len(raw) != sha256.Size {
		t.Fatal("invalid root-recorded renderer image ID")
	}
	// This is a required fixture input, not self-verifying image authority. The
	// outer owned runner must bind this ID/source to the probed current service.
	probeClient := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	probe, err := probeClient.Get(target.String() + "/version")
	if err != nil {
		t.Fatal("required exact renderer unavailable")
	}
	version, readErr := io.ReadAll(io.LimitReader(probe.Body, 256))
	_ = probe.Body.Close()
	if readErr != nil || probe.StatusCode != http.StatusOK || strings.TrimSpace(string(version)) != "8.36.0-hash.5" {
		t.Fatal("required source-built renderer version differs")
	}

	q := newOwnedAttachmentBrowserFixture228(t, base.String(), target.String())
	q.template = createBrandedDesignE2E(t, q.f, q.cookie)
	ownedCreationPrepareProPlanV1(t, q)
	if e := malwarescan.Configure(q.f.ctx, "", "development"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := malwarescan.Configure(context.Background(), "", "development"); e != nil {
			t.Error(e)
		}
	})
	main := packageImported220(t, q, "Main attachment browser")
	a := packageImported220(t, q, "Frozen NDA browser")
	b := packageImported220(t, q, "Browser candidate DPA")
	if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Browser candidate DPA' WHERE id=$1 AND org_id=$2", b.ID, q.f.org); e != nil {
		t.Fatal(e)
	}
	b = packageLatest223(t, q, b.ID)
	var selected map[string]any
	packageAPIReply225(t, packageAPISubmit225(q, "REST", "add_document_attachment", main.ID, "", packageAPIArguments225(t, [2]*generated.Document{main, a}, "REST")), "REST", http.StatusCreated, &selected)
	initial := packageLayoutView226(t, q, main.ID)
	initialPins := packageLayoutPins226(t, q, initial)
	if initial.Generation != "2" || len(initial.Members) != 1 || initial.Members[0].DocumentID != a.ID {
		t.Fatal("initial selected member missing")
	}
	peer := packagePreviewStorage227(t, q, a, "", false)
	laterSHA := sha256.Sum256(peer.later)
	if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Later source',pdf_storage_version_id='later-same-key-v2',pdf_sha256=$3 WHERE id=$1 AND org_id=$2", a.ID, q.f.org, laterSHA[:]); e != nil {
		t.Fatal(e)
	}
	shell, e := os.ReadFile(filepath.Join(root, "index.html"))
	if e != nil {
		t.Fatal("fresh built attachment frontend required")
	}
	q.f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(root))
	q.f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if st, e := os.Stat(filepath.Join(root, clean)); e == nil && !st.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, e = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if e != nil {
		t.Fatal("private task HTTPS listener unavailable")
	}
	server.Config.Handler = q.f.s.Routes()
	server.StartTLS()
	defer server.Close()
	if until, ok := q.f.ctx.Deadline(); !ok || time.Until(until) < 155*time.Second {
		t.Fatal("original four-minute fixture has insufficient150-second browser budget")
	}
	m := initial.Members[0]
	packet, e := json.Marshal(map[string]any{"schema": 1, "base": base.String(), "rootID": main.ID, "sourceAID": a.ID, "sourceBID": b.ID, "sourceBName": b.Name, "session": map[string]string{"name": SessionCookieName, "value": q.cookie}, "selectedA": map[string]any{"version": m.PDFVersionID, "sha256": m.PDFSHA256, "bytes": m.PDFBytes, "pages": m.PDFPages}, "laterASHA256": hex.EncodeToString(laterSHA[:])})
	if e != nil || len(packet) > 65536 {
		t.Fatal("private staff packet bound")
	}
	privateInput, e := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal("create fresh private staff packet")
	}
	n, writeErr := privateInput.Write(packet)
	closeErr := privateInput.Close()
	defer os.Remove(inputPath)
	if writeErr != nil || closeErr != nil || n != len(packet) {
		t.Fatal("write private staff packet")
	}
	deadline := time.Now().Add(150 * time.Second)
	for {
		if q.f.ctx.Err() != nil || !time.Now().Before(deadline) {
			t.Fatal("external staff browser acceptance timed out")
		}
		var body []byte
		doneFile, openErr := os.Open(donePath)
		e := openErr
		if openErr == nil {
			body, e = io.ReadAll(io.LimitReader(doneFile, 1025))
			closeErr := doneFile.Close()
			if e == nil {
				e = closeErr
			}
			if len(body) > 1024 {
				t.Fatal("browser completion exceeds bound")
			}
		}
		if e == nil {
			var done map[string]json.RawMessage
			decoder := json.NewDecoder(bytes.NewReader(body))
			if decoder.Decode(&done) != nil || decoder.Decode(new(any)) != io.EOF || len(done) != 2 || string(done["exit_code"]) != "0" || string(done["verified"]) != "true" {
				t.Fatal("external staff browser rejected journey")
			}
			if q.f.ctx.Err() != nil || !time.Now().Before(deadline) {
				t.Fatal("external staff browser acceptance timed out")
			}
			break
		}
		if !os.IsNotExist(e) || q.f.ctx.Err() != nil || time.Now().After(deadline) {
			t.Fatal("external staff browser acceptance timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}
	final := packageLayoutView226(t, q, main.ID)
	if final.PackageID != initial.PackageID || final.Generation != "7" || len(final.Members) != 1 {
		t.Fatal("browser did not complete exact add/layout/detach sequence")
	}
	m = final.Members[0]
	if m.DocumentID != a.ID || m.Ordinal != 1 || m.Title != "Browser frozen NDA" || m.Category != "NDA" || packageLayoutPins226(t, q, final)[a.ID] != initialPins[a.ID] {
		t.Fatal("final labels/order/frozen tuple changed")
	}
	if peer.heads.Load() < 1 || peer.gets.Load() < 1 {
		t.Fatal("browser did not fetch exact old selected version")
	}
	rootNow := packageLatest223(t, q, main.ID)
	bNow := packageLatest223(t, q, b.ID)
	if rootNow.Status != "draft" || rootNow.PdfStorageKey != main.PdfStorageKey || rootNow.PdfStorageVersionID != main.PdfStorageVersionID || !bytes.Equal(rootNow.PdfSha256, main.PdfSha256) || bNow.Status != "draft" || bNow.DeletedAt.Valid || bNow.ParentEnvelopeID.Valid {
		t.Fatal("root source or detached source changed")
	}
	events, e := q.f.q.ListEventsByDocument(q.f.ctx, generated.ListEventsByDocumentParams{DocumentID: pgtype.UUID{Bytes: main.ID, Valid: true}, Limit: 10001})
	if e != nil || len(events) == 0 || len(events) >= 10001 {
		t.Fatal("complete root events unavailable", e)
	}
	adds, layouts := 0, 0
	for _, event := range events {
		switch event.Kind {
		case "document.attachment_added":
			adds++
		case "document.attachments_updated":
			layouts++
		case audit.KindDocumentSent, audit.KindDocumentSigned, audit.KindDocumentCompleted:
			t.Fatal("staff editor activated a ceremony")
		default:
			continue
		}
		if !event.ActorUserID.Valid || event.ActorUserID.Bytes != [16]byte(q.f.user.ID) {
			t.Fatal("attachment audit lost staff actor")
		}
	}
	if adds != 2 || layouts != 2 {
		t.Fatal("unexpected attachment mutation audit counts", adds, layouts)
	}
	rows, e := q.f.q.ListChainedEventsPageForOrg(q.f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: q.f.org, PageLimit: 1000})
	if e != nil || len(rows) == 0 || len(rows) >= 1000 {
		t.Fatal("complete chain unavailable", e)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(rows)
	if result := verifier.Result(); !result.OK || !result.Complete {
		t.Fatal("actual organization chain invalid")
	}
	ownedPlainAssertDrainedV1(t, q)
	if e := os.MkdirAll(artifacts, 0700); e != nil {
		t.Fatal(e)
	}
	safe, e := json.MarshalIndent(map[string]any{"schema": 1, "passed": true, "root_id": main.ID, "selected_member": m, "package_generation": final.Generation, "attachment_added_events": adds, "attachment_layout_events": layouts, "organization_chain_verified": true, "original_root_pdf_unchanged": true, "detached_source_retained": true, "renderer_image": imageID, "scope": "Synthetic local staff editor acceptance; no signing ceremony, provider or release acceptance."}, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(artifacts, "attachment-editor-backend.json"), safe, 0600); e != nil {
		t.Fatal(e)
	}
}
