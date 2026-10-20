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
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	evidenceverify "github.com/bright-interaction/hash/internal/evidence"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sanitize"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"io"
	"math"
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

// Source-only new fixture. The original67/78 test and production files remain
// unchanged. Root must separately build/fence/probe the exact .2 image, production
// worker and built frontend, then supply the real external browser. Version/image
// fixture inputs alone are not release or runtime availability authority.
// Same existing logical limits and old external-browser4min/150s bounds; normal
// renderer60s and worker15s deadlines remain untouched. No SMTP worker is started.
func newOwnedRealRenderBrowserFixtureV1(t *testing.T, publicURL, rendererURL string) *ownedPublicReadFixtureV1 {
	const withLifecycleDocument = false // fresh current-native fixture, no unrelated legacy document
	t.Helper()
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
		ctx, pool, q, s, org, id := setupDSRE2E(t)
		user, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: id, OrgID: org, Role: "owner"})
		if err != nil {
			t.Fatal(err)
		}
		f = lifecycleAuthorizationFixture{ctx: ctx, pool: pool, q: q, s: s, org: org, user: user}
	}
	application = f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	ctx, cancel := context.WithTimeout(f.ctx, 4*time.Minute)
	t.Cleanup(cancel)
	f.ctx = ctx
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
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1}, MaxGrants: 128, MaxOrganisationGrants: 64}
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

// This autosave control uses the real public intake/field/Send writers. No raw
// legacy document/recipient/field insertion supplies native source authority.
func ownedRealBrowserManualAutosaveV1(t *testing.T, q *ownedPublicReadFixtureV1, sourcePDF []byte, pageCount int, actor sendengine.Actor) (*generated.Document, *generated.Recipient, *generated.DocumentField, *generated.DocumentField, *url.URL) {
	t.Helper()
	f := q.f
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Billing: f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: f.s.PublicURL})
	// Malware-provider acceptance is separate; the source-built production PDF
	// worker is still mandatory and handles the genuine imported PDF bytes.
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, sourcePDF))
	var imported struct {
		Document  documentResponse `json:"document"`
		PageCount int              `json:"page_count"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &imported) != nil || imported.Document.ID == uuid.Nil || imported.PageCount != pageCount {
		t.Fatalf("actual browser autosave PDF intake=%d", response.Code)
	}
	legacy, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: imported.Document.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.SourceKind != "pdf" || !legacy.EvidenceVersionPinsRequired || !legacy.PdfStorageKey.Valid || !legacy.PdfStorageVersionID.Valid || len(legacy.PdfSha256) != sha256.Size || len(legacy.HtmlSourceJson) != 0 {
		t.Fatal("actual autosave source lacks genuine manual intake pins")
	}
	response = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+legacy.ID.String()+"/recipients", `{"email":"autosave@example.test","name":"Synthetic Autosave Person","role":"signer","locale":"en"}`, q.cookie)
	if response.Code != http.StatusCreated {
		t.Fatalf("actual autosave party=%d", response.Code)
	}
	recipients, err := f.q.ListRecipientsByDocument(f.ctx, legacy.ID)
	if err != nil || len(recipients) != 1 {
		t.Fatal("actual autosave party identity missing", err)
	}
	party := recipients[0]
	key, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
	// The imported real schema3 source has empty signature slots at42–49% and79–86%.
	// Keep this manual control strictly inside those blanks rather than over party identity text.
	for _, spec := range []struct {
		kind, label string
		y, h        int
	}{{"text", "Reviewed reference", 4300, 500}, {"signature", "Visible autosave signature", 8000, 500}} {
		response = httptest.NewRecorder()
		f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "MCP", "add_document_field", key.Plaintext, map[string]any{"document_id": legacy.ID.String(), "recipient_id": party.ID.String(), "type": spec.kind, "page": pageCount, "x_pct": 1200, "y_pct": spec.y, "w_pct": 6500, "h_pct": spec.h, "required": "true", "label": spec.label}, nil))
		fieldMCPTextE2E(t, response, false)
		ownedPlainAssertDrainedV1(t, q)
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, legacy.ID)
	if err != nil || len(fields) != 2 {
		t.Fatal("actual autosave fields missing", err)
	}
	var text, signature *generated.DocumentField
	for _, field := range fields {
		if !field.RecipientID.Valid || uuid.UUID(field.RecipientID.Bytes) != party.ID {
			t.Fatal("autosave field lost its intended party")
		}
		if field.Type == "text" {
			text = field
		} else if field.Type == "signature" {
			signature = field
		}
	}
	if text == nil || signature == nil {
		t.Fatal("actual text/signature writer omitted autosave controls")
	}
	sent, err := f.s.Send.Send(f.ctx, actor, legacy.ID)
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 1 {
		t.Fatal("actual native autosave Send failed", err)
	}
	invitation, err := url.Parse(strings.Clone(sent.Links[0].URL))
	if err != nil {
		t.Fatal(err)
	}
	sent.CloseConsumerV1()
	ownedPlainAssertDrainedV1(t, q)
	return legacy, party, text, signature, invitation
}

func ownedRealBrowserFieldGeometryV1(t *testing.T, fields []*generated.DocumentField) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(fields))
	pct := func(value pgtype.Numeric) float64 {
		got, err := value.Float64Value()
		if err != nil || !got.Valid || math.IsNaN(got.Float64) || math.IsInf(got.Float64, 0) {
			t.Fatal("non-finite actual field percentage")
		}
		return got.Float64
	}
	for _, field := range fields {
		out = append(out, map[string]any{"id": field.ID, "recipient_id": uuid.UUID(field.RecipientID.Bytes), "type": field.Type, "page": field.Page, "x_pct": pct(field.XPct), "y_pct": pct(field.YPct), "w_pct": pct(field.WPct), "h_pct": pct(field.HPct)})
	}
	return out
}

// All reads below are independent post-completion test oracles. They do not
// create a source grant, intent, measurement, retention proof or native READY.
func ownedRealBrowserArtifactsV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, label, directory string, expectedPages int) (map[string]string, []map[string]any) {
	t.Helper()
	f := q.f
	type artifact struct {
		name, prefix string
		key, version pgtype.Text
		digest       []byte
	}
	outputs := []artifact{
		{label + "-source.pdf", "source", doc.PdfStorageKey, doc.PdfStorageVersionID, doc.PdfSha256},
		{label + "-final.pdf", "final_pdf", doc.FinalPdfKey, doc.FinalPdfVersionID, doc.FinalPdfSha},
		{label + "-certificate.pdf", "audit_cert", doc.AuditCertKey, doc.AuditCertVersionID, doc.AuditCertSha256},
		{label + "-certificate-payload.html", "audit_payload", doc.AuditPayloadKey, doc.AuditPayloadVersionID, doc.AuditPayloadSha256},
		{label + "-certificate-signature.txt", "audit_signature", doc.AuditSignatureKey, doc.AuditSignatureVersionID, doc.AuditSignatureSha256},
	}
	hashes := make(map[string]string, len(outputs))
	tuples := make([]map[string]any, 0, len(outputs))
	bodies := make([][]byte, 0, len(outputs))
	for _, output := range outputs {
		if !output.key.Valid || !output.version.Valid || strings.TrimSpace(output.version.String) == "" || len(output.digest) != sha256.Size {
			t.Fatal("actual completed artifact pin missing", output.prefix)
		}
		body, err := readDocumentArtifact(f.ctx, f.s.Storage, doc, output.key.String, output.digest, output.version)
		if err != nil {
			t.Fatal("exact real-rendered artifact read", err)
		}
		digest := sha256.Sum256(body)
		if !bytes.Equal(digest[:], output.digest) {
			t.Fatal("artifact read changed its committed digest")
		}
		if strings.HasSuffix(output.name, ".pdf") {
			if !bytes.HasPrefix(body, []byte("%PDF-")) {
				t.Fatal("real-rendered PDF header missing")
			}
			count, err := sanitize.PageCountWithContext(f.ctx, body)
			if err != nil || count < 1 {
				t.Fatal("actual worker could not count completed PDF", err)
			}
			if output.prefix != "audit_cert" && count != expectedPages {
				t.Fatal("source/final page count changed")
			}
		}
		if err := os.WriteFile(filepath.Join(directory, output.name), body, 0600); err != nil {
			t.Fatal("write private synthetic artifact")
		}
		hashes[output.name] = hex.EncodeToString(digest[:])
		bodies = append(bodies, body)
		tuples = append(tuples, map[string]any{"name": output.name, "prefix": output.prefix, "key": output.key.String, "version_id": output.version.String, "sha256": hex.EncodeToString(digest[:])})
	}
	if !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(bodies[3]), string(bodies[4])) {
		t.Fatal("exact detached certificate signature differs")
	}
	claims, err := evidenceverify.ParseCertificateCommitments(bodies[3])
	if err != nil || claims.DocumentID != doc.ID.String() || claims.OrgID != doc.OrgID.String() || claims.FinalPDFSHA256 != hex.EncodeToString(doc.FinalPdfSha) || claims.CompletionEffectiveAt != doc.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano) || claims.DocumentEventsScope != "ceremony-root" || claims.PreFinalChainScope != "organization" {
		t.Fatal("canonical signed HTML certificate commitments differ", err)
	}
	events, err := f.q.ListEventsByDocument(f.ctx, generated.ListEventsByDocumentParams{DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, Limit: 10001})
	if err != nil || len(events) > 10000 {
		t.Fatal("complete actual root event set unavailable", err)
	}
	preFinal := make([]*generated.Event, 0, len(events))
	var terminal *generated.Event
	for _, event := range events {
		if event.Kind == audit.KindDocumentCompleted {
			if terminal != nil {
				t.Fatal("multiple terminal events")
			}
			terminal = event
		} else {
			preFinal = append(preFinal, event)
		}
	}
	if terminal == nil {
		t.Fatal("terminal event missing")
	}
	_, eventSHA, eventCount, err := evidenceverify.BuildCeremonyEventsJSON(doc.ID, preFinal)
	if err != nil || eventSHA != claims.DocumentEventsSHA256 || eventCount != claims.DocumentEventsCount {
		t.Fatal("signed root-event commitment differs", err)
	}
	var terminalPins map[string]any
	if json.Unmarshal(terminal.PayloadHashed, &terminalPins) != nil {
		t.Fatal("hashed terminal payload invalid")
	}
	chainRows, chainErr := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: doc.OrgID, PageLimit: 1000})
	if chainErr != nil {
		t.Fatal("actual organization prefix unavailable", chainErr)
	}
	if err := ownedRealBrowserClaimsMatchChainV1(doc, terminal, preFinal, claims, chainRows); err != nil {
		t.Fatal(err)
	}
	for _, output := range outputs[1:] {
		if terminalPins[output.prefix+"_key"] != output.key.String || terminalPins[output.prefix+"_version_id"] != output.version.String || terminalPins[output.prefix+"_sha256"] != hex.EncodeToString(output.digest) {
			t.Fatal("one of twelve terminal pins changed", output.prefix)
		}
	}
	return hashes, tuples
}

func TestOwnedRealRenderedSignerFourArtifactsWithExternalBrowserE2E(t *testing.T) {
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

	q := newOwnedRealRenderBrowserFixtureV1(t, base.String(), target.String())
	f := q.f
	ctx := f.ctx
	cookie := q.cookie
	input, _, _ := testfixture.HTMLContract(t)
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal("decode synthetic profile")
	}
	input.Values["provider_name"], input.Values["customer_name"] = "Syntetisk Åsa Provider", "Syntetisk Zoë Customer"
	input.Values["scope"] = strings.Repeat("Reviewed synthetic scope: reliable service, approved wording, ÅÄÖ and café.\n", 65)
	for i := range master.Values {
		if master.Values[i].Name == "scope" {
			master.Values[i].MaxChars = htmlmaster.MaxValueChars
		}
	}
	master.HTML = strings.Replace(master.HTML, `<p><span data-hash-value="scope"></span></p>`, `<section class="scope"><span data-hash-value="scope"></span></section>`, 1)
	// Explicit schema3 requires a fresh full-page approval and creates both
	// server-owned fields. The master cannot style the app-owned suffix.
	master.SchemaVersion = htmlmaster.SigningPageSchemaVersion
	master.SigningPage = testfixture.BrandedSigningPolicy()
	master.CSS = `@page{size:A4;margin:20mm}body{font-family:Inter,sans-serif;font-size:12pt;color:#102038}p{line-height:1.35}.scope{white-space:pre-wrap;line-height:1.5}`
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatalf("synthetic real-rendered design preflight: %v", err)
	}
	if _, err := compiled.Materialize(htmlmaster.Input{Values: input.Values, Sections: input.Sections}); err != nil {
		t.Fatalf("synthetic real-rendered values preflight: %v", err)
	}
	masterJSON, _ := json.Marshal(master)
	defaults, _ := json.Marshal(input.Values)
	beforeCreatePending := q.runtime.SessionsV1().PendingV1()
	beforeCreateOwners := q.runtime.SessionsV1().StartStateE2EV1()
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "Real-rendered synthetic two-party review", HTMLMasterJSON: masterJSON, VariablesJSON: defaults}, cookie)
	if w.Code != http.StatusCreated {
		t.Logf("create response after authoring cleanup: status=%d content_type=%q body_bytes=%d body_sha256=%x pending_before=%+v owners_before=%+v pending_after=%+v owners_after=%+v", w.Code, w.Header().Get("Content-Type"), w.Body.Len(), sha256.Sum256(w.Body.Bytes()), beforeCreatePending, beforeCreateOwners, q.runtime.SessionsV1().PendingV1(), q.runtime.SessionsV1().StartStateE2EV1())
		t.Fatalf("real profile design creation status=%d", w.Code)
	}
	var templateDTO templateResponse
	if json.Unmarshal(w.Body.Bytes(), &templateDTO) != nil {
		t.Fatal("decode created design")
	}
	template, err := f.q.GetHTMLTemplate(ctx, generated.GetHTMLTemplateParams{ID: templateDTO.ID, OrgID: f.org})
	if err != nil {
		t.Fatal("read created design")
	}
	q.template = template
	// Match the existing manual-PDF fixture: prepare the actual legacy pro
	// catalog through its bounded native owner before manual intake. Its real
	// process observer joins the authoring observer; no count or grant is faked.
	ownedCreationPrepareProPlanV1(t, q)
	preview := submitHTMLPreviewE2E(t, f, template, nil, cookie)
	if preview.Code != http.StatusOK {
		t.Fatalf("actual-renderer owner preview status=%d", preview.Code)
	}
	approval := htmlApprovalInputE2E(template)
	approval.PreviewReceipt, approval.ExpectedPreviewPDFSHA256 = preview.Header().Get("X-Hash-Preview-Receipt"), preview.Header().Get("X-Hash-PDF-SHA256")
	if approval.PreviewReceipt == "" || !htmlPreviewSHA256(approval.ExpectedPreviewPDFSHA256) {
		t.Fatal("actual owner preview proof missing")
	}
	if w := submitHTMLTemplateE2E(t, f, "approve", template.ID, approval, cookie); w.Code != http.StatusOK {
		t.Fatalf("actual preview approval status=%d", w.Code)
	}
	doc := createHTMLContractDocumentE2E(t, f, template, cookie)
	f.doc = doc
	pages := int(doc.HtmlCurrentPageCount.Int32)
	if !doc.HtmlCurrentPageCount.Valid || pages < 2 || pages > 12 {
		t.Fatal("real approved profile must render bounded multiple pages")
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal("real source commitment missing")
	}
	rows, err := f.q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil || len(rows) != 2 || rows[0].ID == rows[1].ID {
		t.Fatal("fresh two-party UUID binding missing")
	}
	fieldByRecipient := map[uuid.UUID]uuid.UUID{}
	automaticFields, err := f.q.ListFieldsByDocument(ctx, doc.ID)
	if err != nil || htmlsource.ValidateSigningFields(doc, automaticFields, pages) != nil {
		t.Fatal("automatic intended-party fields missing")
	}
	for _, field := range automaticFields {
		fieldByRecipient[uuid.UUID(field.RecipientID.Bytes)] = field.ID
	}
	if err := htmlsource.ValidateSigningPageState(ctx, f.q, doc, pages); err != nil {
		t.Fatal("automatic page state inconsistent", err)
	}
	doc, err = f.q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal("read placed document")
	}
	review, _ := json.Marshal(map[string]string{"expected_updated_at": doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_pdf_sha256": hex.EncodeToString(doc.PdfSha256), "expected_html_source_commitment": commitment})
	if w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/html/review", string(review), cookie); w.Code != http.StatusOK {
		t.Fatalf("exact real-PDF review status=%d", w.Code)
	}
	sender := f.s.Send
	actor := sendengine.Actor{UserID: &f.user.ID, OrgID: f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	sent, err := sender.Send(ctx, actor, doc.ID)
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatal("real reviewed contract send failed")
	}
	parties := make([]signerBrowserPartyE2E, 0, 2)
	for _, link := range sent.Links {
		parsed, err := url.Parse(strings.Clone(link.URL))
		if err != nil {
			t.Fatal("decode private fixture invitation")
		}
		parties = append(parties, signerBrowserPartyE2E{Token: strings.Clone(strings.TrimPrefix(parsed.Path, "/sign/")), RecipientID: link.RecipientID, Name: strings.Clone(link.Name), Role: strings.Clone(link.Role), FieldID: fieldByRecipient[link.RecipientID]})
	}
	// Multi-party contract profiles allow signature fields only. This separate
	// legacy single-signer control proves the real autosave receipt and gate.
	sent.CloseConsumerV1()
	ownedPlainAssertDrainedV1(t, q)
	sourcePDF, err := readDocumentArtifact(ctx, f.s.Storage, doc, doc.PdfStorageKey.String, doc.PdfSha256, doc.PdfStorageVersionID)
	if err != nil {
		t.Fatal("exact real-rendered source unavailable for actual manual intake", err)
	}
	legacy, legacyParty, text, legacySignature, legacyURL := ownedRealBrowserManualAutosaveV1(t, q, sourcePDF, pages, actor)
	legacyFields, err := f.q.ListFieldsByDocument(ctx, legacy.ID)
	if err != nil {
		t.Fatal(err)
	}

	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("current built signer frontend required")
	}
	f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(root))
	f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if info, err := os.Stat(filepath.Join(root, clean)); err == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal("private task HTTPS listener unavailable")
	}
	server.Config.Handler = f.s.Routes()
	server.StartTLS()
	defer server.Close()
	if until, ok := ctx.Deadline(); !ok || time.Until(until) < 155*time.Second {
		t.Fatal("original four-minute fixture has insufficient time for its150-second browser rendezvous")
	}
	packet, _ := json.Marshal(map[string]any{"base": base.String(), "documentID": doc.ID, "pdfSHA256": hex.EncodeToString(doc.PdfSha256), "sourceCommitment": commitment, "pageCount": pages, "materializationRevision": 1, "parties": parties, "rendererVersion": strings.TrimSpace(string(version)), "rendererImageID": imageID, "fieldGeometry": ownedRealBrowserFieldGeometryV1(t, automaticFields), "legacyGeometry": ownedRealBrowserFieldGeometryV1(t, legacyFields), "legacy": map[string]any{"documentID": legacy.ID, "token": strings.TrimPrefix(legacyURL.Path, "/sign/"), "recipientID": legacyParty.ID, "name": legacyParty.Name, "pageCount": pages, "pdfSHA256": hex.EncodeToString(legacy.PdfSha256), "textFieldID": text.ID, "signatureFieldID": legacySignature.ID}})
	privateInput, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("create fresh private signer browser packet")
	}
	writeN, writeErr := privateInput.Write(packet)
	closeErr := privateInput.Close()
	if writeErr != nil || closeErr != nil || writeN != len(packet) {
		t.Fatal("write private signer browser packet")
	}
	defer os.Remove(inputPath)
	deadline := time.Now().Add(150 * time.Second)
	for {
		var body []byte
		var err error
		doneFile, openErr := os.Open(donePath)
		if openErr != nil {
			err = openErr
		} else {
			body, err = io.ReadAll(io.LimitReader(doneFile, 1025))
			closeErr := doneFile.Close()
			if err == nil {
				err = closeErr
			}
			if len(body) > 1024 {
				t.Fatal("external browser completion packet exceeds bound")
			}
		}
		if err == nil {
			var done struct {
				ExitCode int  `json:"exit_code"`
				Verified bool `json:"verified"`
			}
			if json.Unmarshal(body, &done) != nil || done.ExitCode != 0 || !done.Verified {
				t.Fatal("external signer browser rejected journey")
			}
			break
		}
		if !os.IsNotExist(err) || ctx.Err() != nil || time.Now().After(deadline) {
			t.Fatal("external signer browser acceptance timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}
	current, err := f.q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || current.Status != "completed" || !current.FinalPdfKey.Valid || !current.FinalPdfVersionID.Valid || !current.AuditCertKey.Valid || !current.AuditCertVersionID.Valid || !bytes.Equal(current.HtmlSourceJson, doc.HtmlSourceJson) || !bytes.Equal(current.PdfSha256, doc.PdfSha256) {
		t.Fatal("both-party browser completion lost exact source or final evidence")
	}
	rows, err = f.q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		t.Fatal("read completed parties")
	}
	fields, err := f.q.ListFieldsByDocument(ctx, doc.ID)
	if err != nil {
		t.Fatal("read completed placements")
	}
	signatures, err := f.q.ListSignaturesByDocument(ctx, doc.ID)
	if err != nil || len(signatures) != 2 {
		t.Fatal("both exact signatures missing")
	}
	if err := pdflayout.ValidateSignatureRows(current, rows, fields, signatures, pages); err != nil {
		t.Fatal("completed intended-party field binding invalid")
	}
	for _, signature := range signatures {
		if signature.FieldID != fieldByRecipient[signature.RecipientID] {
			t.Fatal("completed signature changed its own automatic field")
		}
		if _, err := f.s.Storage.GetVerifiedVersion(ctx, signature.ImageStorageKey, signature.ImageVersionID.String, signature.ImageSha256); err != nil {
			t.Fatal("signature exact evidence version invalid")
		}
	}
	var persisted string
	var filled bool
	if err := f.pool.QueryRow(ctx, `SELECT value,completed_at IS NOT NULL FROM document_fields WHERE id=$1 AND document_id=$2`, text.ID, legacy.ID).Scan(&persisted, &filled); err != nil || persisted != "Agreed browser reference ÅÄÖ" || !filled {
		t.Fatal("browser autosave not durably confirmed")
	}
	if err := os.MkdirAll(artifacts, 0700); err != nil {
		t.Fatal("create private PDF QA artifacts")
	}
	var intake struct {
		SchemaVersion int               `json:"schema_version"`
		Items         []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(current.MetadataRedactionReport, &intake); err != nil || intake.SchemaVersion != 2 || len(intake.Items) != 1 {
		t.Fatal("completed source lost its measured intake report")
	}
	measured, err := sanitize.DecodePDFReport(intake.Items[0])
	if err != nil || measured.PDF.OutputSHA256 != hex.EncodeToString(current.PdfSha256) || measured.PDF.PagesAfter != pages {
		t.Fatal("completed intake proof differs from exact reviewed source")
	}
	artifactHashes, artifactPins := ownedRealBrowserArtifactsV1(t, q, current, "profile", artifacts, pages)
	legacyCurrent, err := f.q.GetDocument(ctx, generated.GetDocumentParams{ID: legacy.ID, OrgID: f.org})
	if err != nil || legacyCurrent.Status != "completed" || legacyCurrent.SourceKind != "pdf" || legacyCurrent.PdfStorageKey != legacy.PdfStorageKey || legacyCurrent.PdfStorageVersionID != legacy.PdfStorageVersionID || !bytes.Equal(legacyCurrent.PdfSha256, legacy.PdfSha256) {
		t.Fatal("actual manual browser completion changed source or did not complete", err)
	}
	legacyRows, err := f.q.ListRecipientsByDocument(ctx, legacy.ID)
	if err != nil || len(legacyRows) != 1 {
		t.Fatal(err)
	}
	legacySignatures, err := f.q.ListSignaturesByDocument(ctx, legacy.ID)
	if err != nil || len(legacySignatures) != 1 || pdflayout.ValidateSignatureRows(legacyCurrent, legacyRows, legacyFields, legacySignatures, pages) != nil {
		t.Fatal("actual manual autosave signature binding differs", err)
	}
	legacyHashes, legacyPins := ownedRealBrowserArtifactsV1(t, q, legacyCurrent, "autosave", artifacts, pages)
	for name, hash := range legacyHashes {
		artifactHashes[name] = hash
	}
	artifactPins = append(artifactPins, legacyPins...)
	chainRows, err := f.q.ListChainedEventsPageForOrg(ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 1000})
	if err != nil || len(chainRows) == 0 || len(chainRows) >= 1000 {
		t.Fatal("complete synthetic audit chain unavailable", err)
	}
	chain := audit.NewChainVerifier()
	chain.VerifyPage(chainRows)
	if result := chain.Result(); !result.OK || !result.Complete {
		t.Fatal("actual completed organization chain invalid")
	}
	ownedPlainAssertDrainedV1(t, q)
	_, signingArtifact, err := htmlsource.SigningPage(current)
	if err != nil || signingArtifact == nil {
		t.Fatal("completed signing artifact missing", err)
	}
	safeParties := make([]map[string]any, 0, len(rows))
	for _, party := range rows {
		safeParties = append(safeParties, map[string]any{"id": party.ID, "role": party.Role, "name": party.Name})
	}
	receipt, marshalErr := json.MarshalIndent(map[string]any{"result": "pass", "scope": "Actual native WorkRuntime/concrete Client/Go HTTPS/PostgreSQL/source worker/real Chromium and built browser HTML plus public-intake manual PDF signing. Four exact terminal artifacts verified per document. Participants/S3-retention/key/outbox are synthetic; root must separately bind actual renderer image/source. No SMTP/provider/production/legal/capacity acceptance.", "document_id": doc.ID, "source_commitment": commitment, "pdf_sha256": hex.EncodeToString(doc.PdfSha256), "page_count": pages, "signature_count": len(signatures), "intended_parties": safeParties, "autosave_confirmed": true, "manual_signature_fields": false, "automatic_branded_page_support": true, "signing_artifact": signingArtifact, "renderer_version": strings.TrimSpace(string(version)), "renderer_image_id_supplied_by_root": imageID, "artifact_sha256": artifactHashes, "exact_artifact_pins": artifactPins, "public_key": f.s.Sign.Signer.PublicKeyBase64(), "field_geometry": ownedRealBrowserFieldGeometryV1(t, fields), "manual_field_geometry": ownedRealBrowserFieldGeometryV1(t, legacyFields), "manual_document_id": legacy.ID, "manual_expected_value": "Agreed browser reference ÅÄÖ", "four_terminal_artifacts_per_document": true, "sanitization_report": current.MetadataRedactionReport}, "", "  ")
	if marshalErr != nil {
		t.Fatal("encode safe backend receipt")
	}
	if err := os.WriteFile(filepath.Join(artifacts, "backend-receipt.json"), append(receipt, '\n'), 0600); err != nil {
		t.Fatal("write safe signer browser backend receipt")
	}
	t.Log("current-native actual renderer/browser approved HTML plus public-intake manual autosave and exact four terminal artifacts accepted locally; synthetic storage/retention/actors/key/outbox; independent visual QA and outer image/process receipt still required")
}

// This independent test oracle binds a syntactically valid signed head to the
// actual complete organization chain. Other document events may legitimately
// interleave between the captured head and this document's terminal event.
func ownedRealBrowserClaimsMatchChainV1(doc *generated.Document, terminal *generated.Event, preFinal []*generated.Event, claims evidenceverify.CertificateCommitments, chainRows []*generated.Event) error {
	if doc == nil || terminal == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || len(chainRows) == 0 || len(chainRows) >= 1000 || len(preFinal) == 0 {
		return errors.New("real browser oracle: complete nonempty organization/root evidence required")
	}
	nameSHA := sha256.Sum256([]byte(doc.Name))
	if claims.DocumentID != doc.ID.String() || claims.OrgID != doc.OrgID.String() || claims.DocumentNameSHA256 != hex.EncodeToString(nameSHA[:]) || claims.PreFinalChainScope != "organization" || claims.DocumentEventsScope != "ceremony-root" {
		return errors.New("real browser oracle: signed identity/name/scope mismatch")
	}
	chain := audit.NewChainVerifier()
	chain.VerifyPage(chainRows)
	if result := chain.Result(); !result.OK || !result.Complete {
		return errors.New("real browser oracle: complete actual organization chain invalid")
	}
	positions := make(map[uuid.UUID]int, len(chainRows))
	headIndex, terminalIndex := -1, -1
	for index, row := range chainRows {
		if row == nil || row.ID == uuid.Nil || row.OrgID != doc.OrgID || !row.CreatedAt.Valid {
			return errors.New("real browser oracle: organization event identity missing")
		}
		if _, exists := positions[row.ID]; exists {
			return errors.New("real browser oracle: duplicate organization event")
		}
		positions[row.ID] = index
		if index > 0 {
			previous := chainRows[index-1]
			if row.CreatedAt.Time.Before(previous.CreatedAt.Time) || (row.CreatedAt.Time.Equal(previous.CreatedAt.Time) && bytes.Compare(row.ID[:], previous.ID[:]) <= 0) {
				return errors.New("real browser oracle: organization event order changed")
			}
		}
		if hex.EncodeToString(row.RowHash) == claims.PreFinalChainHeadSHA256 && row.CreatedAt.Time.UTC().Format(time.RFC3339Nano) == claims.PreFinalChainHeadCreatedAt {
			if headIndex >= 0 {
				return errors.New("real browser oracle: repeated captured head")
			}
			headIndex = index
		}
		if row.ID == terminal.ID {
			if row.Kind != audit.KindDocumentCompleted || !row.DocumentID.Valid || uuid.UUID(row.DocumentID.Bytes) != doc.ID || !bytes.Equal(row.RowHash, terminal.RowHash) || !row.CreatedAt.Time.Equal(terminal.CreatedAt.Time) {
				return errors.New("real browser oracle: terminal identity changed")
			}
			terminalIndex = index
		}
	}
	// New current-native fixtures always have creation/sign events. An absent or
	// genesis head cannot satisfy this actual nonempty ceremony's signed claim.
	if headIndex < 0 || terminalIndex < 0 || headIndex >= terminalIndex {
		return errors.New("real browser oracle: captured head is absent or not before terminal")
	}
	for _, event := range preFinal {
		if event == nil || event.OrgID != doc.OrgID || !event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != doc.ID || event.Kind == audit.KindDocumentCompleted {
			return errors.New("real browser oracle: root event identity changed")
		}
		index, exists := positions[event.ID]
		if !exists || index > headIndex || !bytes.Equal(chainRows[index].RowHash, event.RowHash) || !chainRows[index].CreatedAt.Time.Equal(event.CreatedAt.Time) {
			return errors.New("real browser oracle: signed root event is outside captured organization prefix")
		}
	}
	return nil
}

func TestOwnedRealBrowserClaimOracleRejectsWellFormedWrongBindingsV1(t *testing.T) {
	org, document, otherDocument := uuid.New(), uuid.New(), uuid.New()
	doc := &generated.Document{ID: document, OrgID: org, Name: "Synthetic exact oracle document"}
	at := time.Date(2026, time.October, 16, 12, 0, 0, 0, time.UTC)
	rows := make([]*generated.Event, 0, 4)
	for index, spec := range []struct {
		document uuid.UUID
		kind     string
	}{{document, "document.created"}, {document, "recipient.signed"}, {otherDocument, "document.created"}, {document, audit.KindDocumentCompleted}} {
		row := &generated.Event{ID: uuid.New(), OrgID: org, DocumentID: pgtype.UUID{Bytes: spec.document, Valid: true}, Kind: spec.kind, CreatedAt: pgtype.Timestamptz{Time: at.Add(time.Duration(index) * time.Microsecond), Valid: true}, PayloadJson: []byte("{}"), PayloadHashed: []byte("{}")}
		if index > 0 {
			row.PrevHash = bytes.Clone(rows[index-1].RowHash)
		}
		var err error
		row.RowHash, err = audit.RecomputeEventRowHash(row)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	nameSHA := sha256.Sum256([]byte(doc.Name))
	claims := evidenceverify.CertificateCommitments{DocumentID: document.String(), OrgID: org.String(), DocumentNameSHA256: hex.EncodeToString(nameSHA[:]), PreFinalChainScope: "organization", DocumentEventsScope: "ceremony-root", PreFinalChainHeadSHA256: hex.EncodeToString(rows[1].RowHash), PreFinalChainHeadCreatedAt: rows[1].CreatedAt.Time.UTC().Format(time.RFC3339Nano)}
	if bytes.Equal(rows[3].PrevHash, rows[1].RowHash) {
		t.Fatal("positive oracle fixture lost genuine interleaving")
	}
	if err := ownedRealBrowserClaimsMatchChainV1(doc, rows[3], rows[:2], claims, rows); err != nil {
		t.Fatal("valid complete chain with interleaving refused", err)
	}
	wrongSHA := sha256.Sum256([]byte("different well formed signed binding"))
	for _, test := range []struct {
		name string
		edit func(*evidenceverify.CertificateCommitments)
	}{
		{"name", func(c *evidenceverify.CertificateCommitments) { c.DocumentNameSHA256 = hex.EncodeToString(wrongSHA[:]) }},
		{"unknown head", func(c *evidenceverify.CertificateCommitments) {
			c.PreFinalChainHeadSHA256 = hex.EncodeToString(wrongSHA[:])
		}},
		{"head time", func(c *evidenceverify.CertificateCommitments) {
			c.PreFinalChainHeadCreatedAt = at.Add(time.Hour).Format(time.RFC3339Nano)
		}},
		{"old genuine head", func(c *evidenceverify.CertificateCommitments) {
			c.PreFinalChainHeadSHA256 = hex.EncodeToString(rows[0].RowHash)
			c.PreFinalChainHeadCreatedAt = rows[0].CreatedAt.Time.UTC().Format(time.RFC3339Nano)
		}},
		{"terminal head", func(c *evidenceverify.CertificateCommitments) {
			c.PreFinalChainHeadSHA256 = hex.EncodeToString(rows[3].RowHash)
			c.PreFinalChainHeadCreatedAt = rows[3].CreatedAt.Time.UTC().Format(time.RFC3339Nano)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := claims
			test.edit(&changed)
			if err := ownedRealBrowserClaimsMatchChainV1(doc, rows[3], rows[:2], changed, rows); err == nil {
				t.Fatal("well-formed wrong signed binding accepted")
			}
		})
	}
	missing := *rows[1]
	missing.ID = uuid.New()
	if err := ownedRealBrowserClaimsMatchChainV1(doc, rows[3], []*generated.Event{rows[0], &missing}, claims, rows); err == nil {
		t.Fatal("signed root event absent from genuine prefix accepted")
	}
}
