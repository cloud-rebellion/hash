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
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sanitize"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This is a real PG/application journey with synthetic bounded renderer/S3
// peers and synthetic retention. It proves exact lifecycle/ownership bindings,
// not Chromium layout, provider Object Lock, production capacity or READY.
// Target native authoring/public-read work shares ONE actual WorkRuntime from
// before target template/document birth. Auxiliary draft setup and legacy
// mutation/PDF/provider work have separate explicit admission boundaries.
// There is no borrowed native tx or fabricated cache row.
// This peer retains the existing bounded multipart/HTML protocol checks but
// emits a genuine fixed-content PDF at the actual protocol paper dimensions,
// preserving original exact-A4 defaults, never a claimed render of the HTML.
// The worker still parses both inputs, enforces the canonical suffix geometry,
// scans/cleans/merges them and issues the actual composition/report proof.
// No manifest, page count, report or storage digest is synthesized here.
type ownedA4ProtocolRendererV1 struct {
	protocol htmlCreationRendererE2E
	gate     *ownedRendererGate165V1
}

func (p *ownedA4ProtocolRendererV1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claimed, finish := p.gate.claimV1()
	defer finish()
	protocol := httptest.NewRecorder()
	var paper [2]string
	p.protocol.servePaperProtocolV1(protocol, r, &paper)
	if claimed && !p.gate.waitV1() {
		return
	}
	for key, values := range protocol.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	if protocol.Code != http.StatusOK {
		w.WriteHeader(protocol.Code)
		_, _ = w.Write(protocol.Body.Bytes())
		return
	}
	if protocol.Header().Get("Content-Type") != "application/pdf" {
		http.Error(w, "unexpected synthetic renderer protocol response", http.StatusInternalServerError)
		return
	}
	var output []byte
	if paper == [2]string{"8.27", "11.69"} {
		output = ownedA4ProtocolPDFV1()
	} else {
		width, werr := strconv.ParseFloat(paper[0], 64)
		height, herr := strconv.ParseFloat(paper[1], 64)
		if werr != nil || herr != nil || math.IsNaN(width) || math.IsNaN(height) || math.IsInf(width, 0) || math.IsInf(height, 0) || width <= 0 || height <= 0 {
			http.Error(w, "invalid synthetic paper geometry", http.StatusBadRequest)
			return
		}
		output = ownedPaperProtocolPDFV1(width*72, height*72)
	}
	w.Header().Del("Content-Length")
	w.Header().Del("ETag")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output)
}
func ownedA4ProtocolPDFV1() []byte { return ownedPaperProtocolPDFV1(594.959960, 841.919980) }
func ownedPaperProtocolPDFV1(width, height float64) []byte {
	const stream = "BT /F1 12 Tf 30 40 Td (SYNTHETIC_EXACT_A4_PROTOCOL_FIXTURE) Tj ET\n"
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.6f %.6f] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>", width, height),
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
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

type ownedFrozenReadSourceV1 struct{ fetches *atomic.Int64 }

func (ownedFrozenReadSourceV1) Kind() resolver.SourceKind { return resolver.SourceAgentComputed }
func (s ownedFrozenReadSourceV1) Fetch(context.Context, resolver.Ref) (string, error) {
	s.fetches.Add(1)
	return "unexpected source fetch", errors.New("literal owned fixture has no binding to fetch")
}

type ownedPublicReadFixtureV1 struct {
	f              lifecycleAuthorizationFixture
	runtime        *pdfadmission.WorkRuntimeV1
	template       *generated.Template
	evidence       *signerBrowserEvidenceE2E
	cookie         string
	fetches        atomic.Int64
	renderer       *ownedA4ProtocolRendererV1
	rendererServer *httptest.Server
	storagePeer    *htmlCreationStorageE2E
}

func newOwnedPublicReadFixtureV1(t *testing.T) *ownedPublicReadFixtureV1 {
	t.Helper()
	return newOwnedPublicReadFixtureBaseV1(t, true)
}

// Authorization starts with the same genuine runtime/provider/template setup
// and no unrelated legacy lifecycle document, preserving its original exact
// one-document replay oracle without deleting any source or history.
func newOwnedAutomationAuthorizationFixtureV1(t *testing.T) *ownedPublicReadFixtureV1 {
	t.Helper()
	return newOwnedPublicReadFixtureBaseV1(t, false)
}
func newOwnedPublicReadFixtureBaseV1(t *testing.T, withLifecycleDocument bool) *ownedPublicReadFixtureV1 {
	t.Helper()
	return newOwnedPublicReadFixtureProfileV1(t, withLifecycleDocument, false)
}

// Only package measurement explicitly enables one isolated parser admission.
// Existing fixture limits and the physical PG/process caps remain unchanged.
func newOwnedDocumentPackageMeasurementFixtureV1(t *testing.T) *ownedPublicReadFixtureV1 {
	t.Helper()
	return newOwnedPublicReadFixtureProfileV1(t, false, true)
}
func newOwnedPublicReadFixtureProfileV1(t *testing.T, withLifecycleDocument, withPackageMeasurement bool, queryTracers ...pgx.QueryTracer) *ownedPublicReadFixtureV1 {
	t.Helper()
	// Controlled logical-work integration profile, matching the existing
	// authoring fixture. Retained stored-template compilations alone raise the
	// two-reader Parent overlap floor above448MiB. The original conservative
	// fixture body oracle remains below; it does not measure a complete peak.
	// This is not a production default or physical capacity claim.
	// One actual shared SDK stream is enabled for the new concrete Send Client.
	// Byte/DB/grant caps are unchanged; this synthetic protocol slot proves no
	// live provider Object Lock or physical process/provider capacity.
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1}, MaxGrants: 128, MaxOrganisationGrants: 64}
	if withPackageMeasurement {
		limits.Global.ChildAddressBytes = 2 << 30
		limits.Global.PDFWorkers = 1
		limits.Organisation.ChildAddressBytes = 2 << 30
		limits.Organisation.PDFWorkers = 1
	}
	return newOwnedPublicReadFixtureAllocated257dV1(t, withLifecycleDocument, limits, queryTracers...)
}

// The complete test allocation is chosen before any fixture pool, physical
// session factory, runtime, document or retained consumer is constructed.
// Existing callers keep their original global128/org64 profile above.
func newOwnedPublicReadFixtureAllocated257dV1(t *testing.T, withLifecycleDocument bool, limits workguard.LimitsV1, queryTracers ...pgx.QueryTracer) *ownedPublicReadFixtureV1 {
	t.Helper()
	return newOwnedPublicReadFixtureAllocatedPool315V1(t, withLifecycleDocument, limits, 0, queryTracers...)
}

// Only the new named AI overlap profile requests a one-connection application
// pool at birth. Original default constructors and numeric limits stay unchanged.
func newOwnedPublicReadFixtureAllocatedPool315V1(t *testing.T, withLifecycleDocument bool, limits workguard.LimitsV1, poolMaximum int32, queryTracers ...pgx.QueryTracer) *ownedPublicReadFixtureV1 {
	t.Helper()
	if (poolMaximum != 0 && poolMaximum != 1) || (withLifecycleDocument && poolMaximum != 0) {
		t.Fatal("explicit one-pool allocation requires the native fixture without a legacy lifecycle seed")
	}
	if len(queryTracers) > 1 || (withLifecycleDocument && len(queryTracers) != 0) {
		t.Fatal("pool tracer requires the isolated original-pool fixture without a lifecycle seed")
	}
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
	database := isolateMigratedHTMLTemplateDatabaseE2E(t)
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
		ctx, pool, q, s, org, id := setupDSRPoolBirth315E2E(t, poolMaximum, queryTracers...)
		user, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: id, OrgID: org, Role: "owner"})
		if err != nil {
			t.Fatal(err)
		}
		f = lifecycleAuthorizationFixture{ctx: ctx, pool: pool, q: q, s: s, org: org, user: user}
	}
	application = f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	ctx, cancel := context.WithTimeout(f.ctx, 90*time.Second)
	t.Cleanup(cancel)
	f.ctx = ctx
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
		if withLifecycleDocument {
			if _, err := f.pool.Exec(ctx, "TRUNCATE orgs CASCADE"); err != nil {
				t.Error(err)
			} //nolint:rawsql -- all rows in this unique synthetic DB
			return // This branch still has original lifecycle cleanup using the pool.
		}
		// No legacy lifecycle DELETE cleanup was registered for this branch.
		// The mandatory isolated-DB DROP disposes its retained rows only after
		// the original pool/native retirement and independent absence witnesses.
		// Pool.Close joins client resources; the server may still be retiring
		// their backends. Join this unique fixture application with a separate
		// witness before the existing final absence assertion. Never terminate
		// a backend or treat a timeout as successful retirement.
		cfg, err := pgx.ParseConfig(isolatedDSN)
		if err != nil {
			t.Error(err)
			return
		}
		cfg.RuntimeParams["application_name"] = "hash_owned_pool_retirement_witness"
		witness, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Error("pool retirement witness", err)
			return
		}
		defer func() {
			closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := witness.Close(closeCtx); err != nil {
				t.Error("close pool retirement witness", err)
			}
		}()
		f.pool.Close()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		checks := 0
		for {
			var count int
			var remaining string
			err := witness.QueryRow(ctx, "SELECT count(*)::integer,coalesce(string_agg(pid::text || '/' || backend_start::text || '/' || state, ','),'') FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", application).Scan(&count, &remaining)
			if err != nil {
				t.Error("pool physical retirement inspection", err)
				return
			}
			if count == 0 {
				t.Logf("unique fixture pool physical retirement joined; pending observations=%d", checks)
				return
			}
			checks++
			select {
			case <-ctx.Done():
				t.Errorf("pool physical retirement unjoined: count=%d backends=%s err=%v", count, remaining, ctx.Err())
				return
			case <-ticker.C:
			}
		}

	})
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
	q.renderer = &ownedA4ProtocolRendererV1{gate: newOwnedRendererGate165V1(f.ctx)}
	renderer := httptest.NewServer(q.renderer)
	q.rendererServer = renderer
	t.Cleanup(renderer.Close)
	peer := &htmlCreationStorageE2E{importStoragePeer: &importStoragePeer{objects: make(map[string][]byte)}}
	q.storagePeer = peer
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	f.s.Storage, err = storage.New(ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-owned-read", SecretKey: "synthetic-owned-read-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	q.evidence = &signerBrowserEvidenceE2E{client: f.s.Storage, retained: make(map[string]time.Time)}
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
	f.s.Sign = &sign.Engine{Pool: f.pool, Queries: f.q, WorkRuntime: runtime, Storage: f.s.Storage, PDF: render.NewGotenberg(renderer.URL), Audit: f.s.Audit, Mailer: dispatch.QueueingMailer{Q: f.q}, Signer: signer, BaseURL: f.s.PublicURL, OrgName: f.s.OperatorName, BrandingCSS: func(ctx context.Context, doc *generated.Document) (string, error) {
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
		err := runtime.CloseV1(cleanup)
		pending := runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.SignerScopes != 0 || pending.SignerReaders != 0 || pending.DocumentPackageOperations != 0 || pending.ObserverSessions != observers {
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
	q.template = createBrandedDesignE2E(t, f, q.cookie)
	q.requireLiteralFixtureProfileV1(t, limits)
	// The generic approval helper swaps in a Letter-size renderer. This
	// schema3 profile must preview the same exact-A4 synthetic peer as create.
	approveBrandedDesignE2E(t, f, q.template, peer, q.cookie)
	return q
}

// This synthetic fixture oracle retains a conservative legacy native-loan
// upper bound from fixed scalar headers and actual creator bytes. Its repeated
// reader classes exceed the current per-body typed costs; it excludes canonical
// CPU/output reservations and is not a complete resource peak or capacity proof.
// It supplies no application grant, body authority or backend retirement proof.
func (q *ownedPublicReadFixtureV1) requireLiteralFixtureProfileV1(t *testing.T, limits workguard.LimitsV1) {
	t.Helper()
	f := q.f
	h, err := f.q.GetHTMLAuthoringTemplateHeaderV1(f.ctx, generated.GetHTMLAuthoringTemplateHeaderV1Params{TemplateID: q.template.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.q.GetHTMLAuthoringRevisionHeaderV1(f.ctx, generated.GetHTMLAuthoringRevisionHeaderV1Params{TemplateID: q.template.ID, OrgID: f.org, Version: q.template.Version})
	if err != nil {
		t.Fatal(err)
	}
	a, err := f.q.GetHTMLAuthoringActorHeaderV1(f.ctx, generated.GetHTMLAuthoringActorHeaderV1Params{UserID: f.user.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if h.MeasurementServerVersionNum <= 0 || h.MeasurementServerVersionNum != h.ServerVersionNum || r.MeasurementServerVersionNum != r.ServerVersionNum || h.ServerVersionNum != r.ServerVersionNum {
		t.Fatal("fresh literal profile measurement version unavailable")
	}
	// Keep this oracle and its arithmetic a finite small-fixture operation.
	for _, n := range []int64{h.RawTextBytes, h.MasterWireBytes, h.VariablesWireBytes, h.BlocksWireBytes, h.FieldsWireBytes, h.SanitizationWireBytes, r.MasterWireBytes, r.VariablesWireBytes, a.RawTextBytes} {
		if n < 0 || n > 1<<20 {
			t.Fatal("literal profile scalar exceeds explicit1MiB oracle input bound")
		}
	}
	if int64(len(q.template.HtmlMasterJson)) != h.MasterWireBytes || int64(len(q.template.VariablesJson)) != h.VariablesWireBytes || int64(len(q.template.BlocksJson)) != h.BlocksWireBytes || int64(len(q.template.FieldsJson)) != h.FieldsWireBytes || int64(len(q.template.PdfSanitizationReport)) != h.SanitizationWireBytes || r.MasterWireBytes != h.MasterWireBytes || r.VariablesWireBytes != h.VariablesWireBytes {
		t.Fatal("fresh template/revision concrete inputs differ from exact scalar profile")
	}
	canonical, err := htmlmaster.CanonicalTemplate(q.template.HtmlMasterJson, q.template.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	if err := json.Unmarshal(canonical.DefaultsJSON, &values); err != nil {
		t.Fatal(err)
	}
	variables, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := pdfadmission.HTMLCreationResourcesForV1(f.ctx, pdfadmission.HTMLCreationInputsV1{StoredMaster: q.template.HtmlMasterJson, StoredDefaults: q.template.VariablesJson, CanonicalMaster: canonical.MasterJSON, CanonicalDefaults: canonical.DefaultsJSON, Variables: variables, Sections: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	const base int64 = 32 << 20
	templateWire := h.MasterWireBytes + h.VariablesWireBytes + h.BlocksWireBytes + h.FieldsWireBytes + h.SanitizationWireBytes
	revisionWire := r.MasterWireBytes + r.VariablesWireBytes
	// Each preview load retains header/maps/template/revision/actor; nil maps
	// have actual wire4. The final load overlaps the original retained consumer.
	loadDB := 5*base + 16*(4+templateWire+revisionWire)
	loadParent := loadDB + 8*(h.RawTextBytes+32+a.RawTextBytes)
	previewDB, previewParent := 2*loadDB, 2*loadParent
	// The literal creator has nil CRMPopulation. Its prepared five loans remain
	// while final reader(header/template/revision/actor) and the actual priced
	// writer overlap. No CRM/source/provider work is silently admitted here.
	creationDB := loadDB + 4*base + 16*(templateWire+revisionWire) + writer.DBStagingBytes
	creationParent := loadParent + 4*base + 16*(templateWire+revisionWire) + 8*(h.RawTextBytes+32+a.RawTextBytes) + writer.WorkingBytes
	for _, peak := range []struct {
		name       string
		parent, db int64
	}{{"preview", previewParent, previewDB}, {"literal creation", creationParent, creationDB}} {
		t.Logf("conservative legacy native-loan upper bound %s ParentBytes=%d DBStagingBytes=%d", peak.name, peak.parent, peak.db)
		if peak.parent > limits.Global.ParentBytes || peak.parent > limits.Organisation.ParentBytes || peak.db > limits.Global.DBStagingBytes || peak.db > limits.Organisation.DBStagingBytes {
			t.Fatalf("explicit literal fixture profile cannot admit genuine retained %s peak", peak.name)
		}
	}
}
func (q *ownedPublicReadFixtureV1) createSentV1(t *testing.T) (*generated.Document, []signerBrowserPartyE2E) {
	t.Helper()
	f := q.f
	doc := createHTMLContractDocumentE2E(t, f, q.template, q.cookie)
	if len(doc.MetadataRedactionReport) == 0 {
		t.Fatal("fresh real worker report absent")
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	review, err := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
	if err != nil {
		t.Fatal(err)
	}
	if w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/html/review", string(review), q.cookie); w.Code != http.StatusOK {
		t.Fatalf("genuine exact review=%d %s", w.Code, w.Body.String())
	}
	doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	original := doc
	var before string
	if err := f.pool.QueryRow(f.ctx, "SELECT to_jsonb(s)::text FROM document_signing_policy_sizes_v1 s WHERE document_id=$1 AND org_id=$2", doc.ID, f.org).Scan(&before); err != nil || before == "" {
		t.Fatal("fresh creator did not derive actual policy cache", err)
	} //nolint:rawsql -- genuine fresh cache witness, never insertion/repair
	actor := sendengine.Actor{UserID: &f.user.ID, OrgID: f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	sent, err := f.s.Send.Send(f.ctx, actor, doc.ID)
	defer sent.CloseConsumerV1() // After actual final link/error use below.
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatalf("genuine configured-Resolver send=%+v err=%v", sent, err)
	}
	var after string
	if err := f.pool.QueryRow(f.ctx, "SELECT to_jsonb(s)::text FROM document_signing_policy_sizes_v1 s WHERE document_id=$1 AND org_id=$2", doc.ID, f.org).Scan(&after); err != nil || after != before {
		t.Fatal("configured Send rewrote/lost fresh immutable HTML policy cache; no repair or remeasurement allowed", err)
	} //nolint:rawsql -- desired production integration regression
	if q.fetches.Load() != 0 {
		t.Fatal("literal no-binding fixture fetched an undeclared source")
	}
	parties := make([]signerBrowserPartyE2E, 0, 2)
	for _, link := range sent.Links {
		u, err := url.Parse(link.URL)
		if err != nil {
			t.Fatal(err)
		}
		parties = append(parties, signerBrowserPartyE2E{Token: strings.TrimPrefix(u.Path, "/sign/"), RecipientID: link.RecipientID, Name: link.Name, Role: link.Role})
	}
	doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if !sameSignerDocumentSource(original, doc) || original.HtmlReviewedBy != doc.HtmlReviewedBy || original.HtmlReviewedAt != doc.HtmlReviewedAt || !bytes.Equal(original.HtmlReviewedPdfSha256, doc.HtmlReviewedPdfSha256) {
		t.Fatal("configured Send changed exact reviewed source/variables/PDF pins")
	}
	if doc.Status != "sent" || doc.SigningAdmissionPolicy != "historical" {
		t.Fatal("fixture did not retain genuine actual existing lifecycle policy")
	}
	return doc, parties
}
func (q *ownedPublicReadFixtureV1) snapshotV1(t *testing.T) workguard.SnapshotV1 {
	t.Helper()
	s, err := q.runtime.SnapshotV1(q.f.org)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func (q *ownedPublicReadFixtureV1) reconcileV1(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := q.runtime.ReconcileCleanupV1(ctx)
		if err == nil {
			return
		}
		if !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Fatal(err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("actual original cleanup remained unknown", err)
		}
	}
}
func (q *ownedPublicReadFixtureV1) assertObserversOnlyV1(t *testing.T) {
	t.Helper()
	q.reconcileV1(t)
	p := q.runtime.SessionsV1().PendingV1()
	s := q.snapshotV1(t)
	if p.WorkSessions != 0 || p.UnknownStarts != 0 || p.HTMLAdmissions != 0 || p.SignerScopes != 0 || p.SignerReaders != 0 || p.ObserverSessions != 2 {
		t.Fatalf("actual consumed work remains or exact process+tenant observers missing: %+v", p)
	}
	global, err := q.runtime.SnapshotV1(uuid.Nil)
	if err != nil || global.Global != s.Global || global.GlobalGrants != s.GlobalGrants || global.Organisation != (workguard.VectorV1{}) || global.OrganisationGrants != 0 || global.ActiveOrganisations != s.ActiveOrganisations {
		t.Fatal("global numeric observation invented an organization or a separate coordinator", global, err)
	}
	if s.Global != (workguard.VectorV1{SQLSessions: 2}) || s.GlobalGrants != 2 || s.Organisation != (workguard.VectorV1{SQLSessions: 1}) || s.OrganisationGrants != 1 {
		t.Fatalf("actual observer-only numeric debt wrong: %+v", s)
	}
}
func (q *ownedPublicReadFixtureV1) lookupV1(t *testing.T, token string) *sign.RecipientContext {
	t.Helper()
	rc, err := q.f.s.Sign.LookupByToken(q.f.ctx, auth.HashMagicToken(token))
	if err != nil {
		t.Fatal("owned public active lookup", err)
	}
	t.Cleanup(func() {
		if err := rc.CloseReadV1(); err != nil {
			t.Error(err)
		}
	})
	return rc
}
func (q *ownedPublicReadFixtureV1) requestV1(token, endpoint string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+"/sign/"+token+endpoint, nil).WithContext(q.f.ctx)
	q.f.s.Routes().ServeHTTP(w, r)
	return w
}

func TestOwnedPublicSignerConfiguredResolverAndCompletedLifecycleE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	rc := q.lookupV1(t, parties[0].Token)
	if err := rc.ValidateReadMaterializationV1(); err != nil {
		t.Fatal(err)
	}
	p := q.runtime.SessionsV1().PendingV1()
	s := q.snapshotV1(t)
	if p.WorkSessions != 0 || p.SignerReaders != 1 || p.SignerScopes != 1 || s.Global.ParentBytes <= 0 || s.Global.DBStagingBytes <= 0 {
		t.Fatal("physical-first successful public result did not retain actual full body debt")
	}
	if err := q.f.s.Sign.RecheckRecipientReadV1(q.f.ctx, rc, func(fresh *sign.RecipientContext) error {
		if !sameSignerDocumentSource(doc, fresh.Document) {
			return errSignerReadChanged
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	for _, endpoint := range []string{"", "/pdf", "/fields"} {
		w := q.requestV1(parties[0].Token, endpoint)
		if w.Code != http.StatusOK {
			t.Fatalf("genuine public read %s=%d %s", endpoint, w.Code, w.Body.String())
		}
		q.assertObserversOnlyV1(t)
	}
	var finalToken string
	for i, party := range parties {
		rc := q.lookupV1(t, party.Token)
		notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := signerArticle13NoticeEvidence(rc, notice)
		if err != nil {
			t.Fatal(err)
		}
		result, err := q.f.s.Sign.Sign(q.f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic owned public read qualifier"})
		if err != nil {
			t.Fatal("genuine sequential sign", err)
		}
		if i == 0 && result.Completed {
			t.Fatal("first party completed two-party contract")
		}
		if i == len(parties)-1 {
			if !result.Completed || result.FinalPDFURL == "" {
				t.Fatal("genuine final sign did not complete/rotate artifact capability")
			}
			u, err := url.Parse(result.FinalPDFURL)
			if err != nil {
				t.Fatal(err)
			}
			segments := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(segments) != 3 || segments[0] != "sign" || segments[2] != "final-pdf" {
				t.Fatal("unexpected actual final artifact route")
			}
			finalToken = segments[1]
		}
		if err := rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		q.assertObserversOnlyV1(t)
	}
	completed, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
	if err != nil || completed.Status != "completed" {
		t.Fatal("actual Sign did not commit completed document", err)
	}
	if !sameSignerDocumentSource(doc, completed) {
		t.Fatal("genuine completion changed original HTML/current/variables/source PDF tuple")
	}
	type artifact struct {
		key, version pgtype.Text
		digest       []byte
	}
	artifacts := []artifact{{completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha}, {completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256}, {completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256}, {completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256}}
	verified := make([][]byte, 0, len(artifacts))
	for _, a := range artifacts {
		if !a.key.Valid || strings.TrimSpace(a.key.String) == "" || !a.version.Valid || a.version.String == "" || len(a.digest) != sha256.Size {
			t.Fatal("actual completion omitted final/cert/payload/signature exact pins")
		}
		body, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, a.key.String, a.digest, a.version)
		if err != nil {
			t.Fatal("actual completed artifact exact-version read", err)
		}
		verified = append(verified, body)
	}
	if !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(verified[2]), string(verified[3])) {
		t.Fatal("actual completed detached certificate signature failed")
	}
	final, err := q.f.s.Sign.LookupCompletedArtifactByToken(q.f.ctx, auth.HashMagicToken(finalToken))
	if err != nil {
		t.Fatal("healthy completed public lookup", err)
	}
	defer final.CloseReadV1()
	body, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, final.Document, final.Document.FinalPdfKey.String, final.Document.FinalPdfSha, final.Document.FinalPdfVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(body); !bytes.Equal(digest[:], completed.FinalPdfSha) {
		t.Fatal("completed exact storage binding changed")
	}
	if err := q.f.s.Sign.RecheckCompletedArtifactByToken(q.f.ctx, auth.HashMagicToken(finalToken), final); err != nil {
		t.Fatal(err)
	}
	if err := final.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	if w := q.requestV1(finalToken, "/final-pdf"); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatalf("actual completed HTTP response=%d, exact bytes=%v", w.Code, bytes.Equal(w.Body.Bytes(), body))
	}
	q.assertObserversOnlyV1(t)
	if old, err := q.f.s.Sign.LookupByToken(q.f.ctx, auth.HashMagicToken(parties[0].Token)); err == nil {
		_ = old.CloseReadV1()
		t.Fatal("old invitation remained active after genuine completion")
	}
}

func ownedReadHolderV1(t *testing.T, q *ownedPublicReadFixtureV1, doc uuid.UUID, table bool) (pgx.Tx, int32) {
	t.Helper()
	tx, err := q.f.pool.Begin(q.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if table {
		_, err = tx.Exec(q.f.ctx, "LOCK TABLE recipients IN ACCESS EXCLUSIVE MODE")
	} else {
		_, err = q.f.q.WithTx(tx).GetDocumentForUpdate(q.f.ctx, generated.GetDocumentForUpdateParams{ID: doc, OrgID: q.f.org})
	}
	if err != nil {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		_ = tx.Rollback(cleanup)
		stop()
		t.Fatal(err)
	}
	var pid int32
	if err := tx.QueryRow(q.f.ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		_ = tx.Rollback(cleanup)
		stop()
		t.Fatal(err)
	} //nolint:rawsql -- genuine scoped synthetic holder, never adopted by native reader
	return tx, pid
}
func ownedReadWaitV1(t *testing.T, q *ownedPublicReadFixtureV1, holder int32, query string) {
	t.Helper()
	application := q.f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM pg_stat_activity a WHERE a.datname=current_database() AND a.application_name=$1 AND a.state='active' AND a.wait_event_type='Lock' AND position($2 in a.query)>0 AND $3=ANY(pg_blocking_pids(a.pid))", application, query, holder).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			return
		}
		if count > 1 {
			t.Fatal("unexpected native waiters")
		}
		time.Sleep(10 * time.Millisecond)
	} //nolint:rawsql -- exact current native query and actual blocker PID
	t.Fatal("actual owned public read did not reach the held SQL boundary")
}

type ownedReadLookupResultV1 struct {
	rc  *sign.RecipientContext
	err error
}
type ownedReadLookupJobV1 struct {
	result   chan ownedReadLookupResultV1
	finished chan struct{}
	cancel   context.CancelFunc
	received *sign.RecipientContext
}

func ownedReadStartLookupV1(q *ownedPublicReadFixtureV1, hash []byte) *ownedReadLookupJobV1 {
	ctx, cancel := context.WithCancel(q.f.ctx)
	j := &ownedReadLookupJobV1{result: make(chan ownedReadLookupResultV1, 1), finished: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(j.finished)
		rc, err := q.f.s.Sign.LookupByToken(ctx, hash)
		j.result <- ownedReadLookupResultV1{rc, err}
	}()
	return j
}
func (j *ownedReadLookupJobV1) receiveV1(t *testing.T) ownedReadLookupResultV1 {
	t.Helper()
	select {
	case out := <-j.result:
		j.received = out.rc
		return out
	case <-time.After(7 * time.Second):
		t.Fatal("actual public lookup did not join")
		return ownedReadLookupResultV1{}
	}
}
func (j *ownedReadLookupJobV1) cleanupV1(t *testing.T, holder pgx.Tx) {
	t.Helper()
	j.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if holder != nil {
		_ = holder.Rollback(ctx)
	}
	select {
	case <-j.finished:
	case <-time.After(8 * time.Second):
		t.Error("actual lookup still consuming; native registry/debt retained")
		return
	}
	if j.received != nil {
		if err := j.received.CloseReadV1(); err != nil {
			t.Error(err)
		}
	} else {
		select {
		case out := <-j.result:
			if out.rc != nil {
				if err := out.rc.CloseReadV1(); err != nil {
					t.Error(err)
				}
			}
		default:
		}
	}
}
func TestOwnedPublicSignerInputSnapshotAndCancellationE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	t.Run("original_presented_bytes_before_global_wait", func(t *testing.T) {
		held, pid := ownedReadHolderV1(t, q, doc.ID, true)
		hash := auth.HashMagicToken(parties[0].Token)
		job := ownedReadStartLookupV1(q, hash)
		defer job.cleanupV1(t, held)
		ownedReadWaitV1(t, q, pid, "-- name: ProbeSignerScopeByTokenHashV1")
		// The actual shared coordinator snapshot locks after the probe grant,
		// establishing a Go happens-before edge for the initial input copy. The
		// second numeric observation orders this mutation before later body grants;
		// neither observation authorizes SQL, expiry, retirement or body release.
		if s := q.snapshotV1(t); s.Global.ParentBytes != 8<<20 {
			t.Fatal("global input wait already acquired or lost body ownership", s)
		}
		copy(hash, bytes.Repeat([]byte{0x7c}, sha256.Size))
		_ = q.snapshotV1(t)
		if err := held.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		out := job.receiveV1(t)
		if out.err != nil || out.rc == nil || out.rc.Recipient.ID != parties[0].RecipientID || out.rc.Document.ID != doc.ID {
			t.Fatal("public lookup adopted mutable caller bytes after native wait", out.err)
		}
		if err := out.rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
	})
	q.assertObserversOnlyV1(t)
	t.Run("cancel_actual_global_query_then_join", func(t *testing.T) {
		held, pid := ownedReadHolderV1(t, q, doc.ID, true)
		job := ownedReadStartLookupV1(q, auth.HashMagicToken(parties[0].Token))
		defer job.cleanupV1(t, held)
		ownedReadWaitV1(t, q, pid, "-- name: ProbeSignerScopeByTokenHashV1")
		job.cancel()
		out := job.receiveV1(t)
		if out.err == nil || out.rc != nil {
			t.Fatal("cancelled real SQL probe published successful consumer")
		}
		if err := held.Rollback(q.f.ctx); err != nil {
			t.Fatal(err)
		}
	})
	q.assertObserversOnlyV1(t)
	rc := q.lookupV1(t, parties[0].Token)
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
}

func TestOwnedPublicSignerOriginalDeadlineAndBorrowerJoinE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	for _, deadlineKind := range []string{"recipient", "document"} {
		t.Run(deadlineKind+"_extended_deadline_cannot_extend_original", func(t *testing.T) {
			deadline := time.Now().Add(1500 * time.Millisecond)
			expiryQuery := "UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1 AND document_id=$3"
			target, scope := parties[0].RecipientID, doc.ID
			if deadlineKind == "document" {
				expiryQuery = "UPDATE documents SET expires_at=$2 WHERE id=$1 AND org_id=$3"
				target, scope = doc.ID, q.f.org
			}
			if _, err := q.f.pool.Exec(q.f.ctx, expiryQuery, target, deadline, scope); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- scoped actual expiry race, no status/cache/source fabrication
			rc := q.lookupV1(t, parties[0].Token)
			held, pid := ownedReadHolderV1(t, q, doc.ID, false)
			ctx, cancel := context.WithCancel(q.f.ctx)
			result := make(chan error, 1)
			finished := make(chan struct{})
			var called atomic.Bool
			defer func() {
				cancel()
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = held.Rollback(cleanup)
				select {
				case <-finished:
				case <-time.After(8 * time.Second):
					t.Error("actual deadline recheck did not join")
				}
			}()
			go func() {
				defer close(finished)
				result <- q.f.s.Sign.RecheckRecipientReadV1(ctx, rc, func(*sign.RecipientContext) error { called.Store(true); return nil })
			}()
			ownedReadWaitV1(t, q, pid, "-- name: GetSignerDocumentReadHeaderV1")
			if _, err := held.Exec(q.f.ctx, expiryQuery, target, time.Now().Add(time.Hour), scope); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- actual same presented credential extension while original is in flight
			until := time.Now().Add(2 * time.Second)
			expired := false
			for time.Now().Before(until) {
				if err := q.f.pool.QueryRow(q.f.ctx, "SELECT clock_timestamp()>$1::timestamptz", deadline).Scan(&expired); err != nil {
					t.Fatal(err)
				}
				if expired {
					break
				}
				time.Sleep(10 * time.Millisecond)
			} //nolint:rawsql -- real database clock witness, no caller time declaration
			if !expired {
				t.Fatal("original deadline did not pass within fixed fixture bound")
			}
			if err := held.Commit(q.f.ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, sign.ErrMagicLinkExpired) || called.Load() {
					t.Fatal("fresh expiry replaced original authorization deadline", err)
				}
			case <-time.After(7 * time.Second):
				t.Fatal("original deadline recheck did not return")
			}
			if err := rc.CloseReadV1(); err != nil {
				t.Fatal(err)
			}
		})
		q.assertObserversOnlyV1(t)
	}
	t.Run("close_original_waits_for_actual_recheck_consumer", func(t *testing.T) {
		rc := q.lookupV1(t, parties[0].Token)
		entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		result := make(chan error, 1)
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		ctx, cancel := context.WithCancel(q.f.ctx)
		defer func() {
			unblock()
			cancel()
			select {
			case <-finished:
			case <-time.After(8 * time.Second):
				t.Error("actual borrowed original body still consuming")
			}
		}()
		go func() {
			defer close(finished)
			result <- q.f.s.Sign.RecheckRecipientReadV1(ctx, rc, func(fresh *sign.RecipientContext) error {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				if fresh.Document.ID != doc.ID {
					return errSignerReadChanged
				}
				return nil
			})
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("actual locked policy callback did not start")
		}
		before := q.snapshotV1(t)
		if err := rc.CloseReadV1(); !errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) {
			t.Fatal("live original recheck borrower reported cleanup complete", err)
		}
		if after := q.snapshotV1(t); after.Global != before.Global || after.GlobalGrants != before.GlobalGrants {
			t.Fatal("closing original refunded while actual recheck still consumed its frozen body")
		}
		unblock()
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(7 * time.Second):
			t.Fatal("joined actual borrower did not finish")
		}
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("result preceded unjoined recheck goroutine")
		}
		if err := rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
	})
	q.assertObserversOnlyV1(t)
}

func TestOwnedPublicSignerActualConsumerOrdersAndResponseUseE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	t.Run("consumer_first_still_waits_for_actual_SQL_retirement", func(t *testing.T) {
		scope, err := q.runtime.SessionsV1().ProbeSignerScopeV1(q.f.ctx, auth.HashMagicToken(parties[0].Token))
		if err != nil {
			t.Fatal(err)
		}
		defer scope.CloseConsumerV1()
		reader, err := q.runtime.SessionsV1().NewSignerReaderV1(q.f.ctx, scope, pdfadmission.SignerReadActiveV1)
		if reader != nil {
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := reader.CloseV1(ctx); err != nil {
					t.Error(err)
				}
			}()
		}
		if err != nil {
			t.Fatal(err)
		}
		err = reader.WithModelsV1(q.f.ctx, func(a pdfadmission.ApplicationSignerReadAccessV1) error {
			if !a.ActiveCeremony || a.CompletedCeremony {
				return errSignerReadChanged
			}
			return nil
		}, func(_ context.Context, m *pdfadmission.ApplicationSignerReadModelsV1) error {
			if m == nil || m.Document == nil || m.Document.ID != doc.ID || m.Recipient == nil || m.Recipient.ID != parties[0].RecipientID || m.ControllerOrg == nil || m.ControllerOrg.ID != q.f.org || m.LawfulBasisConfirmation == nil || m.Current == nil {
				return errSignerReadChanged
			}
			// Actual complete model/cache projection, not a public auth acceptance
			// shortcut: healthy Engine and HTTP acceptance is qualified separately.
			if len(m.Document.HtmlSourceJson) == 0 || len(m.Document.HtmlCurrentSourceJson) == 0 || len(m.Document.VariablesJson) == 0 || len(m.Document.MetadataRedactionReport) == 0 {
				return errSignerReadChanged
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.CommitReadV1(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		before := q.snapshotV1(t)
		reader.CloseConsumerV1()
		if after := q.snapshotV1(t); after.Global != before.Global || after.GlobalGrants != before.GlobalGrants {
			t.Fatal("consumer alone refunded before actual original SQL retirement")
		}
		if p := q.runtime.SessionsV1().PendingV1(); p.WorkSessions != 1 || p.SignerReaders != 1 {
			t.Fatal("actual read connection was not still owned", p)
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := reader.CloseV1(cleanup); err != nil {
			t.Fatal(err)
		}
		q.reconcileV1(t)
		if s := q.snapshotV1(t); s.Global != (workguard.VectorV1{ParentBytes: 8 << 20, DBStagingBytes: 8 << 20, SQLSessions: 2}) || s.GlobalGrants != 3 {
			t.Fatal("scope consumer did not retain exact fixed global header after tenant body ended", s)
		}
		scope.CloseConsumerV1()
	})
	q.assertObserversOnlyV1(t)
	t.Run("real_HTTP_write_keeps_original_result_consumer", func(t *testing.T) {
		ctx, cancel := context.WithCancel(q.f.ctx)
		entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		w := &ownedReadResponseWriterV1{ResponseRecorder: httptest.NewRecorder(), ctx: ctx, entered: entered, release: release}
		defer func() {
			unblock()
			cancel()
			select {
			case <-finished:
			case <-time.After(8 * time.Second):
				t.Error("actual HTTP response consumer did not join")
			}
		}()
		go func() {
			defer close(finished)
			q.f.s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+"/sign/"+parties[0].Token, nil).WithContext(ctx))
		}()
		select {
		case <-entered:
		case <-time.After(6 * time.Second):
			t.Fatal("actual public context did not reach response Write")
		}
		p := q.runtime.SessionsV1().PendingV1()
		s := q.snapshotV1(t)
		if p.WorkSessions != 0 || p.SignerReaders != 1 || p.SignerScopes != 1 || s.Global.ParentBytes <= 8<<20 || s.Global.DBStagingBytes <= 8<<20 {
			t.Fatal("public response released full result body before real Write returned", p, s)
		}
		unblock()
		select {
		case <-finished:
		case <-time.After(7 * time.Second):
			t.Fatal("actual response did not join")
		}
		if w.Code != http.StatusOK {
			t.Fatalf("public context response=%d %s", w.Code, w.Body.String())
		}
		var body signerContextResponse
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.DocumentID != doc.ID || body.PDFObservation == nil || body.Privacy.NoticeDigest == "" {
			t.Fatal("public response lost exact source/notice", err)
		}
	})
	q.assertObserversOnlyV1(t)
}

type ownedReadResponseWriterV1 struct {
	*httptest.ResponseRecorder
	ctx     context.Context
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (w *ownedReadResponseWriterV1) Write(body []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	select {
	case <-w.release:
	case <-w.ctx.Done():
		return 0, w.ctx.Err()
	}
	return w.ResponseRecorder.Write(body)
}

func TestOwnedPublicSignerAmbiguityAndMissingCacheRefuseE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	// First prove this exact fresh target is healthy; no cache is synthesized.
	rc := q.lookupV1(t, parties[0].Token)
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	firstHash := auth.HashMagicToken(parties[0].Token)
	second, err := q.f.q.GetRecipient(q.f.ctx, generated.GetRecipientParams{ID: parties[1].RecipientID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.f.q.RotateRecipientMagicToken(q.f.ctx, generated.RotateRecipientMagicTokenParams{ID: second.ID, DocumentID: doc.ID, MagicTokenHash: firstHash, MagicTokenExpiresAt: second.MagicTokenExpiresAt}); err != nil {
		t.Fatal(err)
	}
	if unexpected, err := q.f.s.Sign.LookupByToken(q.f.ctx, firstHash); err == nil || errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) || unexpected != nil {
		if unexpected != nil {
			_ = unexpected.CloseReadV1()
		}
		t.Fatal("same-document duplicate credential did not refuse before tenant/body admission", err)
	}
	if err := q.f.q.RotateRecipientMagicToken(q.f.ctx, generated.RotateRecipientMagicTokenParams{ID: second.ID, DocumentID: doc.ID, MagicTokenHash: second.MagicTokenHash, MagicTokenExpiresAt: second.MagicTokenExpiresAt}); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	// Cross-organization negative fixture is an actual allowed draft only. Its
	// finite literal payload is never returned, measured, marked active/completed
	// or used as a replacement authority; the global cap-two probe must refuse.
	otherOrg, err := q.f.q.CreateOrg(q.f.ctx, generated.CreateOrgParams{Name: "Synthetic duplicate-only draft organization", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	otherUser, err := q.f.q.CreateUser(q.f.ctx, generated.CreateUserParams{OrgID: otherOrg.ID, Email: uuid.NewString() + "@negative.example.test", Name: "Synthetic negative owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	otherDoc, err := q.f.q.CreateBlocksDocument(q.f.ctx, generated.CreateBlocksDocumentParams{OrgID: otherOrg.ID, SenderID: otherUser.ID, Name: "Negative duplicate draft only", BlocksJson: json.RawMessage("{\"version\":1,\"blocks\":[]}"), VariablesJson: json.RawMessage("{}")})
	if err != nil {
		t.Fatal(err)
	}
	other, err := q.f.q.CreateRecipient(q.f.ctx, generated.CreateRecipientParams{DocumentID: otherDoc.ID, Role: "signer", Name: "Synthetic negative recipient", Email: uuid.NewString() + "@negative.example.test", Locale: "en", MagicTokenHash: firstHash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	if unexpected, err := q.f.s.Sign.LookupByToken(q.f.ctx, firstHash); err == nil || errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) || unexpected != nil {
		if unexpected != nil {
			_ = unexpected.CloseReadV1()
		}
		t.Fatal("cross-org duplicate credential did not refuse before tenant/body admission", err)
	}
	if err := q.f.q.RotateRecipientMagicToken(q.f.ctx, generated.RotateRecipientMagicTokenParams{ID: other.ID, DocumentID: otherDoc.ID, MagicTokenHash: bytes.Repeat([]byte{0x6e}, sha256.Size), MagicTokenExpiresAt: other.MagicTokenExpiresAt}); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	if tag, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM document_read_report_sizes_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, q.f.org); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("delete exact genuine cache for unavailable gate", err)
	} //nolint:rawsql -- owned negative cache deletion only, never refresh
	if unexpected, err := q.f.s.Sign.LookupByToken(q.f.ctx, firstHash); !errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) || unexpected != nil {
		if unexpected != nil {
			_ = unexpected.CloseReadV1()
		}
		t.Fatal("missing measured report silently expanded or lost availability refusal", err)
	}
	if w := q.requestV1(parties[0].Token, ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("actual missing-cache route=%d want503", w.Code)
	}
	if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1 AND document_id=$2", parties[0].RecipientID, doc.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- real expiry scalar must precede missing cache refusal
	if unexpected, err := q.f.s.Sign.LookupByToken(q.f.ctx, firstHash); !errors.Is(err, sign.ErrMagicLinkExpired) || unexpected != nil {
		if unexpected != nil {
			_ = unexpected.CloseReadV1()
		}
		t.Fatal("missing cache hid original actual expiry policy", err)
	}
	if w := q.requestV1(parties[0].Token, ""); w.Code != http.StatusGone {
		t.Fatalf("actual expired/missing-cache route=%d want410", w.Code)
	}
	var cacheRows int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM document_read_report_sizes_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, q.f.org).Scan(&cacheRows); err != nil || cacheRows != 0 {
		t.Fatal("request remeasured absent cache", err)
	} //nolint:rawsql -- exact continued absence witness
	q.assertObserversOnlyV1(t)
}
