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
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// This fixture requires real PostgreSQL, the isolated PDF worker, actual
// Chromium rendering and a disposable versioned Object Lock S3 server. It uses
// genuine TLS HTTP requests for execution and signing. Session identity is a
// signed synthetic fixture; invitations are asserted in the durable outbox.
// SMTP/inbox delivery and browser paint remain separate acceptance gates.
type presign488HTTP struct {
	base, cookie string
	client       *http.Client
	queryTrace   *presign488QueryTrace
}
type presign488Response struct {
	code   int
	header http.Header
	body   []byte
}

type presign488QueryKey struct{}
type presign488QueryFailure struct{ SQLSHA256, ErrorType, SQLState string }
type presign488QueryTrace struct {
	mu               sync.Mutex
	failures         []presign488QueryFailure
	queryTotal       uint64
	successfulTotal  uint64
	recentSuccessful [16]string
}

func (s *presign488QueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	sum := sha256.Sum256([]byte(d.SQL))
	return context.WithValue(ctx, presign488QueryKey{}, hex.EncodeToString(sum[:]))
}
func (s *presign488QueryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queryTotal++
	if d.Err == nil {
		// The existing TraceQueryStart produces this SHA of SQL only. Neither
		// query text, arguments, result bodies nor error messages are retained.
		hash, _ := ctx.Value(presign488QueryKey{}).(string)
		if len(hash) == 64 {
			s.recentSuccessful[s.successfulTotal%uint64(len(s.recentSuccessful))] = hash
			s.successfulTotal++
		}
		return
	}
	if errors.Is(d.Err, pgx.ErrNoRows) {
		return
	}
	row := presign488QueryFailure{ErrorType: fmt.Sprintf("%T", d.Err)}
	row.SQLSHA256, _ = ctx.Value(presign488QueryKey{}).(string)
	var pgerr *pgconn.PgError
	if errors.As(d.Err, &pgerr) && regexp.MustCompile(`^[0-9A-Z]{5}$`).MatchString(pgerr.Code) {
		row.SQLState = pgerr.Code
	}
	if len(s.failures) < 64 {
		s.failures = append(s.failures, row)
	}
}

// Bounded completion-order snapshot; reads no database and mutates no owner.
func (s *presign488QueryTrace) successfulSnapshotV1() (uint64, uint64, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.recentSuccessful)
	if s.successfulTotal < uint64(count) {
		count = int(s.successfulTotal)
	}
	hashes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		position := (s.successfulTotal - uint64(count) + uint64(i)) % uint64(len(s.recentSuccessful))
		hashes = append(hashes, s.recentSuccessful[position])
	}
	return s.queryTotal, s.successfulTotal, hashes
}

func (h presign488HTTP) call(ctx context.Context, method, path string, value any, session bool, notice string) (presign488Response, error) {
	var out presign488Response
	var raw []byte
	var err error
	if value != nil {
		raw, err = json.Marshal(value)
		if err != nil {
			return out, errors.New("encode controlled request")
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, h.base+path, bytes.NewReader(raw))
	if err != nil {
		return out, errors.New("construct controlled request")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", h.base)
	r.Header.Set("User-Agent", "Hash controlled pre-sign488 journey")
	if session {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: h.cookie})
	}
	if notice != "" {
		r.Header.Set(signerNoticeDigestHeader, notice)
	}
	res, err := h.client.Do(r)
	if err != nil {
		return out, fmt.Errorf("controlled HTTP transport: %T", err)
	} // never print a bearer URL
	out.code, out.header = res.StatusCode, res.Header.Clone()
	out.body, err = io.ReadAll(io.LimitReader(res.Body, 64*1024*1024+1))
	closed := res.Body.Close()
	if err != nil || closed != nil || len(out.body) > 64*1024*1024 {
		return out, errors.New("controlled response not completely read and closed")
	}
	return out, nil
}

func presign488Call(t *testing.T, h presign488HTTP, ctx context.Context, method, path string, in any, session bool, notice string, want int) presign488Response {
	t.Helper()
	v, err := h.call(ctx, method, path, in, session, notice)
	if err != nil || v.code != want {
		sum := sha256.Sum256(v.body)
		t.Fatalf("controlled HTTP phase: status=%d want=%d bytes=%d body_sha256=%x error=%v", v.code, want, len(v.body), sum, err)
	}
	return v
}

func presign488Decode[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var out T
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil || d.Decode(new(any)) != io.EOF {
		t.Fatal("closed controlled response differs from reviewed wire type")
	}
	return out
}

func presign488ReceiptExpiry(t *testing.T, preview presignexecute.PreviewV1) {
	t.Helper()
	observed := time.Now().UTC()
	if preview.ExpiresAt.Location() != time.UTC || preview.ExpiresAt.Nanosecond()%1000 != 0 || !observed.Before(preview.ExpiresAt) || preview.ExpiresAt.After(observed.Add(45*time.Second)) {
		t.Fatal("actual receipt expiry is not a future bounded canonical microsecond timestamp")
	}
}

func presign488Counts(t *testing.T, q *ownedPublicReadFixtureV1, doc uuid.UUID) string {
	t.Helper()
	var out string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_array(
	 (SELECT count(*) FROM presign_executions WHERE org_id=$1),
	 (SELECT count(*) FROM presign_execution_uses WHERE org_id=$1),
	 (SELECT count(*) FROM presign_execution_requests WHERE org_id=$1),
	 (SELECT count(*) FROM presign_preparations_v1 WHERE org_id=$1),
	 (SELECT count(*) FROM presign_preparation_objects_v1 WHERE org_id=$1),
	 (SELECT count(*) FROM signatures WHERE document_id=$2),
	 (SELECT count(*) FROM events WHERE document_id=$2),
	 (SELECT count(*) FROM email_deliveries))::text`, q.f.org, doc).Scan(&out)
	if err != nil {
		t.Fatal("controlled side-effect inventory unavailable")
	}
	return out
}

func presign488Review(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) *generated.Document {
	t.Helper()
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	body := htmlDocumentReviewInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/html/review", string(raw), q.cookie)
	if w.Code != 200 {
		t.Fatalf("genuine source review status=%d", w.Code)
	}
	doc, err = q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
	if err != nil || htmlsource.Validate(doc, true) != nil {
		t.Fatal("actual reviewed source unavailable")
	}
	return doc
}

func presign488Authority(t *testing.T, q *ownedPublicReadFixtureV1, h presign488HTTP, template *generated.Template, doc *generated.Document) (presign.Reference, presign.Reference) {
	t.Helper()
	f := q.f
	r, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: template.Version})
	if err != nil || !r.ApprovedBy.Valid || !r.ApprovedAt.Valid {
		t.Fatal("actual approved template revision unavailable")
	}
	m, err := htmlmaster.Decode(r.HtmlMasterJson)
	if err != nil {
		t.Fatal(err)
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil {
		t.Fatal(err)
	}
	var company, id, basis string
	for _, p := range parties {
		if p.Slot == "provider" {
			if p.Name != f.user.Name || p.Email != f.user.Email {
				t.Fatal("printed provider is not actual grantor")
			}
			company, id, basis = p.CompanyName, p.CompanyID, p.Authority
		}
	}
	d := presignregistry.WorkflowDefinition{Version: 1, ID: uuid.New(), PolicyID: uuid.New(), OrgID: f.org, Revision: 1, Name: "Controlled reviewed pre-sign488", Kind: presignregistry.KindReviewedDocument,
		Template: presign.TemplatePin{ID: template.ID, Version: int64(template.Version), ContentSHA256: hex.EncodeToString(r.ContentSha256), ApprovedBy: uuid.UUID(r.ApprovedBy.Bytes), ApprovedAt: r.ApprovedAt.Time.UTC()},
		Executor: presign.ExecutorIdentity{Kind: presign.ExecutorMember, UserID: f.user.ID}, Operation: presign.OperationPreSignAndSend,
		InputRules:     presignregistry.InputRules{Version: 1, SourceSchemaVersion: 3, Standalone: true, SignatureFieldsOnly: true, AuthorMustBeGrantor: true},
		DataRules:      presignregistry.DataRules{Version: 1, Values: []presignregistry.ValueRule{}, Sections: []presignregistry.SectionRule{}},
		RecipientRules: presignregistry.RecipientRules{Version: 1, Provider: "named_grantor_exact", Customer: "printed_profile_exact", Mode: "parallel", ProviderCompanyName: company, ProviderCompanyID: id, ProviderAuthorityBasis: basis}, MaxGrantDurationSeconds: 3600, MaxUses: 2}
	for _, v := range m.Values {
		d.DataRules.Values = append(d.DataRules.Values, presignregistry.ValueRule{Variable: v.Name, Mode: presignregistry.ModeReviewedValue})
	}
	for _, s := range m.Sections {
		d.DataRules.Sections = append(d.DataRules.Sections, presignregistry.SectionRule{Section: s.Name, Mode: presignregistry.ModeReviewedValue})
	}
	in := presignregistry.WorkflowIntent{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, Definition: d}
	p := presign488Decode[presignregistry.WorkflowPreview](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/workflows/preview", in, true, "", 200).body)
	a := presign488Decode[presignregistry.Outcome](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/workflows/approve", presignregistry.ConfirmWorkflowInput{Intent: p.Intent, Receipt: p.Receipt, Confirmed: true}, true, "", 200).body)
	w := presign488Decode[presignregistry.WorkflowView](t, presign488Call(t, h, f.ctx, "GET", "/api/v1/presign/workflows/"+a.Reference.ID.String(), nil, true, "", 200).body)
	if w.Definition.ID != a.Reference.ID || w.Definition.Revision != a.Reference.Revision || w.DefinitionSHA256 != a.Reference.SHA256 || w.PolicyReference.ID != d.PolicyID || w.PolicyReference.Revision != d.Revision || w.PolicyReference.SHA256 == "" {
		t.Fatal("actual approved workflow/policy reference unavailable")
	}
	g := presignregistry.GrantIntent{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, GrantID: uuid.New(), Policy: w.PolicyReference, CompanyName: company, CompanyID: id, AuthorityBasis: basis, Font: "Caveat", ExpiresAt: time.Now().UTC().Add(30 * time.Minute), MaxUses: 2}
	gp := presign488Decode[presignregistry.GrantPreview](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/self-grants/preview", g, true, "", 200).body)
	ga := presign488Decode[presignregistry.Outcome](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/self-grants/create", presignregistry.ConfirmGrantInput{Intent: gp.Intent, Receipt: gp.Receipt, Confirmed: true}, true, "", 200).body)
	return w.PolicyReference, ga.Reference
}

func presign488SelectedAnnexDenial(t *testing.T, q *ownedPublicReadFixtureV1, h presign488HTTP, template *generated.Template, annex *generated.Document, policy, grant presign.Reference) {
	t.Helper()
	f := q.f
	doc := presign488Review(t, q, createBrandedDocumentE2E(t, f, template, q.cookie))
	intentFor := func(d *generated.Document) presignexecute.IntentV1 {
		commitment, err := htmlsource.Commitment(d)
		if err != nil {
			t.Fatal(err)
		}
		return presignexecute.IntentV1{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, DocumentID: d.ID, DocumentUpdatedAt: d.UpdatedAt.Time.UTC(), MaterializationID: uuid.UUID(d.HtmlCurrentMaterializationID.Bytes), MaterializationRevision: int64(d.HtmlCurrentMaterializationSequence.Int32), SourceCommitment: commitment, Policy: policy, Grant: grant, LawfulBasis: "contract"}
	}
	// Obtain a genuine receipt before selection. The fresh Preview after
	// selection separately uses the current reviewed source and real authority.
	prior := presign488Decode[presignexecute.PreviewV1](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/executions/preview", intentFor(doc), true, "", 200).body)
	presign488ReceiptExpiry(t, prior)
	packageCreate223(t, q, doc, annex)
	doc = presign488Review(t, q, packageLatest223(t, q, doc.ID))
	inventory := preSignAuthFixture488{owned: q}
	before, packageBefore := inventory.snapshot(t), packageFullState223(t, q)
	eligibility := presign488Decode[presignexecute.EligibilityV1](t, presign488Call(t, h, f.ctx, "GET", "/api/v1/presign/executions/documents/"+doc.ID.String()+"/eligibility", nil, true, "", 200).body)
	if eligibility.Eligible || eligibility.Source != nil {
		t.Fatal("selected annex advertised standalone pre-sign eligibility")
	}
	presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/executions/preview", intentFor(doc), true, "", 409)
	presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/executions", presignexecute.ConfirmV1{Intent: prior.Intent, Receipt: prior.Receipt, Confirmed: true}, true, "", 409)
	inventory.unchanged(t, before)
	if packageFullState223(t, q) != packageBefore {
		t.Fatal("refused standalone execution changed selected package")
	}
}

func TestPresign488ActualHTTPConcurrentReplayCustomerSignAndEvidenceE2E(t *testing.T) {
	presign488ActualHTTPJourney(t, false, false)
}

func TestPresign488ActualHTTPSelectedAnnexDenialE2E(t *testing.T) {
	presign488ActualHTTPJourney(t, true, false)
}

func TestPresign488ActualHTTPAPIPriorSupersessionAfterCompletionE2E(t *testing.T) {
	presign488ActualHTTPJourney(t, false, true)
}

func presign488ActualHTTPJourney(t *testing.T, selectedAnnexOnly, apiPriorOnly bool) {
	if os.Getenv("HASH_PRESIGN_EXECUTION_E2E") != "1" {
		t.Skip("explicit disposable real-renderer/Object-Lock pre-sign488 estate required")
	}
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_PDF_WORKER_PATH", "HASH_E2E_RENDERER_URL", "HASH_E2E_RENDERER_IMAGE_ID", "HASH_E2E_S3_ENDPOINT", "HASH_E2E_S3_BUCKET", "HASH_E2E_S3_ACCESS_KEY", "HASH_E2E_S3_SECRET_KEY"} {
		if os.Getenv(name) == "" {
			t.Fatal("missing explicit controlled dependency", name)
		}
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(os.Getenv("HASH_E2E_RENDERER_IMAGE_ID")) || !strings.HasPrefix(os.Getenv("HASH_E2E_S3_BUCKET"), "hash-presign488-") {
		t.Fatal("exact renderer and unique disposable bucket required")
	}
	// Allocate actual overlay/renderer slots before the runtime and pool are born.
	// Limits match existing physical worker/source bounds; no guard is relaxed.
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, ChildAddressBytes: 2 << 30, PDFWorkers: 1, SQLSessions: 8, ProviderStreams: 1, RendererRequests: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, ChildAddressBytes: 2 << 30, PDFWorkers: 1, SQLSessions: 4, ProviderStreams: 1, RendererRequests: 1}, MaxGrants: 128, MaxOrganisationGrants: 64}
	trace := &presign488QueryTrace{}
	t.Cleanup(func() {
		if t.Failed() {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			t.Logf("bounded native query failures (no SQL, arguments or messages): %+v", trace.failures)
		}
	})
	q := newOwnedPublicReadFixtureAllocated257dV1(t, false, limits, trace)
	f := q.f
	// Import through the existing native synthetic-provider fixture before
	// installing the real storage for the primary contract signing journey.
	var annex *generated.Document
	if selectedAnnexOnly {
		ownedCreationPrepareProPlanV1(t, q)
		annex = packageImported220(t, q, "Controlled selected annex")
	}
	stored, err := storage.New(f.ctx, storage.Config{Endpoint: os.Getenv("HASH_E2E_S3_ENDPOINT"), Region: "us-east-1", Bucket: os.Getenv("HASH_E2E_S3_BUCKET"), AccessKey: os.Getenv("HASH_E2E_S3_ACCESS_KEY"), SecretKey: os.Getenv("HASH_E2E_S3_SECRET_KEY"), BucketLookup: "path", RequireObjectLock: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal("disposable Object Lock storage unavailable")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	provider, err := minio.New(os.Getenv("HASH_E2E_S3_ENDPOINT"), &minio.Options{Creds: credentials.NewStaticV4(os.Getenv("HASH_E2E_S3_ACCESS_KEY"), os.Getenv("HASH_E2E_S3_SECRET_KEY"), ""), Secure: false, Region: "us-east-1", BucketLookup: minio.BucketLookupPath, Transport: transport})
	if err != nil {
		t.Fatal("disposable independent retention observer unavailable")
	}
	retained := func(key, version string, until time.Time) bool {
		mode, actual, e := provider.GetObjectRetention(f.ctx, os.Getenv("HASH_E2E_S3_BUCKET"), key, version)
		return e == nil && mode != nil && *mode == minio.Compliance && actual != nil && !actual.Before(until)
	}
	f.s.Storage, f.s.Send.Storage, f.s.Sign.Storage = stored, stored, stored
	f.s.PreSignExecutionEnabled = true // explicit disposable-journey opt-in; production default remains unavailable until qualified
	if apiPriorOnly {
		f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	}
	f.s.Sign.PDF = render.NewGotenberg(os.Getenv("HASH_E2E_RENDERER_URL"))
	var router http.Handler
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { router.ServeHTTP(w, r) }))
	base := "https://" + srv.Listener.Addr().String()
	f.s.PublicURL, f.s.Send.PublicURL, f.s.Sign.BaseURL = base, base, base
	f.s.PrivacyPolicyURL = base + "/legal/privacy"
	router = f.s.Routes()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client := srv.Client()
	t.Cleanup(client.CloseIdleConnections)
	h := presign488HTTP{base: base, cookie: q.cookie, client: client, queryTrace: trace}
	template := createBrandedDesignVariantE2E(t, f, q.cookie, func(_ *htmlmaster.Master, values map[string]string) {
		values["provider_name"], values["provider_email"] = f.user.Name, f.user.Email
	})
	approveBrandedDesignE2E(t, f, template, q.storagePeer, q.cookie)
	doc := presign488Review(t, q, createBrandedDocumentE2E(t, f, template, q.cookie))
	policy, grant := presign488Authority(t, q, h, template, doc)
	if selectedAnnexOnly {
		presign488SelectedAnnexDenial(t, q, h, template, annex, policy, grant)
		return
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	intent := presignexecute.IntentV1{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, DocumentID: doc.ID, DocumentUpdatedAt: doc.UpdatedAt.Time.UTC(), MaterializationID: uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes), MaterializationRevision: int64(doc.HtmlCurrentMaterializationSequence.Int32), SourceCommitment: commitment, Policy: policy, Grant: grant, LawfulBasis: "contract"}
	before := presign488Counts(t, q, doc.ID)
	preview := presign488Decode[presignexecute.PreviewV1](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/executions/preview", intent, true, "", 200).body)
	presign488ReceiptExpiry(t, preview)
	if preview.Intent.RequestID != intent.RequestID || preview.Receipt == "" || presign488Counts(t, q, doc.ID) != before {
		t.Fatal("preview lost original intent or had execution effects")
	}
	confirm := presignexecute.ConfirmV1{Intent: preview.Intent, Receipt: preview.Receipt, Confirmed: true}
	responses := make(chan presign488Response, 2)
	faults := make(chan error, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			v, e := h.call(f.ctx, "POST", "/api/v1/presign/executions", confirm, true, "")
			responses <- v
			faults <- e
		}()
	}
	workers.Wait()
	close(responses)
	close(faults)
	for e := range faults {
		if e != nil {
			t.Fatal("concurrent controlled request did not join")
		}
	}
	var unexpected []int
	for v := range responses {
		sum := sha256.Sum256(v.body)
		t.Logf("joined concurrent original response status=%d bytes=%d body_sha256=%x", v.code, len(v.body), sum)
		if v.code != 200 && v.code != 503 {
			unexpected = append(unexpected, v.code)
		}
	}
	if len(unexpected) != 0 {
		t.Fatalf("concurrent original request unexpected statuses=%v actual_effect_counts=%s", unexpected, presign488Counts(t, q, doc.ID))
	}
	requestPath := "/api/v1/presign/executions/requests/" + intent.RequestID.String()
	view := presign488Decode[presignexecute.ViewV1](t, presign488Call(t, h, f.ctx, "GET", requestPath, nil, true, "", 200).body)
	if view.State != "committed" || view.Result == nil || view.Result.DocumentID != doc.ID || view.Result.UseNumber != 1 || view.Result.Publication != "published" || view.Result.VisiblePDFSHA256 == hex.EncodeToString(doc.PdfSha256) {
		t.Fatal("original request did not publish exactly one real derivative")
	}
	var executionRaw, assetRaw []byte
	var until time.Time
	if err := f.pool.QueryRow(f.ctx, `SELECT e.canonical_execution,a.canonical_assets,p.retain_until FROM presign_executions e JOIN presign_execution_assets_v1 a ON a.org_id=e.org_id AND a.execution_id=e.id JOIN presign_execution_publications_v1 p ON p.org_id=e.org_id AND p.execution_id=e.id WHERE e.org_id=$1 AND e.document_id=$2`, f.org, doc.ID).Scan(&executionRaw, &assetRaw, &until); err != nil {
		t.Fatal("actual committed execution/assets unavailable")
	}
	execution, err := presign.DecodeExecution(executionRaw)
	if err != nil {
		t.Fatal("actual execution canonical bytes invalid")
	}
	assets, err := presignexecute.DecodeAssetSetV1(execution, assetRaw)
	if err != nil {
		t.Fatal("actual archive canonical bytes invalid")
	}
	if execution.Commitment() != view.Result.Execution.SHA256 || execution.Snapshot().ID != view.Result.Execution.ID || execution.Snapshot().VisiblePDF.Artifact.SHA256 != view.Result.VisiblePDFSHA256 {
		t.Fatal("wire result differs from actual committed execution")
	}
	objects := []presign.ArtifactPin{execution.Snapshot().Document.BasePDF.Artifact}
	for _, a := range assets.Snapshot().Objects {
		objects = append(objects, a.Object)
	}
	for _, o := range objects {
		if !retained(o.StorageKey, o.VersionID, until) {
			t.Fatal("publication preceded actual exact-version retention")
		}
	}
	var uses, signatures, manualEvents int
	var providerQuiet bool
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM presign_execution_uses WHERE org_id=$1),(SELECT count(*) FROM signatures WHERE document_id=$2),(SELECT count(*) FROM events WHERE document_id=$2 AND kind='document.signed'),EXISTS(SELECT 1 FROM recipients WHERE document_id=$2 AND role='provider' AND status='signed' AND coalesce(octet_length(magic_token_hash),0)=0 AND magic_token_expires_at=to_timestamp(0) AND sent_at IS NULL AND first_viewed_at IS NULL)`, f.org, doc.ID).Scan(&uses, &signatures, &manualEvents, &providerQuiet); err != nil || uses != 1 || signatures != 1 || manualEvents != 0 || !providerQuiet {
		t.Fatal("delegated execution duplicated use or invented a provider visit/manual response")
	}
	var to, mail string
	var queued int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM email_deliveries`).Scan(&queued); err != nil || queued != 1 {
		t.Fatal("exactly one customer invitation must be queued")
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT to_email,text_body FROM email_deliveries`).Scan(&to, &mail); err != nil {
		t.Fatal("customer invitation unavailable")
	}
	var customer *generated.Recipient
	recipients, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recipients {
		if r.Role == "customer" {
			customer = r
		}
	}
	if customer == nil || to != customer.Email {
		t.Fatal("invitation did not target the original customer only")
	}
	link := regexp.MustCompile(regexp.QuoteMeta(base) + `/sign/[A-Za-z0-9_-]+`).FindString(mail)
	u, err := url.Parse(link)
	if err != nil || link == "" {
		t.Fatal("actual queued capability unavailable")
	}
	token := strings.TrimPrefix(u.Path, "/sign/")
	after := presign488Counts(t, q, doc.ID)
	replay := presign488Decode[presignexecute.ViewV1](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/executions", confirm, true, "", 200).body)
	if replay.Result == nil || *replay.Result != *view.Result || presign488Counts(t, q, doc.ID) != after {
		t.Fatal("replay changed original execution or repeated effects")
	}
	mutant := confirm
	mutant.Intent.SourceCommitment = strings.Repeat("a", 64)
	presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/executions", mutant, true, "", 409)
	if presign488Counts(t, q, doc.ID) != after {
		t.Fatal("conflicting original request changed durable effects")
	}
	freshDoc := presign488Review(t, q, createBrandedDocumentE2E(t, f, template, q.cookie))
	freshCommitment, err := htmlsource.Commitment(freshDoc)
	if err != nil {
		t.Fatal(err)
	}
	freshIntent := intent
	freshIntent.RequestID = uuid.New()
	freshIntent.DocumentID = freshDoc.ID
	freshIntent.DocumentUpdatedAt = freshDoc.UpdatedAt.Time.UTC()
	freshIntent.MaterializationID = uuid.UUID(freshDoc.HtmlCurrentMaterializationID.Bytes)
	freshIntent.MaterializationRevision = int64(freshDoc.HtmlCurrentMaterializationSequence.Int32)
	freshIntent.SourceCommitment = freshCommitment
	freshBefore := presign488Counts(t, q, freshDoc.ID)
	freshPreview := presign488Decode[presignexecute.PreviewV1](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/executions/preview", freshIntent, true, "", 200).body)
	presign488ReceiptExpiry(t, freshPreview)
	if presign488Counts(t, q, freshDoc.ID) != freshBefore {
		t.Fatal("fresh preview performed execution effects")
	}
	presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/self-grants/"+grant.ID.String()+"/revoke", presignregistry.ResourceMutationInput{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, Reference: grant, Confirmed: true}, true, "", 200)
	recovered := presign488Decode[presignexecute.ViewV1](t, presign488Call(t, h, f.ctx, "GET", requestPath, nil, true, "", 200).body)
	if recovered.Result == nil || *recovered.Result != *view.Result {
		t.Fatal("revocation destroyed the original committed recovery")
	}
	afterRevoke := presign488Counts(t, q, doc.ID)
	originalReplay := presign488Decode[presignexecute.ViewV1](t, presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/executions", confirm, true, "", 200).body)
	if originalReplay.Result == nil || *originalReplay.Result != *view.Result || presign488Counts(t, q, doc.ID) != afterRevoke {
		t.Fatal("revocation prevented exact original replay or repeated its effects")
	}
	freshAfterRevoke := presign488Counts(t, q, freshDoc.ID)
	presign488Call(t, h, f.ctx, "POST", "/api/v1/presign/executions", presignexecute.ConfirmV1{Intent: freshPreview.Intent, Receipt: freshPreview.Receipt, Confirmed: true}, true, "", 403)
	if presign488Counts(t, q, freshDoc.ID) != freshAfterRevoke {
		t.Fatal("revoked authority performed fresh execution effects")
	}
	read := presign488Call(t, h, f.ctx, "GET", "/sign/"+token, nil, false, "", 200)
	customerContext := presign488Decode[signerContextResponse](t, read.body)
	wantDisclosure := sign.PreSignContextV1{SchemaVersion: 1, DocumentID: doc.ID, ExecutionID: execution.Snapshot().ID, ExecutionSHA256: execution.Commitment(), VisiblePDFSHA256: view.Result.VisiblePDFSHA256, DisclosureVersion: presignregistry.Disclosure().Version, DisclosureSHA256: presignregistry.Disclosure().SHA256, DisclosureText: presignregistry.Disclosure().Text, ProviderName: f.user.Name, ExecutedAt: execution.Snapshot().ExecutedAt.UTC().Format(time.RFC3339Nano)}
	if customerContext.DocumentID != doc.ID || customerContext.Recipient.ID != customer.ID || customerContext.PreSignContext == nil || *customerContext.PreSignContext != wantDisclosure || customerContext.Privacy.NoticeDigest == "" || customerContext.PDFObservation == nil || customerContext.PDFObservation.PDFSHA256 != view.Result.VisiblePDFSHA256 || customerContext.PDFObservation.DocumentID != doc.ID || customerContext.PDFObservation.RecipientID != customer.ID {
		t.Fatal("customer disclosure/observation does not describe the original provider execution and exact visible PDF")
	}
	pdf := presign488Call(t, h, f.ctx, "GET", "/sign/"+token+"/pdf", nil, false, "", 200)
	sum := sha256.Sum256(pdf.body)
	if hex.EncodeToString(sum[:]) != view.Result.VisiblePDFSHA256 || !bytes.HasPrefix(pdf.body, []byte("%PDF-")) {
		t.Fatal("first customer PDF is not the committed provider-visible derivative")
	}
	presign488Call(t, h, f.ctx, "POST", "/sign/"+token+"/sign", signerSignInput{TypedName: customer.Name, Font: "Caveat"}, false, "", 428)
	actualSign, signFailure := h.call(f.ctx, "POST", "/sign/"+token+"/sign", signerSignInput{TypedName: customer.Name, Font: "Caveat"}, false, customerContext.Privacy.NoticeDigest)
	if signFailure != nil || actualSign.code != 200 {
		t.Logf("actual customer signing scalar effect counts: %s", presign488Counts(t, q, doc.ID))
		bodySHA := sha256.Sum256(actualSign.body)
		t.Fatalf("actual customer signing status=%d want=200 bytes=%d body_sha256=%x error_type=%T", actualSign.code, len(actualSign.body), bodySHA, signFailure)
	}
	signed := presign488Decode[signerSignResponse](t, actualSign.body)
	if !signed.Completed {
		t.Logf("actual committed-customer finalization scalar effect counts: %s", presign488Counts(t, q, doc.ID))
		observed, observationErr := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
		if observationErr != nil {
			t.Logf("actual finalization state error_type=%T", observationErr)
		} else if observed != nil {
			t.Logf("actual finalization state status=%s report_schema=%s", observed.Status, observed.ParticipantReportSchema)
		}
		t.Fatal("actual customer response did not complete the original delegated contract")
	}
	final, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || final.Status != "completed" || final.PdfStorageKey != doc.PdfStorageKey || final.PdfStorageVersionID != doc.PdfStorageVersionID || !bytes.Equal(final.PdfSha256, doc.PdfSha256) {
		t.Fatal("completion changed original source or did not finish")
	}
	if !final.FinalizationRetainUntil.Valid || final.FinalizationRetainUntil.Time.Before(until) {
		t.Fatal("actual finalization retention target unavailable")
	}
	completionUntil := final.FinalizationRetainUntil.Time
	for _, o := range objects {
		if !retained(o.StorageKey, o.VersionID, completionUntil) {
			t.Fatal("completion failed to retain original base and all8 archived assets through its actual durable target")
		}
	}
	type artifact struct {
		key, version pgtype.Text
		sha          []byte
	}
	var bodies [][]byte
	for _, a := range []artifact{{final.FinalPdfKey, final.FinalPdfVersionID, final.FinalPdfSha}, {final.AuditCertKey, final.AuditCertVersionID, final.AuditCertSha256}, {final.AuditPayloadKey, final.AuditPayloadVersionID, final.AuditPayloadSha256}, {final.AuditSignatureKey, final.AuditSignatureVersionID, final.AuditSignatureSha256}} {
		if !a.key.Valid || !a.version.Valid || len(a.sha) != 32 || !retained(a.key.String, a.version.String, completionUntil) {
			t.Fatal("completed artifact lacks exact retained version")
		}
		body, e := stored.GetVerifiedVersion(f.ctx, a.key.String, a.version.String, a.sha)
		if e != nil {
			t.Fatal("completed exact artifact unavailable")
		}
		bodies = append(bodies, body)
	}
	if !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(bodies[2]), string(bodies[3])) {
		t.Fatal("actual detached certificate signature is invalid")
	}
	claims, err := evidence.ParseCertificateCommitments(bodies[2])
	if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV3 || claims.FinalPDFSHA256 != hex.EncodeToString(final.FinalPdfSha) {
		t.Fatal("signed certificate does not bind actual V3/final PDF")
	}
	carrier := render.ParticipantReportCanonicalCarrierV3
	signedHTML := string(bodies[2])
	start := strings.Index(signedHTML, carrier)
	if start < 0 || strings.Count(signedHTML, carrier) != 1 {
		t.Fatal("one signed V3 canonical carrier required")
	}
	tail := signedHTML[start+len(carrier):]
	end := strings.Index(tail, "</pre>")
	if end < 0 {
		t.Fatal("V3 carrier incomplete")
	}
	report, err := render.DecodeParticipantReportCanonicalV2([]byte(html.UnescapeString(tail[:end])))
	if err != nil || report.DelegatedExecution == nil {
		t.Fatal("closed V3 delegated report unavailable")
	}
	delegated := report.DelegatedExecution
	var eventID uuid.UUID
	var eventHash []byte
	var eventAt time.Time
	if err := f.pool.QueryRow(f.ctx, `SELECT ev.id,ev.row_hash,ev.created_at FROM presign_executions ex JOIN events ev ON ev.id=ex.audit_event_id WHERE ex.org_id=$1 AND ex.id=$2 AND ev.kind='presign.execution.committed' AND ev.document_id=$3`, f.org, execution.Snapshot().ID, doc.ID).Scan(&eventID, &eventHash, &eventAt); err != nil || len(eventHash) != 32 {
		t.Fatal("original committed audit row unavailable")
	}
	x := execution.Snapshot()
	copy := presignregistry.Disclosure()
	wantDelegated := render.ParticipantDelegatedExecutionV1{SchemaVersion: 1, EventID: eventID.String(), EventRowSHA256: hex.EncodeToString(eventHash), EventAt: eventAt.UTC().Format(time.RFC3339Nano), ExecutionID: x.ID.String(), ExecutionSHA256: execution.Commitment(), PolicyID: x.Policy.ID.String(), PolicyRevision: x.Policy.Revision, PolicySHA256: x.Policy.SHA256, GrantID: x.Grant.ID.String(), GrantRevision: x.Grant.Revision, GrantSHA256: x.Grant.SHA256, UseNumber: x.UseNumber, ProviderRecipientID: x.Signature.RecipientID.String(), ProviderSignatureID: x.Signature.ID.String(), ProviderName: f.user.Name, ExecutedAt: x.ExecutedAt.UTC().Format(time.RFC3339Nano), BasePDFSHA256: hex.EncodeToString(doc.PdfSha256), VisiblePDFSHA256: view.Result.VisiblePDFSHA256, AssetsSHA256: assets.Commitment(), OverlayProofSHA256: x.VisibleStampProofSHA256, DisclosureVersion: copy.Version, DisclosureSHA256: copy.SHA256, DisclosureText: copy.Text}
	if *delegated != wantDelegated {
		t.Fatal("signed report substitutes original audit row, provider authority, artifacts or disclosure")
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM presign_execution_uses WHERE org_id=$1),(SELECT count(*) FROM signatures WHERE document_id=$2),(SELECT count(*) FROM events WHERE document_id=$2 AND kind='document.signed')`, f.org, doc.ID).Scan(&uses, &signatures, &manualEvents); err != nil || uses != 1 || signatures != 2 || manualEvents != 1 {
		t.Fatal("final evidence duplicated provider use/manual response")
	}
	providerRecipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: execution.Snapshot().Signature.RecipientID, OrgID: f.org})
	if err != nil || providerRecipient == nil || len(providerRecipient.MagicTokenHash) != 0 || !providerRecipient.MagicTokenExpiresAt.Valid || providerRecipient.MagicTokenExpiresAt.InfinityModifier != pgtype.Finite || !providerRecipient.MagicTokenExpiresAt.Time.Equal(time.Unix(0, 0)) {
		t.Fatal("completion changed the delegated provider permanent public-credential disablement")
	}
	var providerPublicMessages int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM email_deliveries WHERE to_email=$1 AND (strpos(text_body,'/sign/')>0 OR strpos(html_body,'/sign/')>0 OR strpos(text_body,'/completed/')>0 OR strpos(html_body,'/completed/')>0)`, providerRecipient.Email).Scan(&providerPublicMessages); err != nil || providerPublicMessages != 0 {
		t.Fatal("completion created a public recipient link for the delegated provider")
	}
	for index, path := range []string{signed.FinalPDFURL, signed.AuditCertURL} {
		if !strings.HasPrefix(path, "/sign/") || (index == 0 && !strings.HasSuffix(path, "/final-pdf")) || (index == 1 && !strings.HasSuffix(path, "/audit-cert")) {
			t.Fatal("customer completion did not return its separate read-only artifact paths")
		}
		read, readErr := h.call(f.ctx, "GET", path, nil, false, "")
		if readErr != nil || read.code != 200 || !bytes.Equal(read.body, bodies[index]) {
			t.Fatal("customer completion credential did not read the exact retained artifact")
		}
	}
	completedCounts := presign488Counts(t, q, doc.ID)
	oldCredential, oldCredentialErr := h.call(f.ctx, "POST", "/sign/"+token+"/sign", signerSignInput{TypedName: customer.Name, Font: "Caveat"}, false, customerContext.Privacy.NoticeDigest)
	if oldCredentialErr != nil || oldCredential.code != 404 || presign488Counts(t, q, doc.ID) != completedCounts {
		t.Fatal("old ceremony credential remained usable or changed completed effects")
	}
	if apiPriorOnly {
		presign488APIPriorSupersessionAfterCompletion(t, q, h, template, final, execution, assets, bodies, retained)
	} else {
		presign488SessionSupersessionAfterCompletion(t, q, h, template, final, execution, assets, bodies, retained)
	}
	q.assertObserversOnlyV1(t)
}
