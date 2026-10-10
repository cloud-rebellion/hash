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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
)

// Retention is deliberately synthetic. Exact version/digest reads and writes
// still use the real storage client against the disposable S3 protocol peer.
// This adapter proves lifecycle binding, not a provider's Object Lock policy.
type signerBrowserEvidenceE2E struct {
	client   *storage.Client
	mu       sync.Mutex
	retained map[string]time.Time
}

func (s *signerBrowserEvidenceE2E) GetVerifiedVersion(ctx context.Context, key, version string, digest []byte) ([]byte, error) {
	return s.client.GetVerifiedVersion(ctx, key, version, digest)
}

func (*signerBrowserEvidenceE2E) ResolveVerifiedLegacy(context.Context, string, []byte) ([]byte, storage.StoredObject, error) {
	return nil, storage.StoredObject{}, errors.New("browser fixture requires exact storage version pins")
}

func (s *signerBrowserEvidenceE2E) RetainEvidenceVersion(ctx context.Context, key, version string, digest []byte, until time.Time) error {
	if !until.After(time.Now()) {
		return errors.New("synthetic retention deadline invalid")
	}
	if _, err := s.client.GetVerifiedVersion(ctx, key, version, digest); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := key + "|" + version
	if until.After(s.retained[identity]) {
		s.retained[identity] = until
	}
	return nil
}

func (s *signerBrowserEvidenceE2E) PutEvidenceVersioned(ctx context.Context, key, contentType string, body []byte, until time.Time) (storage.StoredObject, error) {
	ref, err := s.client.PutVersioned(ctx, key, contentType, body)
	if err != nil {
		return ref, err
	}
	return ref, s.RetainEvidenceVersion(ctx, key, ref.VersionID, ref.SHA256[:], until)
}

type signerBrowserPartyE2E struct {
	Token       string    `json:"token"`
	RecipientID uuid.UUID `json:"recipientID"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	FieldID     uuid.UUID `json:"fieldID"`
}

// Selected external-browser runs must have actual PostgreSQL, a source-built
// hardened worker and the exact real Chromium renderer. There is no renderer
// fallback. The test publishes only its task-owned HTTPS listener; credentials
// are handed to host orchestration through one fresh 0600 packet and stdin.
func TestRealRenderedSignerPDFObservationWithExternalBrowserE2E(t *testing.T) {
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
	probe, err := (&http.Client{Timeout: 5 * time.Second}).Get(target.String() + "/version")
	if err != nil {
		t.Fatal("required exact renderer unavailable")
	}
	version, readErr := io.ReadAll(io.LimitReader(probe.Body, 256))
	_ = probe.Body.Close()
	if readErr != nil || probe.StatusCode != http.StatusOK || strings.TrimSpace(string(version)) != "8.36.0-hash.1" {
		t.Fatal("required source-built renderer version differs")
	}

	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	ctx, cancel := context.WithTimeout(f.ctx, 4*time.Minute)
	defer cancel()
	f.ctx = ctx
	// Match the application's read-only startup convention for terminal stamp
	// processing; worker intake remains mandatory and separately isolated.
	pdfapi.DisableConfigDir()
	if err := sanitize.ConfigurePDFWorker(ctx, os.Getenv("HASH_E2E_PDF_WORKER_PATH"), "production"); err != nil {
		t.Fatal("required isolated PDF worker unavailable")
	}
	t.Cleanup(func() {
		if err := sanitize.ConfigurePDFWorker(context.Background(), "", "development"); err != nil {
			t.Error("reset task PDF worker")
		}
	})
	f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: "pro", ReviewRef: "synthetic signer browser entitlement"}})
	f.s.Versions = versions.New(f.q)
	peer := &htmlCreationStorageE2E{importStoragePeer: &importStoragePeer{objects: make(map[string][]byte)}}
	objectServer := httptest.NewServer(peer)
	defer objectServer.Close()
	f.s.Storage, err = storage.New(ctx, storage.Config{Endpoint: strings.TrimPrefix(objectServer.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-signer-browser", SecretKey: "synthetic-signer-browser-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal("synthetic versioned S3 client unavailable")
	}
	evidence := &signerBrowserEvidenceE2E{client: f.s.Storage, retained: make(map[string]time.Time)}
	certSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal("generate synthetic local certificate signer")
	}
	theme := branding.NewResolver(f.q)
	f.s.BrandingResolver = theme
	f.s.PublicURL, f.s.OperatorName = base.String(), "Synthetic Hash browser operator"
	f.s.PrivacyContact, f.s.SupervisoryAuthority, f.s.PrivacyPolicyURL = "privacy@hash.example.test", "Synthetic authority", base.String()+"/legal/privacy"
	f.s.Sign = &sign.Engine{Pool: f.pool, Queries: f.q, Storage: evidence, PDF: render.NewGotenberg(target.String()), Audit: f.s.Audit, Mailer: dispatch.QueueingMailer{Q: f.q}, Signer: certSigner, BaseURL: base.String(), OrgName: f.s.OperatorName,
		BrandingCSS: func(ctx context.Context, doc *generated.Document) (string, error) {
			b, err := theme.ResolveFrozen(ctx, doc.ID)
			if err != nil {
				return "", err
			}
			return b.CSSVariables(), nil
		}}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
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
	// This explicitly approved fixture-owned page is not automatic branded-page
	// support. Fields below are placed manually against the exact resulting PDF.
	master.HTML += `<section class="manual-signatures"><h2>Reviewed manual signing positions</h2><p>Both named parties sign this exact synthetic document.</p><p>Customer signature</p><p>Provider signature</p></section>`
	master.CSS = `@page{size:A4;margin:20mm}body{font-family:Inter,sans-serif;font-size:12pt;color:#102038}p{line-height:1.35}.scope{white-space:pre-wrap;line-height:1.5}.manual-signatures{break-before:page}`
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatalf("synthetic real-rendered design preflight: %v", err)
	}
	if _, err := compiled.Materialize(htmlmaster.Input{Values: input.Values, Sections: input.Sections}); err != nil {
		t.Fatalf("synthetic real-rendered values preflight: %v", err)
	}
	masterJSON, _ := json.Marshal(master)
	defaults, _ := json.Marshal(input.Values)
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "Real-rendered synthetic two-party review", HTMLMasterJSON: masterJSON, VariablesJSON: defaults}, cookie)
	if w.Code != http.StatusCreated {
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
	for i, row := range rows {
		required := true
		body, _ := json.Marshal(addFieldInput{RecipientID: row.ID.String(), Type: "signature", Page: pages, XPct: 12, YPct: float64(32 + i*22), WPct: 65, HPct: 12, Required: &required, Label: row.Role + " signature", ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
		response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/fields", string(body), cookie)
		if response.Code != http.StatusCreated {
			t.Fatalf("manual source-pinned signature placement status=%d", response.Code)
		}
		var field struct {
			ID uuid.UUID `json:"id"`
		}
		if json.Unmarshal(response.Body.Bytes(), &field) != nil || field.ID == uuid.Nil {
			t.Fatal("manual signature field identity missing")
		}
		fieldByRecipient[row.ID] = field.ID
	}
	doc, err = f.q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal("read placed document")
	}
	review, _ := json.Marshal(map[string]string{"expected_updated_at": doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_pdf_sha256": hex.EncodeToString(doc.PdfSha256), "expected_html_source_commitment": commitment})
	if w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/html/review", string(review), cookie); w.Code != http.StatusOK {
		t.Fatalf("exact real-PDF review status=%d", w.Code)
	}
	sender := &sendengine.Engine{Pool: f.pool, Queries: f.q, Storage: evidence, Audit: f.s.Audit, Mailer: dispatch.QueueingMailer{Q: f.q}, PublicURL: base.String(), OrgName: f.s.OperatorName}
	actor := sendengine.Actor{UserID: &f.user.ID, OrgID: f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	sent, err := sender.Send(ctx, actor, doc.ID)
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatal("real reviewed contract send failed")
	}
	parties := make([]signerBrowserPartyE2E, 0, 2)
	for _, link := range sent.Links {
		parsed, err := url.Parse(link.URL)
		if err != nil {
			t.Fatal("decode private fixture invitation")
		}
		parties = append(parties, signerBrowserPartyE2E{Token: strings.TrimPrefix(parsed.Path, "/sign/"), RecipientID: link.RecipientID, Name: link.Name, Role: link.Role, FieldID: fieldByRecipient[link.RecipientID]})
	}
	// Multi-party contract profiles allow signature fields only. This separate
	// legacy single-signer control proves the real autosave receipt and gate.
	legacy, err := f.q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Synthetic single-signer autosave control", PdfStorageKey: doc.PdfStorageKey, PdfSha256: doc.PdfSha256, PdfStorageVersionID: doc.PdfStorageVersionID, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal("create legacy autosave control")
	}
	_, tokenHash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal("mint synthetic control admission")
	}
	legacyParty, err := f.q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: legacy.ID, Role: "signer", Name: "Synthetic Autosave Person", Email: "autosave@example.test", Locale: "en", MagicTokenHash: tokenHash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal("create autosave recipient")
	}
	text, err := f.q.CreateDraftField(ctx, generated.CreateDraftFieldParams{DocumentID: legacy.ID, OrgID: f.org, RecipientID: pgtype.UUID{Bytes: legacyParty.ID, Valid: true}, Type: "text", Page: int32(pages), XPct: pctToNumeric(12), YPct: pctToNumeric(20), WPct: pctToNumeric(65), HPct: pctToNumeric(8), Required: true, Label: pgtype.Text{String: "Reviewed reference", Valid: true}, OptionsJson: []byte(`{}`)})
	if err != nil {
		t.Fatal("create autosave field")
	}
	legacySignature, err := f.q.CreateDraftField(ctx, generated.CreateDraftFieldParams{DocumentID: legacy.ID, OrgID: f.org, RecipientID: pgtype.UUID{Bytes: legacyParty.ID, Valid: true}, Type: "signature", Page: int32(pages), XPct: pctToNumeric(12), YPct: pctToNumeric(54), WPct: pctToNumeric(65), HPct: pctToNumeric(12), Required: true, OptionsJson: []byte(`{}`)})
	if err != nil {
		t.Fatal("create autosave signature field")
	}
	legacySent, err := sender.Send(ctx, actor, legacy.ID)
	if err != nil || len(legacySent.Links) != 1 {
		t.Fatal("send autosave control")
	}
	legacyURL, _ := url.Parse(legacySent.Links[0].URL)

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
	packet, _ := json.Marshal(map[string]any{"base": base.String(), "documentID": doc.ID, "pdfSHA256": hex.EncodeToString(doc.PdfSha256), "sourceCommitment": commitment, "pageCount": pages, "materializationRevision": 1, "parties": parties, "rendererVersion": strings.TrimSpace(string(version)), "legacy": map[string]any{"documentID": legacy.ID, "token": strings.TrimPrefix(legacyURL.Path, "/sign/"), "recipientID": legacyParty.ID, "name": legacyParty.Name, "textFieldID": text.ID, "signatureFieldID": legacySignature.ID}})
	if err := os.WriteFile(inputPath, packet, 0600); err != nil {
		t.Fatal("write private signer browser packet")
	}
	defer os.Remove(inputPath)
	deadline := time.Now().Add(150 * time.Second)
	for {
		body, err := os.ReadFile(donePath)
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
		if !os.IsNotExist(err) || time.Now().After(deadline) {
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
			t.Fatal("completed signature changed its own manual field")
		}
		if _, err := evidence.GetVerifiedVersion(ctx, signature.ImageStorageKey, signature.ImageVersionID.String, signature.ImageSha256); err != nil {
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
	outputs := []struct {
		name, key, version string
		digest             []byte
	}{{"profile-source.pdf", current.PdfStorageKey.String, current.PdfStorageVersionID.String, current.PdfSha256}, {"profile-final.pdf", current.FinalPdfKey.String, current.FinalPdfVersionID.String, current.FinalPdfSha}, {"profile-certificate.pdf", current.AuditCertKey.String, current.AuditCertVersionID.String, current.AuditCertSha256}}
	artifactHashes := map[string]string{}
	for _, output := range outputs {
		body, err := evidence.GetVerifiedVersion(ctx, output.key, output.version, output.digest)
		if err != nil {
			t.Fatal("read exact completed PDF artifact")
		}
		if output.name == "profile-final.pdf" {
			count, err := sanitize.PageCountWithContext(ctx, body)
			if err != nil || count != pages {
				t.Fatal("final stamped PDF changed reviewed page count")
			}
		}
		if err := os.WriteFile(filepath.Join(artifacts, output.name), body, 0600); err != nil {
			t.Fatal("write synthetic PDF QA artifact")
		}
		sum := sha256.Sum256(body)
		artifactHashes[output.name] = hex.EncodeToString(sum[:])
	}
	receipt, _ := json.MarshalIndent(map[string]any{"result": "pass", "scope": "Actual Go HTTPS/PostgreSQL/source worker, exact Chromium renderer and built browser signing. Participants, S3/retention, certificate key and delivery outbox are synthetic; no SMTP/provider/production/legal acceptance.", "document_id": doc.ID, "source_commitment": commitment, "pdf_sha256": hex.EncodeToString(doc.PdfSha256), "page_count": pages, "signature_count": len(signatures), "autosave_confirmed": true, "manual_signature_fields": true, "automatic_branded_page_support": false, "renderer_version": strings.TrimSpace(string(version)), "artifact_sha256": artifactHashes, "sanitization_report": current.MetadataRedactionReport}, "", "  ")
	if err := os.WriteFile(filepath.Join(artifacts, "backend-receipt.json"), append(receipt, '\n'), 0600); err != nil {
		t.Fatal("write safe signer browser backend receipt")
	}
	t.Log("actual renderer/HTTPS/PG/worker built-browser both-party signing and legacy autosave accepted; synthetic storage retention/outbox/key; manual fields, branded automation pending")
}
