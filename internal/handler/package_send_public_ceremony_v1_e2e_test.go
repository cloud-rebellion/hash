//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

// Public authoring and Send, actual PostgreSQL, native SDK COMPLIANCE retention,
// original recipient signatures, real final/report publication and archive reads.
// The local renderer/storage protocol peers do not qualify a remote deployment.
// No trigger is disabled and no capture, attempt, consent or receipt is seeded.
func TestPublicPackageSendMainDPANDACompleteCeremonyV1E2E(t *testing.T) {
	for _, via := range []string{"REST", "MCP"} {
		t.Run(via, func(t *testing.T) { publicPackageSendMainDPANDACeremonyV1(t, via) })
	}
}
func publicPackageSendMainDPANDACeremonyV1(t *testing.T, via string) {
	q := inspectionFixturePG236(t)
	root := packageImported220(t, q, "Main services agreement")
	dpa := packageImported220(t, q, "Data processing agreement")
	nda := packageImported220(t, q, "Nondisclosure agreement")
	for i, role := range []string{"provider", "customer"} {
		raw, _ := json.Marshal(map[string]any{"email": role + "@public-package.test", "name": "Package " + role, "role": role, "locale": "en"})
		response := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/recipients", string(raw), q.cookie)
		var party recipientResponse
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &party) != nil || party.ID == uuid.Nil {
			t.Fatal("public party creation failed", response.Code, response.Body.String())
		}
		field := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(field, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{"document_id": root.ID.String(), "type": "signature", "recipient_id": party.ID.String(), "page": 1, "required": true, "label": "Signature " + role, "x_pct": 20, "y_pct": 55 + 20*i, "w_pct": 45, "h_pct": 10}, nil))
		if field.Code != http.StatusCreated {
			t.Fatal("public signature placement failed", field.Code, field.Body.String())
		}
	}
	root = packageLatest223(t, q, root.ID)
	// Original imports already have a readable provider retention policy. Keep
	// their exact keys on the strict original-version peer; the output branch
	// has no object or policy until the actual signature/final/report PUT.
	originalKeys := make(map[string]struct{}, 3)
	for _, original := range []*generated.Document{root, dpa, nda} {
		if !original.PdfStorageKey.Valid || original.PdfStorageKey.String == "" {
			t.Fatal("public fixture omitted an exact original PDF key")
		}
		if _, duplicate := originalKeys[original.PdfStorageKey.String]; duplicate {
			t.Fatal("public fixture reused an original PDF key")
		}
		originalKeys[original.PdfStorageKey.String] = struct{}{}
	}
	if len(originalKeys) != 3 {
		t.Fatal("public fixture reused an original PDF key")
	}
	peer := &completedPackagePeer248{main: &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}, mainKey: root.PdfStorageKey.String, originalKeys: originalKeys, until: make(map[string]time.Time)}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-public-package", SecretKey: "synthetic-public-package-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	q.f.s.Storage = client
	q.f.s.Send.Storage = client
	q.f.s.Sign.Storage = client
	var inventory struct {
		DocumentID uuid.UUID `json:"document_id"`
		UpdatedAt  string    `json:"updated_at"`
		PackageID  string    `json:"package_id"`
		Generation string    `json:"generation"`
	}
	for i, annex := range []*generated.Document{dpa, nda} {
		read := submitSessionOperationE2E(q.f.s, http.MethodGet, "/api/v1/documents/"+root.ID.String()+"/attachments", "", q.cookie)
		if read.Code != 200 || json.Unmarshal(read.Body.Bytes(), &inventory) != nil || inventory.DocumentID != root.ID {
			t.Fatal("public attachment inventory failed", read.Code, read.Body.String())
		}
		raw, _ := json.Marshal(map[string]any{"member_document_id": annex.ID.String(), "expected_updated_at": inventory.UpdatedAt, "expected_member_updated_at": annex.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_package_id": inventory.PackageID, "expected_generation": inventory.Generation, "ordinal": i + 1, "title": annex.Name, "category": []string{"DPA", "NDA"}[i]})
		selected := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/attachments", string(raw), q.cookie)
		if selected.Code != http.StatusCreated {
			t.Fatal("public attachment selection failed", selected.Code, selected.Body.String())
		}
	}
	read := submitSessionOperationE2E(q.f.s, http.MethodGet, "/api/v1/documents/"+root.ID.String()+"/attachments", "", q.cookie)
	if read.Code != 200 || json.Unmarshal(read.Body.Bytes(), &inventory) != nil {
		t.Fatal("saved package inventory failed", read.Code)
	}
	selection := packageSendInputV1{ExpectedUpdatedAt: inventory.UpdatedAt, PackageID: inventory.PackageID, Generation: inventory.Generation}
	post := func(selection *packageSendInputV1) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(sendDocumentInput{LawfulBasis: "contract", PackageSend: selection})
		return submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/send", string(raw), q.cookie)
	}
	var mcpInitial *packageSendResponseV1
	var initialMCPSend func()
	var inspectMCP func(uuid.UUID, string)
	if via == "MCP" {
		mint, err := auth.MintAPIKey()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = q.f.q.CreateAPIKey(q.f.ctx, generated.CreateAPIKeyParams{OrgID: q.f.org, UserID: q.f.user.ID, Name: "Public package ceremony MCP", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"read", "write:workflow"}}); err != nil {
			t.Fatal(err)
		}
		q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
		q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, Billing: q.f.s.Billing, Storage: client, Send: q.f.s.Send, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: q.f.s.PublicURL})
		call := func(tool string, args map[string]any) mcp.ToolResult {
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "MCP", tool, mint.Plaintext, args, nil))
			var envelope struct {
				Error  json.RawMessage `json:"error"`
				Result mcp.ToolResult  `json:"result"`
			}
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &envelope) != nil || len(envelope.Error) > 0 || len(envelope.Result.Content) != 1 {
				t.Fatal("actual MCP envelope failed", response.Code, response.Body.String())
			}
			return envelope.Result
		}
		inspectMCP = func(attempt uuid.UUID, want string) {
			result := call("get_document_send_attempt", map[string]any{"document_id": root.ID.String(), "attempt_id": attempt.String()})
			var observed struct {
				AttemptID       uuid.UUID `json:"attempt_id"`
				Outcome         string    `json:"outcome"`
				RetryAuthorized bool      `json:"retry_authorized"`
			}
			if result.IsError || json.Unmarshal([]byte(result.Content[0].Text), &observed) != nil || observed.AttemptID != attempt || observed.Outcome != want || observed.RetryAuthorized {
				t.Fatal("actual MCP native inspection failed", result)
			}
		}
		initialMCPSend = func() {
			result := call("send_document", map[string]any{"document_id": root.ID.String(), "lawful_basis": "contract", "package_send": selection})
			var sent sendDocumentResponse
			if result.IsError || json.Unmarshal([]byte(result.Content[0].Text), &sent) != nil || sent.Status != "sealing" || len(sent.Links) != 0 || sent.PackageSend == nil || sent.PackageSend.Outcome != "active" || !sent.PackageSend.ReconciliationRequired {
				t.Fatal("actual MCP initial Send misrepresented queued package", result)
			}
			mcpInitial = sent.PackageSend
		}
	}
	before := packageFullState223(t, q)
	stale := selection
	stale.Generation = "999999"
	clock := selection
	clock.ExpectedUpdatedAt = "2025-01-01T00:00:00Z"
	for _, refused := range []*packageSendInputV1{nil, &stale, &clock} {
		response := post(refused)
		if response.Code != http.StatusConflict || packageFullState223(t, q) != before {
			t.Fatal("unreviewed package Send caused effects", response.Code, response.Body.String())
		}
	}
	var confirmationsBefore int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*) FROM document_lawful_basis_confirmations WHERE document_id=$1", root.ID).Scan(&confirmationsBefore); err != nil || confirmationsBefore != 0 {
		t.Fatal("public Send fixture must not preconfirm lawful basis", err)
	}
	if initialMCPSend != nil {
		initialMCPSend()
	}
	response := post(&selection)
	var sent sendDocumentResponse
	if response.Code != http.StatusAccepted || json.Unmarshal(response.Body.Bytes(), &sent) != nil || sent.Status != "sealing" || len(sent.Links) != 0 || sent.PackageSend == nil || sent.PackageSend.Outcome != "active" {
		t.Fatal("public package Send did not commit durable sealing", response.Code, response.Body.String())
	}
	confirmed, confirmErr := q.f.q.GetDocumentLawfulBasisConfirmation(q.f.ctx, generated.GetDocumentLawfulBasisConfirmationParams{DocumentID: root.ID, OrgID: q.f.org})
	if confirmErr != nil || confirmed == nil || confirmed.LawfulBasis != "contract" || !confirmed.ConfirmedBy.Valid || uuid.UUID(confirmed.ConfirmedBy.Bytes) != q.f.user.ID || strings.TrimSpace(confirmed.ControllerName) == "" || strings.TrimSpace(confirmed.ControllerContact) == "" {
		t.Fatal("public Send did not record explicit controller instruction and disclosure", confirmErr)
	}
	attempt, err := uuid.Parse(sent.PackageSend.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if mcpInitial != nil {
		if mcpInitial.AttemptID != attempt.String() {
			t.Fatal("REST retry changed MCP initial Send identity")
		}
		inspectMCP(attempt, "active")
	}
	sealed := packageFullState223(t, q)
	duplicate := post(&selection)
	var repeated sendDocumentResponse
	if duplicate.Code != http.StatusAccepted || json.Unmarshal(duplicate.Body.Bytes(), &repeated) != nil || repeated.PackageSend == nil || repeated.PackageSend.AttemptID != attempt.String() || packageFullState223(t, q) != sealed {
		t.Fatal("repeated public Send replayed effects", duplicate.Code, duplicate.Body.String())
	}
	beforeRetention := peer.main.counts240()
	batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
	var m pdfadmission.HTMLSendPackageIntentMetadataV1
	more, err := batch.WithNextSendV1(client, packageCompletionConfig241(t, q), func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
		if v.Attempt.AttemptID != attempt || !v.CompletionVerified || !v.RetentionVerified || v.Status != "sent" || v.Attempt.Capture.MemberCount != 3 {
			t.Fatal("actual package worker omitted a retained member/effect")
		}
		observedClock, parseErr := time.Parse(time.RFC3339Nano, selection.ExpectedUpdatedAt)
		if parseErr != nil || !v.Attempt.Capture.RootUpdatedAt.Equal(observedClock) {
			t.Fatal("Send rewrote the reviewed clock before exact capture", parseErr)
		}
		m = pdfadmission.HTMLSendPackageIntentMetadataV1{AttemptID: attempt, Capture: v.Attempt.Capture, CreatedAt: v.Attempt.CreatedAt, Article13NoticeEpochAt: v.Attempt.Article13NoticeEpochAt, RetainUntil: v.Attempt.RetainUntil}
		return nil
	})
	batch.CloseConsumerV1()
	if err != nil || !more || m.AttemptID == uuid.Nil {
		peer.main.mu.Lock()
		protocolErr := peer.main.failure
		peer.main.mu.Unlock()
		t.Fatal("real package worker completion failed", err, "strict provider observations", peer.main.counts240(), "protocol refusal", protocolErr)
	}
	afterRetention := peer.main.counts240()
	if afterRetention[2]-beforeRetention[2] != 6 || afterRetention[3]-beforeRetention[3] != 3 || afterRetention[4]-beforeRetention[4] != 3 {
		t.Fatal("Send did not read, extend and re-read every original provider policy", beforeRetention, afterRetention)
	}
	peer.main.mu.Lock()
	for key := range originalKeys {
		if peer.main.until[key].Before(m.RetainUntil) {
			peer.main.mu.Unlock()
			t.Fatal("an exact original lacked the acknowledged package retention deadline")
		}
	}
	protocolErr := peer.main.failure
	peer.main.mu.Unlock()
	if protocolErr != nil {
		t.Fatal("strict original provider refused the public Send ceremony", protocolErr)
	}
	packageWorkerDrained239(t, q)
	packageCompletionActualEffects241(t, q, m, "sent", 2)
	if inspectMCP != nil {
		inspectMCP(attempt, "completed")
	}
	copy := documentpackage.IncorporationCopyV1()
	f := packageResponseHTTPFixture247{q: q, m: m, path: "sign", response: documentpackage.ResponseV1{ManifestSHA256: hex.EncodeToString(m.Capture.CanonicalSHA256[:]), LegalCommitmentSHA256: hex.EncodeToString(m.Capture.CommitmentSHA256[:]), IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256, Consent: true}}
	parties, err := q.f.q.ListRecipientsByDocument(q.f.ctx, root.ID)
	if err != nil || len(parties) != 2 {
		t.Fatal("public parties changed", err)
	}
	terminalToken := ""
	for i, party := range parties {
		f.recipient = party.ID
		f.token = signerPackageToken242(t, q, party.ID)
		rc := q.lookupV1(t, f.token)
		notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(f.token, ""), rc)
		if err != nil {
			t.Fatal(err)
		}
		f.notice = notice.NoticeDigest
		if err = rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		metadata := q.requestV1(f.token, "/package")
		var body struct {
			Package *pdfadmission.SignerPackagePresentationV1 `json:"package"`
		}
		if metadata.Code != 200 || json.Unmarshal(metadata.Body.Bytes(), &body) != nil || body.Package == nil || len(body.Package.Annexes) != 2 || body.Package.Annexes[0].Category != "DPA" || body.Package.Annexes[1].Category != "NDA" || body.Package.LegalCommitmentSHA256 != f.response.LegalCommitmentSHA256 {
			t.Fatal("recipient omitted exact listed annexes", metadata.Code)
		}
		noConsent := f.post247(t, nil)
		if noConsent.Code != http.StatusPreconditionRequired {
			t.Fatal("whole-package consent was optional", noConsent.Code, noConsent.Body.String())
		}
		signed := f.post247(t, &f.response)
		var result signerSignResponse
		if signed.Code != 200 || json.Unmarshal(signed.Body.Bytes(), &result) != nil || result.Completed != (i == 1) {
			t.Fatal("public package signature/final report failed", i, signed.Code, signed.Body.String())
		}
		if i == 1 {
			terminalToken = strings.TrimSuffix(strings.TrimPrefix(result.FinalPDFURL, "/sign/"), "/final-pdf")
			if len(terminalToken) != 43 || result.PackagePortalURL != "/completed/"+terminalToken {
				t.Fatal("fresh completed package portal absent")
			}
		}
	}
	var responses, reports, deliveries int
	err = q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*) FROM document_package_responses_v1 WHERE document_id=$1),(SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$1),(SELECT count(*) FROM document_participant_report_deliveries_v1 WHERE document_id=$1)", root.ID).Scan(&responses, &reports, &deliveries)
	if err != nil || responses != 2 || reports != 1 || deliveries != 3 {
		t.Fatal("package/signature/report receipt set incomplete", err, responses, reports, deliveries)
	}
	archive := completedPackageFixture248{active: f, token: terminalToken, etag: signerPackageMemberETag246(m.Capture.CanonicalSHA256, m.Capture.CommitmentSHA256)}
	for position, source := range []*generated.Document{root, dpa, nda} {
		q.storagePeer.mu.Lock()
		want := bytes.Clone(q.storagePeer.objects[source.PdfStorageKey.String])
		q.storagePeer.mu.Unlock()
		pdf := archive.get248(q.f.ctx, terminalToken, "/completed-package/members/"+strconv.Itoa(position)+"/pdf", archive.etag)
		sum := sha256.Sum256(want)
		if pdf.Code != 200 || !bytes.Equal(pdf.Body.Bytes(), want) || pdf.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(sum[:]) {
			t.Fatal("completed portal changed/omitted original package file", position, pdf.Code)
		}
	}
	q.assertObserversOnlyV1(t)
}
