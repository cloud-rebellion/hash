//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
)

// This separate qualification holds the real browser-facing native PDF write.
// Neither cleanup, browser closure nor a deadline may supply its PASS witness.
// The existing full manual/two-party/four-artifact journey remains unchanged.
type ownedPortalCancelGate198 struct {
	mu                                                                      sync.Mutex
	failure                                                                 string
	otherActive, metadataJoined, commentsJoined                             int
	pdfWrites, fieldsWrites                                                 int
	prefixBytes, nativePDFBytes, nativeFieldsBytes                          int
	fieldsValid, prefixFlushed, canceled, escapeUsed, malformedSent         bool
	expected                                                                map[string]string
	documentID, recipientID, fieldID                                        uuid.UUID
	pdfPrefix, fieldsProducer, pdfJoined, fieldsHTTPJoined, release, escape chan struct{}
	armed                                                                   atomic.Bool
	pdfSelected, fieldsSelected                                             atomic.Bool
}

func (g *ownedPortalCancelGate198) fail(reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failure == "" {
		g.failure = reason
	}
}
func (g *ownedPortalCancelGate198) checkHeaders(h http.Header, contentType string) bool {
	if h.Get("Content-Type") != contentType {
		return false
	}
	for name, value := range g.expected {
		if h.Get(name) != value {
			return false
		}
	}
	return true
}

type ownedPortalPDFWriter198 struct {
	http.ResponseWriter
	request *http.Request
	gate    *ownedPortalCancelGate198
	status  int
}

func (w *ownedPortalPDFWriter198) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *ownedPortalPDFWriter198) WriteHeader(code int) {
	if w.status != 0 {
		w.gate.fail("duplicate-pdf-status")
		return
	}
	w.status = code
}
func (w *ownedPortalPDFWriter198) Write(body []byte) (int, error) {
	g := w.gate
	g.mu.Lock()
	g.pdfWrites++
	calls := g.pdfWrites
	g.mu.Unlock()
	code := w.status
	if code == 0 {
		code = http.StatusOK
	}
	if calls != 1 || code != http.StatusOK || !g.checkHeaders(w.Header(), "application/pdf") || len(body) <= 1024 || !bytes.HasPrefix(body, []byte("%PDF-")) {
		g.fail("invalid-native-pdf")
		return 0, errors.New("native PDF qualification refused")
	}
	// Preserve truthful full length; send only a proper prefix of these real bytes.
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.ResponseWriter.WriteHeader(code)
	n, err := w.ResponseWriter.Write(body[:1024])
	if err != nil || n != 1024 {
		g.fail("prefix-write")
		return n, err
	}
	if err = http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		g.fail("prefix-flush")
		return n, err
	}
	g.mu.Lock()
	g.prefixBytes = n
	g.nativePDFBytes = len(body)
	g.prefixFlushed = true
	g.mu.Unlock()
	close(g.pdfPrefix)
	select {
	case <-w.request.Context().Done():
		g.mu.Lock()
		g.canceled = errors.Is(w.request.Context().Err(), context.Canceled)
		g.mu.Unlock()
		return n, w.request.Context().Err()
	case <-g.escape:
		g.mu.Lock()
		g.escapeUsed = true
		g.mu.Unlock()
		return n, errors.New("qualification cleanup escape")
	}
}

type ownedPortalFieldsWriter198 struct {
	http.ResponseWriter
	gate   *ownedPortalCancelGate198
	status int
}

func (w *ownedPortalFieldsWriter198) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *ownedPortalFieldsWriter198) WriteHeader(code int) {
	if w.status != 0 {
		w.gate.fail("duplicate-fields-status")
		return
	}
	w.status = code
}
func (w *ownedPortalFieldsWriter198) Write(body []byte) (int, error) {
	g := w.gate
	g.mu.Lock()
	g.fieldsWrites++
	calls := g.fieldsWrites
	g.mu.Unlock()
	code := w.status
	if code == 0 {
		code = http.StatusOK
	}
	// JSON field names carry underscores; use the real public response DTO instead.
	var native struct {
		Fields []struct {
			ID          uuid.UUID
			DocumentID  uuid.UUID `json:"document_id"`
			RecipientID uuid.UUID `json:"recipient_id"`
		}
		Count *int
	}
	if calls != 1 || code != http.StatusOK || !g.checkHeaders(w.Header(), "application/json") || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(body, &native) != nil || len(native.Fields) != 1 || native.Fields[0].ID != g.fieldID || native.Fields[0].DocumentID != g.documentID || native.Fields[0].RecipientID != g.recipientID || (native.Count == nil || *native.Count != 1) {
		g.fail("invalid-native-fields")
		return 0, errors.New("native fields qualification refused")
	}
	g.mu.Lock()
	g.fieldsValid = true
	g.nativeFieldsBytes = len(body)
	g.mu.Unlock()
	// No body copy is retained and nothing is transmitted. Returning releases
	// both actual native page and reader consumers when core.ServeHTTP returns.
	return len(body), nil
}
func (g *ownedPortalCancelGate198) wrap(core http.Handler, selected string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.armed.Load() || !strings.HasPrefix(r.URL.Path, selected) {
			core.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet {
			g.fail("unexpected-mutating-request")
			core.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case selected + "/pdf":
			if !g.pdfSelected.CompareAndSwap(false, true) {
				g.fail("duplicate-pdf-request")
				core.ServeHTTP(w, r)
				return
			}
			core.ServeHTTP(&ownedPortalPDFWriter198{ResponseWriter: w, request: r, gate: g}, r)
			close(g.pdfJoined)
		case selected + "/fields":
			if !g.fieldsSelected.CompareAndSwap(false, true) {
				g.fail("duplicate-fields-request")
				core.ServeHTTP(w, r)
				return
			}
			dst := &ownedPortalFieldsWriter198{ResponseWriter: w, gate: g}
			core.ServeHTTP(dst, r)
			close(g.fieldsProducer)
			defer close(g.fieldsHTTPJoined)
			select {
			case <-g.release:
			case <-r.Context().Done():
				g.fail("fields-canceled-before-malformed")
				return
			case <-g.escape:
				g.fail("fields-cleanup-escape")
				return
			}
			g.mu.Lock()
			valid := g.fieldsValid && g.failure == ""
			g.mu.Unlock()
			if !valid {
				return
			}
			w.Header().Set("Content-Length", "1")
			w.WriteHeader(http.StatusOK)
			n, err := w.Write([]byte{'{'})
			if n != 1 || err != nil {
				g.fail("malformed-wire-write")
				return
			}
			if err = http.NewResponseController(w).Flush(); err != nil {
				g.fail("malformed-wire-flush")
				return
			}
			g.mu.Lock()
			g.malformedSent = true
			g.mu.Unlock()
		default:
			g.mu.Lock()
			g.otherActive++
			g.mu.Unlock()
			core.ServeHTTP(w, r)
			g.mu.Lock()
			g.otherActive--
			if r.URL.Path == selected && !strings.Contains(r.Header.Get("Accept"), "text/html") {
				g.metadataJoined++
			}
			if r.URL.Path == selected+"/comments" {
				g.commentsJoined++
			}
			g.mu.Unlock()
		}
	})
}
func ownedPortalReadJSON198(path string, limit int64, out any) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > limit {
		return errors.New("private packet shape")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errors.New("private packet bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("private packet trailing data")
	}
	return nil
}
func ownedPortalWriteJSON198(path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(body) > 4096 {
		return errors.New("private proof bound")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(body)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != len(body) {
		return io.ErrShortWrite
	}
	return nil
}

func TestOwnedSignerNativePrefixCancelWithExternalBrowserE2E(t *testing.T) {
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
	doc, parties := q.createSentV1(t)
	if len(parties) != 2 {
		t.Fatal("two genuine parties required")
	}
	party := parties[0]
	for _, candidate := range parties {
		if candidate.Role == "customer" {
			party = candidate
		}
	}
	fields, err := f.q.ListFieldsByDocument(ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		if field.RecipientID.Valid && uuid.UUID(field.RecipientID.Bytes) == party.RecipientID {
			if party.FieldID != uuid.Nil {
				t.Fatal("one actual field required")
			}
			party.FieldID = field.ID
		}
	}
	pages := int(doc.HtmlCurrentPageCount.Int32)
	if party.FieldID == uuid.Nil || !doc.HtmlCurrentPageCount.Valid || pages < 2 || pages > 12 {
		t.Fatal("genuine automatic signature binding required")
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	ownedPlainAssertDrainedV1(t, q)
	before := ownedFamilyWholeState165V1(t, q, doc.ID, f.pool)
	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal(err)
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
	gate := &ownedPortalCancelGate198{documentID: doc.ID, recipientID: party.RecipientID, fieldID: party.FieldID, expected: map[string]string{"X-Hash-Document-ID": doc.ID.String(), "X-Hash-Recipient-ID": party.RecipientID.String(), "X-Hash-PDF-SHA256": hex.EncodeToString(doc.PdfSha256), "X-Hash-PDF-Pages": strconv.Itoa(pages), "X-Hash-HTML-Source-Commitment": commitment, "X-Hash-Materialization-Revision": "1"}, pdfPrefix: make(chan struct{}), fieldsProducer: make(chan struct{}), pdfJoined: make(chan struct{}), fieldsHTTPJoined: make(chan struct{}), release: make(chan struct{}), escape: make(chan struct{})}
	gate.armed.Store(true)
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = gate.wrap(f.s.Routes(), "/sign/"+party.Token)
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(gate.escape) }) // failure cleanup cannot satisfy canceled/proof
	if until, ok := ctx.Deadline(); !ok || time.Until(until) < 155*time.Second {
		t.Fatal("original fixture reserve exhausted")
	}
	uiPath, nativePath := filepath.Join(artifacts, "ui-failed-open.json"), filepath.Join(artifacts, "native-cancel-proof.json")
	for _, path := range []string{uiPath, nativePath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("proof path must be fresh")
		}
	}
	attemptID := uuid.NewString()
	packet := map[string]any{"base": base.String(), "documentID": doc.ID, "pdfSHA256": hex.EncodeToString(doc.PdfSha256), "sourceCommitment": commitment, "pageCount": pages, "materializationRevision": 1, "rendererVersion": strings.TrimSpace(string(version)), "rendererImageID": imageID, "party": party, "attemptID": attemptID, "uiObservedPath": uiPath, "nativeProofPath": nativePath}
	raw, err := json.Marshal(packet)
	if err != nil || len(raw) > 65536 {
		t.Fatal("private input bound")
	}
	privateInput, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	n, writeErr := privateInput.Write(raw)
	closeErr := privateInput.Close()
	if writeErr != nil || closeErr != nil || n != len(raw) {
		t.Fatal("private input write")
	}
	t.Cleanup(func() { _ = os.Remove(inputPath) })
	deadline := time.Now().Add(150 * time.Second)
	wait := func(ready func() bool) {
		t.Helper()
		for !ready() {
			var terminal struct {
				Result                                    string
				AttemptID                                 string
				NativeProofBeforeClose, FreshContextReady bool
			}
			if ownedPortalReadJSON198(donePath, 1024, &terminal) == nil && terminal.AttemptID == attemptID && terminal.Result != "pass" {
				t.Fatal("external browser failed before required native proof")
			}
			gate.mu.Lock()
			failure := gate.failure
			gate.mu.Unlock()
			if failure != "" {
				t.Fatal("native fault prerequisite", failure)
			}
			if time.Now().After(deadline) {
				t.Fatal("original browser rendezvous expired")
			}
			select {
			case <-ctx.Done():
				t.Fatal("original fixture expired")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	closed := func(ch <-chan struct{}) bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
	wait(func() bool {
		gate.mu.Lock()
		defer gate.mu.Unlock()
		return closed(gate.pdfPrefix) && closed(gate.fieldsProducer) && gate.otherActive == 0 && gate.metadataJoined >= 2 && gate.commentsJoined >= 1
	})
	pendingHeld := q.runtime.SessionsV1().PendingV1()
	snapshotHeld := q.snapshotV1(t)
	if pendingHeld.ObserverSessions != 2 || pendingHeld.WorkSessions != 0 || pendingHeld.UnknownStarts != 0 || pendingHeld.SignerReaders != 1 || pendingHeld.SignerScopes != 1 || pendingHeld.HTMLAdmissions < 1 || snapshotHeld.Global.ParentBytes <= 0 || snapshotHeld.Global.DBStagingBytes <= 0 || snapshotHeld.Organisation.ParentBytes <= 0 || snapshotHeld.Organisation.DBStagingBytes <= 0 || snapshotHeld.Global.SQLSessions != 2 || snapshotHeld.Organisation.SQLSessions != 1 || snapshotHeld.GlobalGrants <= 2 || snapshotHeld.OrganisationGrants <= 1 {
		t.Fatalf("real PDF retained debt missing: pending=%+v snapshot=%+v", pendingHeld, snapshotHeld)
	}
	close(gate.release)
	var ui struct {
		Schema                                                                                                                               int
		AttemptID                                                                                                                            string
		PageOpen, ContextOpen, NoticeAcknowledged, ErrorVisible, ReadyFalse, SignDisabled, NoActionableFields, FieldsMalformed, TimerExpired bool
		MutatingRequests                                                                                                                     int
	}
	wait(func() bool { return ownedPortalReadJSON198(uiPath, 2048, &ui) == nil })
	if ui.Schema != 1 || ui.AttemptID != attemptID || !ui.PageOpen || !ui.ContextOpen || !ui.NoticeAcknowledged || !ui.ErrorVisible || !ui.ReadyFalse || !ui.SignDisabled || !ui.NoActionableFields || !ui.FieldsMalformed || ui.TimerExpired || ui.MutatingRequests != 0 {
		t.Fatal("browser failed-page-open proof differs")
	}
	joinUntil := time.Now().Add(8 * time.Second)
	for !closed(gate.pdfJoined) || !closed(gate.fieldsHTTPJoined) {
		if time.Now().After(joinUntil) {
			t.Fatal("natural native cancellation did not physically join")
		}
		time.Sleep(10 * time.Millisecond)
	}
	gate.mu.Lock()
	ok := gate.failure == "" && gate.canceled && !gate.escapeUsed && gate.prefixFlushed && gate.malformedSent && gate.pdfWrites == 1 && gate.fieldsWrites == 1 && gate.otherActive == 0
	pdfBytes, fieldsBytes := gate.nativePDFBytes, gate.nativeFieldsBytes
	gate.mu.Unlock()
	if !ok {
		t.Fatal("native cancellation witness differs")
	}
	if after := ownedFamilyWholeState165V1(t, q, doc.ID, f.pool); after != before {
		t.Fatal("failed load changed persisted state")
	}
	ownedPlainAssertDrainedV1(t, q)
	finalPending := q.runtime.SessionsV1().PendingV1()
	finalSnapshot := q.snapshotV1(t)
	proof := map[string]any{"Schema": 1, "AttemptID": attemptID, "Canceled": true, "PDFJoined": true, "FieldsJoined": true, "OtherJoined": true, "StateUnchanged": true, "ObserverOnlyDrain": true, "EscapeUsed": false, "PrefixBytes": 1024, "NativePDFBytes": pdfBytes, "NativeFieldsBytes": fieldsBytes, "PendingHeld": pendingHeld, "SnapshotHeld": snapshotHeld, "PendingAfter": finalPending, "SnapshotAfter": finalSnapshot}
	gate.armed.Store(false)
	if err := ownedPortalWriteJSON198(nativePath, proof); err != nil {
		t.Fatal(err)
	}
	var done struct {
		Result                                    string
		AttemptID                                 string
		NativeProofBeforeClose, FreshContextReady bool
	}
	wait(func() bool { return ownedPortalReadJSON198(donePath, 1024, &done) == nil })
	if done.Result != "pass" || done.AttemptID != attemptID || !done.NativeProofBeforeClose || !done.FreshContextReady {
		t.Fatal("browser recovery completion differs")
	}
	ownedPlainAssertDrainedV1(t, q)
	safe := map[string]any{"result": "pass", "scope": "Separate actual compiled SPA/native HTTPS/PG/production worker/current renderer cancellation and recovery gate; synthetic storage/parties/outbox; no full signing/provider/embeddedserver runtime or capacity acceptance.", "document_id": doc.ID, "pdf_sha256": hex.EncodeToString(doc.PdfSha256), "source_commitment": commitment, "page_count": pages, "attempt_id": attemptID, "native_proof_before_failed_context_close": true, "failed_load_state_unchanged": true, "renderer_image_id_supplied_by_root": imageID, "renderer_version": strings.TrimSpace(string(version))}
	if err := ownedPortalWriteJSON198(filepath.Join(artifacts, "backend-receipt.json"), safe); err != nil {
		t.Fatal(err)
	}
}
