//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type ownedChatRow169V1 struct {
	ID   string `json:"id"`
	Body string `json:"body"`
}

type ownedChatDone169V1 struct {
	ExitCode int                 `json:"exit_code"`
	Verified bool                `json:"verified"`
	Posted   []ownedChatRow169V1 `json:"posted"`
}

// A browser creates its exclusive private file before its single JSON write.
// Empty or incomplete first reads remain pending within the existing150s owner.
// File safety, completed invalid JSON and failed browser verdicts still refuse.
func ownedChatReadDone169V1(path string) (ownedChatDone169V1, bool, error) {
	var done ownedChatDone169V1
	raw, err := oidc439ReadDone(path)
	if os.IsNotExist(err) || errors.Is(err, io.ErrUnexpectedEOF) {
		return done, false, nil
	}
	if err != nil {
		return done, false, err
	}
	if len(raw) > 1024 {
		return done, true, os.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&done); errors.Is(err, io.ErrUnexpectedEOF) {
		return ownedChatDone169V1{}, false, nil
	}
	if err != nil || decoder.Decode(new(any)) != io.EOF || done.ExitCode != 0 || !done.Verified || len(done.Posted) != 2 {
		return done, true, os.ErrInvalid
	}
	for i, row := range done.Posted {
		id, parseErr := uuid.Parse(row.ID)
		want := "Owned browser staff message ÅÄÖ"
		if i == 1 {
			want = "Owned browser signer message ÅÄÖ"
		}
		if parseErr != nil || id == uuid.Nil || row.ID != id.String() || row.Body != want {
			return done, true, os.ErrInvalid
		}
	}
	if done.Posted[0].ID == done.Posted[1].ID {
		return done, true, os.ErrInvalid
	}
	return done, true, nil
}

// Separate chat qualification; the original all-party four-artifact oracle is untouched.
func TestOwnedCommentHistoryPortalsWithExternalBrowserE2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") == "" {
		t.Skip("set HASH_BROWSER_E2E=1 with the external owned comment-history browser runner")
	}
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Fatal("explicit owned browser runner required")
	}
	base, err := url.Parse(os.Getenv("HASH_SIGNER_PDF_BROWSER_BASE"))
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		t.Fatal("exact owned HTTPS loopback origin required")
	}
	root, inputPath, donePath, artifacts := os.Getenv("HASH_SIGNER_PDF_BROWSER_FRONTEND"), os.Getenv("HASH_SIGNER_PDF_BROWSER_INPUT"), os.Getenv("HASH_SIGNER_PDF_BROWSER_DONE"), os.Getenv("HASH_SIGNER_PDF_BROWSER_ARTIFACTS")
	for _, p := range []string{root, inputPath, donePath, artifacts} {
		if !filepath.IsAbs(p) {
			t.Fatal("absolute owned paths required")
		}
	}
	if inputPath == donePath {
		t.Fatal("fresh independent handoff paths required")
	}
	for _, p := range []string{inputPath, donePath, artifacts} {
		if _, e := os.Stat(p); !os.IsNotExist(e) {
			t.Fatal("fresh private handoff required")
		}
	}
	target, err := url.Parse(os.Getenv("HASH_E2E_RENDERER_URL"))
	if err != nil || target.Scheme != "http" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		t.Fatal("owned exact renderer origin required")
	}
	probeClient := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	probe, err := probeClient.Get(target.String() + "/version")
	if err != nil {
		t.Fatal("renderer unavailable")
	}
	version, readErr := io.ReadAll(io.LimitReader(probe.Body, 256))
	_ = probe.Body.Close()
	if readErr != nil || probe.StatusCode != http.StatusOK || strings.TrimSpace(string(version)) != "8.36.0-hash.5" {
		t.Fatal("actual renderer version differs")
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
	input.Values["scope"] = "Reviewed synthetic chat acceptance scope ÅÄÖ."
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
		t.Fatal("real two-party Send required")
	}
	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("current built SPA required")
	}
	f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(root))
	f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if info, e := os.Stat(filepath.Join(root, clean)); e == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	router := f.s.Routes()
	seeded := make([]ownedChatRow169V1, 0, 105)
	for n := 1; n <= 105; n++ {
		body := fmt.Sprintf("Owned seeded comment %03d ÅÄÖ", n)
		wire, _ := json.Marshal(createCommentInput{Body: body})
		r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/documents/"+doc.ID.String()+"/comments", bytes.NewReader(wire)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", f.s.PublicURL)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		var row ownedChatRow169V1
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &row) != nil || row.Body != body {
			t.Fatalf("native seed %d status%d", n, w.Code)
		}
		if id, e := uuid.Parse(row.ID); e != nil || id == uuid.Nil {
			t.Fatal("native seed ID missing")
		}
		seeded = append(seeded, row)
	}
	ownedPlainAssertDrainedV1(t, q)
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal("owned HTTPS listener unavailable")
	}
	// Observe genuine public requests without changing admission, dispatch,
	// policy, responses or cleanup. Snapshots are correlation, never atomic
	// refusal authority. No SQL, retry, new grant or blocking log sink is used.
	var boundaryCount atomic.Int32
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/sign/") || boundaryCount.Add(1) > 64 {
			router.ServeHTTP(w, r)
			return
		}
		route := 0
		for i, suffix := range []string{"/fields", "/pdf", "/comments", "/view"} {
			if strings.HasSuffix(r.URL.Path, suffix) {
				route = i + 1
				break
			}
		}
		before, beforeErr := q.runtime.SnapshotV1(f.org)
		beforePending := q.runtime.SessionsV1().PendingV1()
		observed := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		router.ServeHTTP(observed, r)
		after, afterErr := q.runtime.SnapshotV1(f.org)
		afterPending := q.runtime.SessionsV1().PendingV1()
		t.Logf("owned signer boundary route=%d method_get=%t status=%d runtime_matches=%t warn_enabled=%t snapshots_valid=%t before=%+v before_pending=%+v after=%+v after_pending=%+v", route, r.Method == http.MethodGet, observed.Status(), f.s.Sign.WorkRuntime.MatchesPoolV1(f.pool), slog.Default().Enabled(ctx, slog.LevelWarn), beforeErr == nil && afterErr == nil, before, beforePending, after, afterPending)
	})
	server.StartTLS()
	defer server.Close()
	if until, ok := ctx.Deadline(); !ok || time.Until(until) < 155*time.Second {
		t.Fatal("original4minute fixture lacks its150second rendezvous reserve")
	}
	actualCookie := f.s.Cookies.Cookie(SessionCookieName, cookie, time.Hour)
	if !actualCookie.HttpOnly || !actualCookie.Secure || actualCookie.SameSite != http.SameSiteStrictMode || actualCookie.Path != "/" {
		t.Fatal("production cookie security differs")
	}
	packet, err := json.Marshal(map[string]any{"base": base.String(), "documentID": doc.ID, "orgID": f.org, "ownerID": f.user.ID, "recipientID": parties[0].RecipientID, "token": parties[0].Token, "comments": seeded, "cookie": map[string]any{"name": actualCookie.Name, "value": actualCookie.Value, "httpOnly": actualCookie.HttpOnly, "secure": actualCookie.Secure, "sameSite": "Strict", "expires": actualCookie.Expires.Unix()}, "rendererImageID": os.Getenv("HASH_E2E_RENDERER_IMAGE_ID"), "rendererVersion": strings.TrimSpace(string(version))})
	if err != nil || len(packet) > 65536 {
		t.Fatal("bounded private packet failed")
	}
	file, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("fresh private input failed")
	}
	n, writeErr := file.Write(packet)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || n != len(packet) {
		t.Fatal("private input write failed")
	}
	defer os.Remove(inputPath)
	var done ownedChatDone169V1
	deadline := time.Now().Add(150 * time.Second)
	for {
		value, complete, readErr := ownedChatReadDone169V1(donePath)
		if readErr != nil {
			t.Fatal("external chat browser rejected journey")
		}
		if complete {
			done = value
			break
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			t.Fatal("bounded chat browser acceptance timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}
	rows, err := f.pool.Query(ctx, "SELECT id::text,body,author_side FROM document_comments WHERE document_id=$1 ORDER BY created_at,id", doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	actual := make([]ownedChatRow169V1, 0, 107)
	sides := make([]string, 0, 107)
	for rows.Next() {
		var row ownedChatRow169V1
		var side string
		if e := rows.Scan(&row.ID, &row.Body, &side); e != nil {
			rows.Close()
			t.Fatal(e)
		}
		actual = append(actual, row)
		sides = append(sides, side)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(actual) != 107 {
		t.Fatal("actual native history count differs", len(actual), err)
	}
	for i, row := range append(seeded, done.Posted...) {
		if actual[i] != row || (i < 106 && sides[i] != "sender") || (i == 106 && sides[i] != "signer") {
			t.Fatal("actual history identity/order/body/side differs", i)
		}
	}
	if done.Posted[0].Body != "Owned browser staff message ÅÄÖ" || done.Posted[1].Body != "Owned browser signer message ÅÄÖ" || done.Posted[0].ID == done.Posted[1].ID {
		t.Fatal("exact two native browser POSTs missing")
	}
	var events, measured, staff, public int
	err = f.pool.QueryRow(ctx, `SELECT count(*)::integer,count(*) FILTER(WHERE m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer)::integer,count(*) FILTER(WHERE e.actor_user_id=$3 AND e.recipient_id IS NULL AND e.payload_json->>'side'='sender')::integer,count(*) FILTER(WHERE e.recipient_id=$4 AND e.payload_json->>'side'='signer')::integer FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.comment_posted'`, doc.ID, f.org, f.user.ID, parties[0].RecipientID).Scan(&events, &measured, &staff, &public)
	if err != nil || events != 107 || measured != 107 || staff != 106 || public != 1 {
		t.Fatal("actual comment audit/measurement/actor counts differ", events, measured, staff, public, err)
	}
	// Current events bind the persisted comment identity, UTF8 body digest and
	// timestamp in addition to side. A legacy side-only JSON equality is not
	// the current protocol; prove every actual event/row/actor association.
	commentRows, err := f.q.ListComments(ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	commentEvents, err := f.q.ListEventsByDocumentChronological(ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if err = ownedChatCurrentAudit487V1(commentEvents, commentRows, f.org, doc.ID, f.user.ID, parties[0].RecipientID, 106, 1); err != nil {
		t.Fatal("actual current comment evidence/actor contract differs", err)
	}
	var payload []byte
	if err = f.pool.QueryRow(ctx, "SELECT payload_json FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.comment_posted' AND recipient_id=$3", doc.ID, f.org, parties[0].RecipientID).Scan(&payload); err != nil || article13.ValidateAuditPayload(payload, f.org, doc.ID, parties[0].RecipientID) != nil {
		t.Fatal("public comment lacks current notice evidence", err)
	}
	recipients, err := f.q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil || len(recipients) != 2 {
		t.Fatal("exact recipients missing")
	}
	var notifications int
	if err = f.pool.QueryRow(ctx, "SELECT count(*)::integer FROM email_deliveries WHERE subject=$1", "New comment on "+doc.Name).Scan(&notifications); err != nil || notifications != 213 {
		t.Fatal("comment outbox count differs", notifications, err)
	}
	for email, want := range map[string]int{recipients[0].Email: 106, recipients[1].Email: 106, f.user.Email: 1} {
		var n int
		if e := f.pool.QueryRow(ctx, "SELECT count(*)::integer FROM email_deliveries WHERE subject=$1 AND to_email=$2", "New comment on "+doc.Name, email).Scan(&n); e != nil || n != want {
			t.Fatal("comment recipient fanout differs", n, want, e)
		}
	}
	current, err := f.q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || !sameSignerDocumentSource(doc, current) {
		t.Fatal("browser comments altered frozen source", err)
	}
	ownedPlainAssertDrainedV1(t, q)
	var signatures int
	if err = f.pool.QueryRow(ctx, "SELECT count(*)::integer FROM signatures WHERE document_id=$1", doc.ID).Scan(&signatures); err != nil || signatures != 0 {
		t.Fatal("chat journey performed signing", err)
	}
	tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	verifier := audit.NewChainVerifier()
	params := generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 64}
	var total int
	if err = tx.QueryRow(ctx, "SELECT count(*)::integer FROM events WHERE org_id=$1", f.org).Scan(&total); err != nil {
		t.Fatal(err)
	}
	for {
		page, e := f.q.WithTx(tx).ListChainedEventsPageForOrg(ctx, params)
		if e != nil {
			t.Fatal(e)
		}
		if len(page) == 0 {
			break
		}
		verifier.VerifyPage(page)
		last := page[len(page)-1]
		params.AfterCreatedAt = last.CreatedAt
		params.AfterID = pgtype.UUID{Bytes: last.ID, Valid: true}
	}
	chain := verifier.Result()
	if !chain.OK || !chain.Complete || chain.TotalChecked != total || total < 107 {
		t.Fatal("complete real organisation chain did not verify", chain.TotalChecked, total)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	receipt, _ := json.MarshalIndent(map[string]any{"result": "pass", "scope": "Actual native template preview approval/create/review/Send,105 staff native POST seeds, current built staff+signer portals and2 actual browser POSTs. Real renderer and owned cookie session, synthetic participants/storage/key/outbox. No OIDC/SMTP/provider/payment/production/signing-completion acceptance.", "document_id": doc.ID, "comments": len(actual), "sender_comments": 106, "signer_comments": 1, "comment_events": events, "comment_measurements": measured, "comment_notifications": notifications, "current_notice_validated": true, "frozen_source_preserved": true, "native_post_effects_exact": true, "owned_session": true, "org_chain_verified": true, "org_events_checked": chain.TotalChecked, "renderer_version": strings.TrimSpace(string(version)), "renderer_image_id_supplied_by_root": os.Getenv("HASH_E2E_RENDERER_IMAGE_ID")}, "", "  ")
	if err = os.WriteFile(filepath.Join(artifacts, "backend-receipt.json"), receipt, 0600); err != nil {
		t.Fatal(err)
	}
}
