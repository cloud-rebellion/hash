//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/noticeaccess"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// A passive wrapper, never a body interceptor. Unwrap forwards real net/http
// deadline capability; the notice service must not receive fake success.
type amendment487Writer struct {
	http.ResponseWriter
	status, written int
	bodySHA         hash.Hash
}

func (w *amendment487Writer) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *amendment487Writer) WriteHeader(n int) {
	if w.status == 0 {
		w.status = n
	}
	w.ResponseWriter.WriteHeader(n)
}
func (w *amendment487Writer) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, e := w.ResponseWriter.Write(b)
	w.written += n
	if n > 0 {
		_, _ = w.bodySHA.Write(b[:n])
	}
	return n, e
}

type amendment487FileWitness struct {
	Position  int    `json:"position"`
	Sequence  int    `json:"sequence"`
	URLSHA256 string `json:"url_sha256"`
	PDFSHA256 string `json:"pdf_sha256"`
	Bytes     int    `json:"bytes"`
	Exact     bool   `json:"exact"`
}
type amendment487HTTP struct {
	mu                  sync.Mutex
	auth                *oidc439Routes
	original, candidate uuid.UUID
	mode                amendments.ModeV1
	authority           string
	counts              map[string][]int
	faults              int
	filePaths           map[string]noticeaccess.PublicFileV1
	etags               map[string]string
	previewPaths        map[string]noticeaccess.PublicFileV1
	previewRows         []amendment487FileWitness
	fileRows            []amendment487FileWitness
}

func (o *amendment487HTTP) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := &amendment487Writer{ResponseWriter: w, bodySHA: sha256.New()}
		next.ServeHTTP(v, r)
		status := v.status
		if status == 0 {
			status = 200
		}
		if r.URL.Path == "/auth/login" || r.URL.Path == "/auth/callback" || r.URL.Path == "/api/v1/me" {
			o.auth.observe(r, &oidc439StatusWriter{ResponseWriter: v, status: status})
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if f, ok := o.filePaths[r.RequestURI]; ok {
			digest := sha256.Sum256([]byte("https://" + r.Host + r.RequestURI))
			exact := r.Method == "GET" && r.TLS != nil && r.Host == o.authority && r.ContentLength == 0 && r.TransferEncoding == nil && (r.Body == nil || r.Body == http.NoBody) && status == 200 && int64(v.written) == f.PDFBytes && hex.EncodeToString(v.bodySHA.Sum(nil)) == f.PDFSHA256 && strings.TrimSpace(strings.Split(v.Header().Get("Content-Type"), ";")[0]) == "application/pdf"
			if etag := o.etags[r.RequestURI]; etag != "" {
				exact = exact && v.Header().Get("X-Hash-PDF-SHA256") == f.PDFSHA256 && len(r.Header.Values("If-Match")) == 1 && r.Header.Get("If-Match") == etag && r.Header.Get("Range") == ""
			}
			if !exact || len(o.fileRows) >= 8 {
				o.faults++
			}
			o.fileRows = append(o.fileRows, amendment487FileWitness{int(f.Position), len(o.fileRows) + 1, hex.EncodeToString(digest[:]), hex.EncodeToString(v.bodySHA.Sum(nil)), v.written, exact})
		}
		if f, ok := o.previewPaths[r.RequestURI]; ok {
			sum := hex.EncodeToString(v.bodySHA.Sum(nil))
			urlSum := sha256.Sum256([]byte("https://" + r.Host + r.RequestURI))
			exact := r.Method == "GET" && r.TLS != nil && r.Host == o.authority && r.ContentLength == 0 && r.TransferEncoding == nil && (r.Body == nil || r.Body == http.NoBody) && status == 200 && int64(v.written) == f.PDFBytes && sum == f.PDFSHA256 && strings.TrimSpace(strings.Split(v.Header().Get("Content-Type"), ";")[0]) == "application/pdf"
			if !exact || len(o.previewRows) >= 8 {
				o.faults++
			}
			o.previewRows = append(o.previewRows, amendment487FileWitness{int(f.Position), len(o.previewRows) + 1, hex.EncodeToString(urlSum[:]), sum, v.written, exact})
		}
		if r.Method == "GET" || r.Method == "HEAD" {
			return
		}
		class := ""
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/documents/"+o.original.String()+"/amendments":
			class = "link"
		case r.Method == "POST" && r.URL.Path == "/api/v1/documents/"+o.candidate.String()+"/send":
			class = "send"
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/v1/documents/"+o.original.String()+"/amendments/") && strings.HasSuffix(r.URL.Path, "/revoke"):
			class = "revoke"
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/v1/documents/"+o.original.String()+"/amendments/") && strings.HasSuffix(r.URL.Path, "/notice"):
			class = "issue"
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/v1/notices/") && strings.HasSuffix(r.URL.Path, "/access"):
			class = "exchange"
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/sign/") && strings.HasSuffix(r.URL.Path, "/view"):
			class = "view"
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/sign/") && strings.HasSuffix(r.URL.Path, "/sign"):
			class = "sign"
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/sign/") && strings.HasSuffix(r.URL.Path, "/accept"):
			class = "accept"
		default:
			o.faults++
			return
		}
		if len(o.counts[class]) >= 8 {
			o.faults++
			return
		}
		o.counts[class] = append(o.counts[class], status)
	})
}
func (o *amendment487HTTP) arm(paths map[string]noticeaccess.PublicFileV1, etags map[string]string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.filePaths) != 0 {
		panic("duplicate487 download arm")
	}
	o.filePaths = paths
	o.etags = etags
}
func amendment487Publish(t *testing.T, path string, value any) {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > 32768 {
		t.Fatal("bounded487 native handoff")
	}
	crmDocumentBrowserWriteE2E(t, path, raw)
}
func amendment487ReadDone(path string) (bool, bool, error) {
	raw, e := oidc439ReadDone(path)
	if os.IsNotExist(e) || e == io.ErrUnexpectedEOF {
		return false, false, nil
	}
	if e != nil {
		return false, false, e
	}
	var v struct {
		Schema   int  `json:"schema"`
		Exit     int  `json:"exit_code"`
		Verified bool `json:"verified"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	decodeErr := d.Decode(&v)
	if decodeErr == io.ErrUnexpectedEOF {
		return false, false, nil
	}
	if decodeErr != nil || d.Decode(new(any)) != io.EOF || v.Schema != 1 || v.Exit < 0 || v.Exit > 1 || v.Verified != (v.Exit == 0) {
		return true, false, fmt.Errorf("invalid487 done")
	}
	return true, v.Verified, nil
}

// All setup below precedes the browser and is explicitly not owner-authoring UI
// evidence. Link, Send, sign/Accept, notice issue and revoke occur only in the UI.
func TestLaterAmendmentWholeSPABrowser487E2E(t *testing.T) {
	if os.Getenv("HASH_AMENDMENT_BROWSER_E2E") != "1" {
		t.Skip("explicit487 external whole-SPA fixture required")
	}
	started := time.Now()
	mode := amendments.ModeV1(os.Getenv("HASH_AMENDMENT_BROWSER_MODE"))
	if !amendments.ValidModeV1(mode) {
		t.Fatal("one exact487 mode required")
	}
	for _, key := range []string{"HASH_E2E_DB_URL", "HASH_E2E_PDF_WORKER_PATH", "HASH_E2E_RENDERER_URL", "HASH_E2E_RENDERER_IMAGE_ID"} {
		if os.Getenv(key) == "" {
			t.Fatal("missing487 owned input", key)
		}
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(os.Getenv("HASH_E2E_RENDERER_IMAGE_ID")) {
		t.Fatal("exact487 renderer image identity required")
	}
	base := oidc439Origin(t, os.Getenv("HASH_OIDC_BROWSER_BASE"))
	issuer := oidc439Origin(t, os.Getenv("HASH_OIDC_BROWSER_ISSUER"))
	if base.Host != "127.0.0.1:8443" || issuer.Host != "127.0.0.1:8444" {
		t.Fatal("exact487 TLS origins")
	}
	frontend, input, done, artifacts := os.Getenv("HASH_OIDC_BROWSER_FRONTEND"), os.Getenv("HASH_OIDC_BROWSER_INPUT"), os.Getenv("HASH_OIDC_BROWSER_DONE"), os.Getenv("HASH_OIDC_BROWSER_ARTIFACTS")
	for _, p := range []string{frontend, input, done, artifacts} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			t.Fatal("exact487 owned paths")
		}
	}
	if input == done || filepath.Dir(input) != filepath.Dir(done) {
		t.Fatal("distinct sibling487 handoffs")
	}
	dir, e := os.Lstat(artifacts)
	if e != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 {
		t.Fatal("private487 artifacts")
	}
	for _, p := range []string{input, done, filepath.Join(artifacts, "amendment-native487.json"), filepath.Join(artifacts, "amendment-browser487.json")} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("fresh487 outputs required")
		}
	}
	files := 0
	if e := filepath.WalkDir(frontend, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return os.ErrInvalid
		}
		if !d.IsDir() {
			if !d.Type().IsRegular() {
				return os.ErrInvalid
			}
			files++
		}
		return nil
	}); e != nil || files != 153 {
		t.Fatal("exact current153-file SPA required")
	}
	shell, e := os.ReadFile(filepath.Join(frontend, "index.html"))
	if e != nil || len(shell) == 0 || len(shell) > 1<<20 {
		t.Fatal("bounded487 SPA shell")
	}
	completed := newCompletedPackageFixture248(t, false)
	q := completed.active.q
	f := q.f
	var pg, migration int
	if e := f.pool.QueryRow(f.ctx, `SELECT current_setting('server_version_num')::int,(SELECT version_id FROM (SELECT DISTINCT ON(version_id) id,version_id,is_applied FROM goose_db_version ORDER BY version_id,id DESC) x WHERE is_applied ORDER BY id DESC LIMIT 1)`).Scan(&pg, &migration); e != nil || pg != 160015 || migration != 115 {
		t.Fatal("exact PG16.15/current115 required")
	}
	deadline, ok := f.ctx.Deadline()
	if !ok || time.Until(deadline) < 10*time.Second {
		t.Fatal("original native90s deadline unavailable")
	}
	original := packageLatest223(t, q, completed.active.m.Capture.DocumentID)
	before := laterAmendmentOriginalSnapshot483(t, q, original.ID)
	senderBefore, e := f.q.GetUser(f.ctx, original.SenderID)
	if e != nil {
		t.Fatal(e)
	}
	candidate := laterAmendmentCandidate483(t, q, mode)
	if mode == amendments.AgreedNoticeV1 {
		annex := laterAmendmentCandidate483(t, q, mode)
		raw, _ := json.Marshal(map[string]any{"member_document_id": annex.ID, "expected_updated_at": candidate.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_member_updated_at": annex.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_package_id": "", "expected_generation": "0", "ordinal": 1, "title": "Reviewed DPA annex487", "category": "DPA"})
		w := submitSessionOperationE2E(f.s, "POST", "/api/v1/documents/"+candidate.ID.String()+"/attachments", string(raw), q.cookie)
		if w.Code != 201 {
			t.Fatal("native487 prepared annex selection", w.Code)
		}
		candidate = packageLatest223(t, q, candidate.ID)
	}
	peer := httptest.NewServer(laterAmendmentRetainedPeer483{base: completed.peer})
	t.Cleanup(peer.Close)
	stored, e := storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(peer.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-browser487", SecretKey: "synthetic-browser487-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if e != nil {
		t.Fatal(e)
	}
	f.s.Storage, f.s.Send.Storage, f.s.Sign.Storage = stored, stored, stored
	f.s.PublicURL, f.s.Sign.BaseURL, f.s.Send.PublicURL = base.String(), base.String(), base.String()
	f.s.PrivacyPolicyURL = base.String() + "/legal/privacy"
	target, e := url.Parse(os.Getenv("HASH_E2E_RENDERER_URL"))
	if e != nil || target.Scheme != "http" || target.Host != "hash-renderer:3000" || target.Path != "" || target.RawQuery != "" || target.Fragment != "" || target.User != nil {
		t.Fatal("exact private487 renderer")
	}
	probe, e := http.NewRequestWithContext(f.ctx, "GET", target.String()+"/version", nil)
	if e != nil {
		t.Fatal(e)
	}
	res, e := (&http.Client{Timeout: 5 * time.Second}).Do(probe)
	if e != nil {
		t.Fatal(e)
	}
	version, e := io.ReadAll(io.LimitReader(res.Body, 257))
	ce := res.Body.Close()
	if e != nil || ce != nil || res.StatusCode != 200 || strings.TrimSpace(string(version)) != "8.36.0-hash.5" {
		t.Fatal("actual487 renderer version")
	}
	f.s.Sign.PDF = render.NewGotenberg(target.String())
	f.s.ActionSecret = "synthetic-browser487-action-key"
	f.s.Sign.ActionSecret = f.s.ActionSecret
	f.s.Evidence = &evidence.Builder{Q: f.q, Storage: stored, Versions: f.s.Versions, Signer: f.s.Sign.Signer, PublicKeyPEM: f.s.Sign.Signer.PublicKeyPEM(), CertificateTrustedPublicKeys: []string{f.s.Sign.Signer.PublicKeyBase64()}, Issuer: "Controlled amendment487"}
	f.s.NoticeAccess, e = q.runtime.NewLaterAmendmentNoticeAccessV1(stored, f.s.Cookies, base.String())
	if e != nil {
		t.Fatal(e)
	}
	actor, e := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@amendment487.example.test", Name: "Invited owner487", Role: "owner"})
	if e != nil || actor == nil || actor.ID == original.SenderID || actor.ZitadelSub.Valid {
		t.Fatal("distinct unbound invited487 owner required")
	}
	basis := amendments.BasisV1{Kind: "reviewed_legacy_clause", ClauseReference: "Synthetic existing clause12", ReviewedClause: "For this controlled test only, the owner reviewed a clause permitting later signatures, explicit acknowledgement and email notice.", AllowedModes: []amendments.ModeV1{mode}, AllowedChannels: []string{}, EffectiveCondition: "Controlled fixture conditions; no legal effectiveness inferred from email."}
	if mode == amendments.AgreedNoticeV1 {
		basis.AllowedChannels = []string{"email"}
	}
	var originalPins, rawFiles []byte
	if e := f.pool.QueryRow(f.ctx, `SELECT convert_to(hash_amendment_original_pins_v1($1,$2)::text,'UTF8'),convert_to(hash_amendment_file_set_v1($3,$2)::text,'UTF8')`, original.ID, f.org, candidate.ID).Scan(&originalPins, &rawFiles); e != nil {
		t.Fatal(e)
	}
	var originalMeta map[string]any
	var fileSet amendments.FileSetV1
	if json.Unmarshal(originalPins, &originalMeta) != nil || json.Unmarshal(rawFiles, &fileSet) != nil || len(fileSet.Files) < 1 || len(fileSet.Files) > 2 {
		t.Fatal("exact487 original/proposed metadata")
	}
	expectedFiles := make([]noticeaccess.PublicFileV1, len(fileSet.Files))
	for i, v := range fileSet.Files {
		expectedFiles[i] = noticeaccess.PublicFileV1{Position: v.Position, Title: v.Title, PDFSHA256: v.SHA256, PDFBytes: v.Bytes, PDFPages: v.Pages, FileVersionSHA256: noticeaccess.FileVersionSHA256V1(v)}
	}
	basisWire := map[string]any{"kind": basis.Kind, "clause_reference": basis.ClauseReference, "reviewed_clause": basis.ReviewedClause, "allowed_modes": basis.AllowedModes, "allowed_channels": basis.AllowedChannels, "effective_condition": basis.EffectiveCondition}
	originalWire := map[string]any{"id": original.ID, "name": original.Name, "final_pdf_sha256": hex.EncodeToString(original.FinalPdfSha), "report_pdf_sha256": hex.EncodeToString(original.AuditCertSha256), "report_sha256": originalMeta["report_sha256"]}
	reviewDocuments := []map[string]any{}
	for _, v := range fileSet.Files {
		doc := packageLatest223(t, q, v.DocumentID)
		reviewDocuments = append(reviewDocuments, map[string]any{"id": doc.ID, "name": doc.Name, "pdf_sha256": v.SHA256, "pages": v.Pages})
	}
	fields, e := f.q.ListFieldsByDocument(f.ctx, candidate.ID)
	if e != nil {
		t.Fatal(e)
	}
	geometry := ownedRealBrowserFieldGeometryV1(t, fields)
	cert, roots, spki, e := oidc439TLS()
	if e != nil {
		t.Fatal(e)
	}
	provider, e := newOIDC439Provider(issuer.String(), base.String()+"/auth/callback", actor.Email)
	if e != nil {
		t.Fatal(e)
	}
	oidc439Server(t, f.ctx, issuer, cert, provider)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	f.s.OIDC, e = auth.NewOIDC(oidc.ClientContext(f.ctx, client), auth.OIDCConfig{IssuerURL: issuer.String(), ClientID: provider.clientID, RedirectURL: base.String() + "/auth/callback", Cookies: f.s.Cookies})
	if e != nil {
		t.Fatal(e)
	}
	f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(frontend))
	f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if x, e := os.Stat(filepath.Join(frontend, clean)); e == nil && !x.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(frontend, "index.html"))
	})
	previewPaths := map[string]noticeaccess.PublicFileV1{}
	for i, v := range fileSet.Files {
		previewPaths["/api/v1/documents/"+v.DocumentID.String()+"/pdf"] = expectedFiles[i]
	}
	counts := &oidc439Routes{cookies: f.s.Cookies, userID: actor.ID}
	observed := &amendment487HTTP{auth: counts, original: original.ID, candidate: candidate.ID, mode: mode, authority: base.Host, previewPaths: previewPaths, counts: map[string][]int{}, filePaths: map[string]noticeaccess.PublicFileV1{}, etags: map[string]string{}}
	routes := observed.wrap(f.s.Routes())
	oidc439Server(t, f.ctx, base, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routes.ServeHTTP(w, r.WithContext(oidc.ClientContext(r.Context(), client)))
	}))
	paths := []string{input, done}
	for _, name := range []string{"amendment-linked487.json", "amendment-public487.json", "amendment-terminal487.json"} {
		p := filepath.Join(filepath.Dir(input), name)
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("fresh487 phase handoff required")
		}
		paths = append(paths, p)
	}
	defer func() {
		for _, p := range paths {
			_ = os.Remove(p)
		}
	}()
	amendment487Publish(t, input, map[string]any{"schema": 1, "source": "hash-amendment-browser487", "base": base.String(), "issuer": issuer.String(), "leaf_spki_sha256": spki, "mode": mode, "org_id": f.org, "user_id": actor.ID, "original_sender_id": original.SenderID, "email": actor.Email, "name": actor.Name, "role": actor.Role, "session_generation": actor.SessionGeneration, "native_deadline_unix_ms": deadline.UnixMilli(), "original": originalWire, "candidate": map[string]any{"id": candidate.ID, "name": candidate.Name, "updated_at": candidate.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "pdf_sha256": hex.EncodeToString(candidate.PdfSha256), "pages": fileSet.Files[0].Pages, "requires_signature": candidate.RequiresSignature}, "basis": basisWire, "files": expectedFiles, "review_documents": reviewDocuments, "field_geometry": geometry, "notice": map[string]any{"subject": "Controlled exact amendment notice487", "text": "Review the exact later files. No signature or acknowledgement is requested by this notice.", "recipient_email": "legal487@example.test"}})
	var relation amendments.RecordV1
	linked, published, terminal := false, false, false
	var notice amendments.NoticeV1
	var recipientID uuid.UUID
	invitationToken := ""
	terminalArtifacts := []packageBrowserArtifact403{}
	for f.ctx.Err() == nil {
		if complete, success, e := amendment487ReadDone(done); e != nil {
			t.Fatal(e)
		} else if complete {
			if !success || !linked || !terminal {
				t.Fatal("browser487 rejected or preceded native terminal")
			}
			break
		}
		if !linked {
			var id uuid.UUID
			e := f.pool.QueryRow(f.ctx, `SELECT id FROM document_amendments_v1 WHERE org_id=$1 AND original_document_id=$2 AND document_id=$3`, f.org, original.ID, candidate.ID).Scan(&id)
			if e == nil {
				relation, e = amendment487ReadRelation(t, q, original.ID, candidate.ID, id)
				if e != nil || relation.CreatedBy != actor.ID || relation.Mode != mode || relation.Revision != "1" || relation.PredecessorID != nil || relation.RequestID == uuid.Nil {
					t.Fatal("actual UI487 link tuple")
				}
				if laterAmendmentOriginalSnapshot483(t, q, original.ID) != before {
					t.Fatal("UI487 link changed original")
				}
				amendment487Publish(t, paths[2], map[string]any{"schema": 1, "source": "hash-amendment-linked487", "amendment": relation})
				linked = true
			} else if e != pgx.ErrNoRows {
				t.Fatal(e)
			}
		}
		if linked && !published {
			if mode == amendments.AgreedNoticeV1 {
				var id uuid.UUID
				e := f.pool.QueryRow(f.ctx, `SELECT id FROM document_amendment_notices_v1 WHERE org_id=$1 AND amendment_id=$2`, f.org, relation.ID).Scan(&id)
				if e == nil {
					freshRelation, readError := amendment487ReadRelation(t, q, original.ID, candidate.ID, relation.ID)
					if readError != nil || freshRelation.Mode != amendments.AgreedNoticeV1 || freshRelation.Notice == nil || freshRelation.Notice.ID != id {
						t.Fatal("fresh487 authenticated notice relation")
					}
					notice = *freshRelation.Notice
					if len(notice.Deliveries) != 1 || notice.Deliveries[0].RecipientEmail != "legal487@example.test" || notice.FileCommitmentSHA256 != relation.FileCommitmentSHA256 || len(notice.VerifiedReceipts) != 0 {
						t.Fatal("actual UI487 notice/outbox tuple")
					}
					var body string
					if e := f.pool.QueryRow(f.ctx, `SELECT text_body FROM email_deliveries WHERE id=$1`, notice.Deliveries[0].EmailDeliveryID).Scan(&body); e != nil {
						t.Fatal(e)
					}
					entry := ""
					for _, part := range strings.Fields(body) {
						u, e := url.Parse(part)
						if e == nil && u.Scheme == "https" && u.Host == base.Host && u.Path == "/notice/"+notice.ID.String() && strings.HasPrefix(u.Fragment, "access=") {
							if _, e := noticeaccess.TokenDigestV1(strings.TrimPrefix(u.Fragment, "access=")); e == nil {
								entry = u.String()
							}
						}
					}
					if entry == "" {
						t.Fatal("actual487 private notice email entrypoint")
					}
					selected := map[string]noticeaccess.PublicFileV1{}
					etags := map[string]string{}
					for _, v := range expectedFiles {
						path := "/api/v1/notices/" + notice.ID.String() + "/files/" + strconv.Itoa(int(v.Position))
						selected[path] = v
						etags[path] = noticeaccess.ExpectedFileETagV1(relation.FileCommitmentSHA256, v.PDFSHA256)
					}
					observed.arm(selected, etags)
					amendment487Publish(t, paths[3], map[string]any{"schema": 1, "source": "hash-amendment-notice487", "notice_id": notice.ID, "entrypoint": entry, "file_commitment_sha256": relation.FileCommitmentSHA256, "files": expectedFiles, "access_id": notice.Deliveries[0].AccessID})
					published = true
					terminal = true
				} else if e != pgx.ErrNoRows {
					t.Fatal(e)
				}
			} else {
				current := packageLatest223(t, q, candidate.ID)
				if current.Status == "sent" {
					parties, e := f.q.ListRecipientsByDocument(f.ctx, candidate.ID)
					if e != nil || len(parties) != 1 {
						t.Fatal("one actual487 recipient")
					}
					party := parties[0]
					recipientID = party.ID
					var body string
					if e := f.pool.QueryRow(f.ctx, `SELECT text_body FROM email_deliveries WHERE to_email=$1 AND status='pending' AND strpos(text_body,'/sign/')>0`, party.Email).Scan(&body); e != nil {
						t.Fatal(e)
					}
					matches := regexp.MustCompile(`/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`).FindAllStringSubmatch(body, -1)
					if len(matches) != 1 {
						t.Fatal("unique actual487 invitation")
					}
					invitationToken = matches[0][1]
					if invitationToken == completed.token || invitationToken == completed.active.token {
						t.Fatal("487 original credential reused")
					}
					rr := q.requestV1(invitationToken, "")
					var sc signerContextResponse
					if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &sc) != nil || sc.AmendmentContext == nil || sc.AmendmentContext.AmendmentID != relation.ID || sc.AmendmentContext.Mode != mode {
						t.Fatal("native487 retained signer disclosure")
					}
					if e := q.reconcileV1ForBrowser487(t); e != nil {
						t.Fatal(e)
					}
					amendment487Publish(t, paths[3], map[string]any{"schema": 1, "source": "hash-amendment-invitation487", "token": invitationToken, "recipient_id": party.ID, "name": party.Name, "notice_digest": sc.Privacy.NoticeDigest, "amendment_context": sc.AmendmentContext, "pdf_sha256": hex.EncodeToString(current.PdfSha256), "pages": fileSet.Files[0].Pages, "fields": geometry})
					published = true
				}
			}
		}
		if published && !terminal && mode != amendments.AgreedNoticeV1 {
			current := packageLatest223(t, q, candidate.ID)
			if current.Status == "completed" {
				terminalArtifacts = amendment487Terminal(t, q, candidate, current, mode, recipientID, completed.peer)
				var body string
				if e := f.pool.QueryRow(f.ctx, `SELECT e.text_body FROM document_participant_report_deliveries_v1 r JOIN email_deliveries e ON e.id=r.email_delivery_id WHERE r.document_id=$1 AND r.org_id=$2 AND r.audience='recipient' AND r.recipient_id=$3 AND r.message_sha256=hash_package_send_message_sha256_v1(e.id)`, candidate.ID, f.org, recipientID).Scan(&body); e != nil {
					t.Fatal(e)
				}
				m := regexp.MustCompile(`/completed/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`).FindAllStringSubmatch(body, -1)
				if len(m) != 1 || m[0][1] == invitationToken {
					t.Fatal("actual487 rotated completion link")
				}
				token := m[0][1]
				selected := map[string]noticeaccess.PublicFileV1{}
				for i, a := range terminalArtifacts[:2] {
					suffix := "/final-pdf"
					if i == 1 {
						suffix = "/audit-cert"
					}
					selected["/sign/"+token+suffix] = noticeaccess.PublicFileV1{Position: int16(i), PDFSHA256: a.SHA256, PDFBytes: a.Bytes}
				}
				observed.arm(selected, map[string]string{})
				amendment487Publish(t, paths[4], map[string]any{"schema": 1, "source": "hash-amendment-terminal487", "token": token, "artifacts": terminalArtifacts})
				terminal = true
			}
		}
		select {
		case <-f.ctx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	if f.ctx.Err() != nil {
		t.Fatal("original487 native90s deadline exhausted")
	}
	if laterAmendmentOriginalSnapshot483(t, q, original.ID) != before {
		t.Fatal("whole487 journey changed immutable original")
	}
	member, e := f.q.GetUser(f.ctx, actor.ID)
	if e != nil || member.Role != "owner" || !member.ZitadelSub.Valid || member.ZitadelSub.String != provider.subject || member.SessionGeneration != actor.SessionGeneration {
		t.Fatal("actual487 owner identity")
	}
	senderAfter, e := f.q.GetUser(f.ctx, original.SenderID)
	if e != nil || !reflect.DeepEqual(senderBefore, senderAfter) {
		t.Fatal("487 unrelated original sender changed")
	}
	amendment487Alert(t, q, relation.ID, notice.ID, original.SenderID, actor.ID, mode)
	observed.mu.Lock()
	faults := observed.faults
	countsCopy := map[string][]int{}
	for k, v := range observed.counts {
		countsCopy[k] = append([]int(nil), v...)
	}
	witnesses := append([]amendment487FileWitness(nil), observed.fileRows...)
	previews := append([]amendment487FileWitness(nil), observed.previewRows...)
	observed.mu.Unlock()
	wanted := map[string][]int{"link": {201}}
	if mode == amendments.AgreedNoticeV1 {
		wanted["issue"] = []int{201}
		wanted["exchange"] = []int{200}
		wanted["revoke"] = []int{200}
		if len(witnesses) != 4 {
			t.Fatal("487 two exact notice files each read+download")
		}
		var revoked bool
		if e := f.pool.QueryRow(f.ctx, `SELECT revoked_at IS NOT NULL FROM document_amendment_notice_access_v1 WHERE id=$1`, notice.Deliveries[0].AccessID).Scan(&revoked); e != nil || !revoked {
			t.Fatal("real487 owner revocation")
		}
		freshRelation, e := amendment487ReadRelation(t, q, original.ID, candidate.ID, relation.ID)
		freshNotice := freshRelation.Notice
		if e != nil || freshRelation.Mode != amendments.AgreedNoticeV1 || freshNotice == nil || freshNotice.ID != notice.ID || freshNotice.RequestID != notice.RequestID || freshNotice.FileCommitmentSHA256 != relation.FileCommitmentSHA256 || len(freshNotice.VerifiedReceipts) != 0 || len(freshNotice.Deliveries) != 1 || freshNotice.Deliveries[0].EmailDeliveryID != notice.Deliveries[0].EmailDeliveryID || freshNotice.Deliveries[0].AccessID != notice.Deliveries[0].AccessID || freshNotice.Deliveries[0].RecipientEmail != "legal487@example.test" || freshNotice.Deliveries[0].State != "queued" || freshNotice.Deliveries[0].RevokedAt == nil {
			t.Fatal("fresh487 notice progress/receipt invariants")
		}
		var signatures, reports int
		if e := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM signatures WHERE document_id=$1),(SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$1)`, candidate.ID).Scan(&signatures, &reports); e != nil || signatures != 0 || reports != 0 || packageLatest223(t, q, candidate.ID).Status != "draft" {
			t.Fatal("487 notice created response/effect state")
		}
	} else {
		wanted["send"] = []int{200}
		wanted["view"] = []int{200}
		kind := "sign"
		if mode == amendments.AcknowledgementV1 {
			kind = "accept"
		}
		wanted[kind] = []int{200}
		if len(witnesses) != 2 {
			t.Fatal("487 final/report actual download witnesses")
		}
	}
	if faults != 0 || !reflect.DeepEqual(countsCopy, wanted) {
		t.Fatal("487 actual mutation scope differs", faults, countsCopy)
	}
	for _, v := range witnesses {
		if !v.Exact {
			t.Fatal("487 actual HTTP/download mismatch")
		}
	}
	seenPreview := map[int]bool{}
	for _, v := range previews {
		if !v.Exact {
			t.Fatal("487 exact actual staff preview mismatch")
		}
		seenPreview[v.Position] = true
	}
	if len(seenPreview) != len(expectedFiles) {
		t.Fatal("487 owner did not read every proposed exact PDF")
	}
	authCounts := counts.snapshot()
	issuedGenerations := counts.sessionGenerations()
	if authCounts["login"] != 1 || authCounts["callback"] != 1 || authCounts["login_cookie_sets"] != 1 || authCounts["session_cookie_sets"] != 1 || authCounts["callback_handshake_clears"] != 1 || authCounts["faults"] != 0 || authCounts["logout"] != 0 || authCounts["create"] != 0 || authCounts["me_ok"] < 1 || authCounts["me_denied"] < 1 || !reflect.DeepEqual(issuedGenerations, []int64{actor.SessionGeneration}) {
		// Failure-only fixed scalar projection. Never serialize the route observer,
		// cookies, requests, URLs, provider state or signed session material.
		diagnostic := struct {
			Schema int `json:"schema"`
			Counts struct {
				Login          int `json:"login"`
				Callback       int `json:"callback"`
				Logout         int `json:"logout"`
				Create         int `json:"create"`
				MeOK           int `json:"me_ok"`
				MeDenied       int `json:"me_denied"`
				LoginCookies   int `json:"login_cookie_sets"`
				SessionCookies int `json:"session_cookie_sets"`
				CallbackClears int `json:"callback_handshake_clears"`
				LogoutClears   int `json:"logout_cookie_clears"`
				Faults         int `json:"faults"`
			} `json:"auth_counts"`
			IssuedGenerations  []int64 `json:"issued_generations"`
			ExpectedGeneration int64   `json:"expected_generation"`
		}{Schema: 1, IssuedGenerations: issuedGenerations, ExpectedGeneration: actor.SessionGeneration}
		diagnostic.Counts.Login = authCounts["login"]
		diagnostic.Counts.Callback = authCounts["callback"]
		diagnostic.Counts.Logout = authCounts["logout"]
		diagnostic.Counts.Create = authCounts["create"]
		diagnostic.Counts.MeOK = authCounts["me_ok"]
		diagnostic.Counts.MeDenied = authCounts["me_denied"]
		diagnostic.Counts.LoginCookies = authCounts["login_cookie_sets"]
		diagnostic.Counts.SessionCookies = authCounts["session_cookie_sets"]
		diagnostic.Counts.CallbackClears = authCounts["callback_handshake_clears"]
		diagnostic.Counts.LogoutClears = authCounts["logout_cookie_clears"]
		diagnostic.Counts.Faults = authCounts["faults"]
		raw, marshalErr := json.Marshal(diagnostic)
		if marshalErr != nil || len(raw) > 2048 {
			t.Fatal("487 actual native cookie/session authority; bounded diagnostic unavailable")
		}
		t.Fatalf("487 actual native cookie/session authority: %s", raw)
	}
	providerCounts := provider.snapshot()
	if providerCounts.Authorize != 1 || providerCounts.Accept != 1 || providerCounts.Token != 1 || providerCounts.Faults != 0 || providerCounts.PendingCodes != 0 || providerCounts.PendingTickets != 0 {
		t.Fatal("one genuine487 OIDC flow")
	}
	q.reconcileV1(t)
	q.assertObserversOnlyV1(t)
	amendment487Publish(t, filepath.Join(artifacts, "amendment-native487.json"), map[string]any{"schema": 1, "source": "hash-amendment-native487", "passed": true, "mode": mode, "org_id": f.org, "user_id": actor.ID, "original_sender_id": original.SenderID, "original_document_id": original.ID, "candidate_document_id": candidate.ID, "amendment_id": relation.ID, "request_id": relation.RequestID, "original_immutable": true, "owner_distinct_from_original_sender": true, "separate_owner_alerts_queued": true, "mutation_statuses": countsCopy, "download_witnesses": witnesses, "preview_witnesses": previews, "auth_counts": authCounts, "terminal_artifacts": terminalArtifacts, "pg_version": pg, "migration_version": migration, "spa_assets": files, "duration_ms": time.Since(started).Milliseconds(), "renderer_version": strings.TrimSpace(string(version)), "runtime_drained": true, "scope": "Actual wholeSPA/HTTPS/OIDC/nativePG/UI mode/file observations; controlled original setup/OIDC/storage/malware/entitlement/outbox; no configuredSMTP/provider/legal/capacity/release acceptance"})
}

// Read the normal authenticated staff inventory after the browser action. This
// passive fixture observation never links, issues, sends or changes a document.
// Every invocation reads afresh and selects only this exact original/head tuple.
func amendment487ReadRelation(t *testing.T, q *ownedPublicReadFixtureV1, original, candidate, id uuid.UUID) (amendments.RecordV1, error) {
	t.Helper()
	if original == uuid.Nil || candidate == uuid.Nil || id == uuid.Nil {
		return amendments.RecordV1{}, fmt.Errorf("invalid487 amendment observation identity")
	}
	w := submitSessionOperationContextE2E(q.f.ctx, q.f.s, http.MethodGet, "/api/v1/documents/"+original.String()+"/amendments", "", q.cookie)
	q.reconcileV1(t)
	if w.Code != http.StatusOK || w.Body.Len() == 0 || w.Body.Len() > 512<<10 {
		return amendments.RecordV1{}, fmt.Errorf("fresh487 authenticated amendment inventory unavailable")
	}
	var inventory amendments.InventoryV1
	decoder := json.NewDecoder(bytes.NewReader(w.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&inventory) != nil || decoder.Decode(new(any)) != io.EOF || inventory.Schema != amendments.SchemaV1 || inventory.OriginalDocumentID != original || inventory.Original.DocumentID != original || inventory.HeadID == nil || *inventory.HeadID != id || len(inventory.Amendments) != 1 {
		return amendments.RecordV1{}, fmt.Errorf("fresh487 authenticated amendment inventory")
	}
	relation := inventory.Amendments[0]
	if relation.ID != id || relation.DocumentID != candidate || relation.Revision != "1" || relation.PredecessorID != nil || inventory.HeadRevision != relation.Revision {
		return amendments.RecordV1{}, fmt.Errorf("fresh487 exact amendment relation")
	}
	return relation, nil
}

// Reconcile current normal native consumers; no alternate client or grant.
func (q *ownedPublicReadFixtureV1) reconcileV1ForBrowser487(t *testing.T) error {
	q.reconcileV1(t)
	return q.f.ctx.Err()
}
func amendment487Alert(t *testing.T, q *ownedPublicReadFixtureV1, relation, notice, sender, actor uuid.UUID, mode amendments.ModeV1) {
	t.Helper()
	if sender == actor {
		t.Fatal("487 wrong owner-alert test setup")
	}
	var n int
	e := q.f.pool.QueryRow(q.f.ctx, `SELECT count(*) FROM document_amendments_v1 a JOIN users u ON u.id=a.owner_alert_user_id AND u.org_id=a.org_id JOIN email_deliveries e ON e.id=a.owner_alert_email_delivery_id WHERE a.id=$1 AND a.owner_alert_user_id=$2 AND e.to_email=u.email AND a.owner_alert_message_sha256=hash_package_send_message_sha256_v1(e.id) AND e.status='pending'`, relation, sender).Scan(&n)
	if e != nil || n != 1 {
		t.Fatal("actual487 separate link owner alert")
	}
	if mode == amendments.AgreedNoticeV1 {
		e = q.f.pool.QueryRow(q.f.ctx, `SELECT count(*) FROM document_amendment_notices_v1 a JOIN users u ON u.id=a.owner_alert_user_id AND u.org_id=a.org_id JOIN email_deliveries e ON e.id=a.owner_alert_email_delivery_id WHERE a.id=$1 AND a.owner_alert_user_id=$2 AND e.to_email=u.email AND a.owner_alert_message_sha256=hash_package_send_message_sha256_v1(e.id) AND e.status='pending'`, notice, sender).Scan(&n)
		if e != nil || n != 1 {
			t.Fatal("actual487 separate issue owner alert")
		}
	}
}
func amendment487Terminal(t *testing.T, q *ownedPublicReadFixtureV1, prior, current *generated.Document, mode amendments.ModeV1, recipient uuid.UUID, strict *completedPackagePeer248) []packageBrowserArtifact403 {
	t.Helper()
	if current.Status != "completed" || !current.CompletionEffectiveAt.Valid || current.PdfStorageKey != prior.PdfStorageKey || current.PdfStorageVersionID != prior.PdfStorageVersionID || !bytes.Equal(current.PdfSha256, prior.PdfSha256) {
		t.Fatal("487 fresh completion source changed")
	}
	var reports, deliveries, signatures, accepted int
	if e := q.f.pool.QueryRow(q.f.ctx, `SELECT (SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$1 AND completion_effective_at=$2),(SELECT count(*) FROM document_participant_report_deliveries_v1 WHERE document_id=$1),(SELECT count(*) FROM signatures WHERE document_id=$1),(SELECT count(*) FROM recipients WHERE document_id=$1 AND status='accepted')`, current.ID, current.CompletionEffectiveAt).Scan(&reports, &deliveries, &signatures, &accepted); e != nil || reports != 1 || deliveries != 2 || (mode == amendments.SignatureV1 && (signatures != 1 || accepted != 0)) || (mode == amendments.AcknowledgementV1 && (signatures != 0 || accepted != 1)) {
		t.Fatal("487 distinct response/report cardinalities")
	}
	payload, e := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, current.AuditPayloadKey.String, current.AuditPayloadSha256, current.AuditPayloadVersionID)
	if e != nil {
		t.Fatal(e)
	}
	detached, e := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, current.AuditSignatureKey.String, current.AuditSignatureSha256, current.AuditSignatureVersionID)
	if e != nil || !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(detached)) {
		t.Fatal("487 actual signed evidence")
	}
	claims, e := evidence.ParseCertificateCommitments(payload)
	if e != nil || claims.DocumentID != current.ID.String() || claims.FinalPDFSHA256 != hex.EncodeToString(current.FinalPdfSha) {
		t.Fatal("487 current evidence commitments")
	}
	_ = assertFreshParticipantReport406(t, q.f, current, payload)
	out := []packageBrowserArtifact403{}
	for _, a := range []struct {
		name, key string
		sum       []byte
		version   pgtype.Text
	}{{"final-pdf", current.FinalPdfKey.String, current.FinalPdfSha, current.FinalPdfVersionID}, {"evidence-report", current.AuditCertKey.String, current.AuditCertSha256, current.AuditCertVersionID}, {"signed-report-payload", current.AuditPayloadKey.String, current.AuditPayloadSha256, current.AuditPayloadVersionID}, {"detached-report-signature", current.AuditSignatureKey.String, current.AuditSignatureSha256, current.AuditSignatureVersionID}} {
		raw, e := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, a.key, a.sum, a.version)
		sum := sha256.Sum256(raw)
		strict.mu.Lock()
		until := strict.until[a.key]
		strict.mu.Unlock()
		if e != nil || len(raw) == 0 || !bytes.Equal(sum[:], a.sum) || !current.FinalizationRetainUntil.Valid || until.Before(current.FinalizationRetainUntil.Time) {
			t.Fatal("487 exact retained terminal bytes")
		}
		out = append(out, packageBrowserArtifact403{Name: a.name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(raw))})
	}
	events, e := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: current.ID, Valid: true}, Limit: 1000})
	if e != nil || len(events) >= 1000 {
		t.Fatal("487 original event history")
	}
	for _, ev := range events {
		sum, e := audit.RecomputeEventRowHash(ev)
		if e != nil || !bytes.Equal(sum, ev.RowHash) {
			t.Fatal("487 immutable event preimage")
		}
	}
	return out
}
