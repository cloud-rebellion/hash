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
	"hash"
	"io"
	"maps"
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

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This fixture serves only current built settings and ordinary Server.Routes.
// It has no control endpoint, renderer, PDF worker, CRM, storage or SMTP peer.
// The template approval is synthetic setup, not a browser template approval.
// Real signed cookies, PostgreSQL, font HTTP bytes, registry consent, immutable
// revisions, original-actor outcomes and audit lineage are mandatory.
type presignRegistryBrowserDispatchE2E struct {
	Method    string                  `json:"method"`
	Path      string                  `json:"path"`
	Status    int                     `json:"status"`
	ActorID   uuid.UUID               `json:"actor_id"`
	Operation string                  `json:"operation"`
	RequestID uuid.UUID               `json:"request_id"`
	Outcome   presignregistry.Outcome `json:"outcome"`
	workflow  *presignregistry.WorkflowIntent
	grant     *presignregistry.GrantIntent
	resource  *presignregistry.ResourceMutationInput
}

type presignRegistryBrowserFontE2E struct {
	Font   string `json:"font"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type presignRegistryBrowserCaptureE2E struct {
	http.ResponseWriter
	status int
	bytes  int
	digest hash.Hash
	body   bytes.Buffer
	json   bool
}

func (w *presignRegistryBrowserCaptureE2E) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *presignRegistryBrowserCaptureE2E) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.bytes += len(body)
	if w.digest != nil {
		_, _ = w.digest.Write(body)
	}
	if w.json && w.body.Len()+len(body) <= 8192 {
		_, _ = w.body.Write(body)
	}
	return w.ResponseWriter.Write(body)
}

func presignRegistryBrowserCanonicalE2E(t *testing.T, value any) []byte {
	t.Helper()
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		t.Fatal("encode registry proof")
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}

func presignRegistryBrowserCommandE2E(t *testing.T, operation string, value any) string {
	t.Helper()
	sum := sha256.Sum256(append([]byte("hash:presign-command:v1:"+operation+"\x00"), presignRegistryBrowserCanonicalE2E(t, value)...))
	return hex.EncodeToString(sum[:])
}

func TestPresignRegistrySettingsWithExternalBrowserE2E(t *testing.T) {
	if os.Getenv("HASH_PRESIGN_REGISTRY_BROWSER_E2E") != "1" {
		t.Skip("explicit built registry browser fixture required")
	}
	if os.Getenv("HASH_E2E_DB_URL") == "" {
		t.Fatal("selected registry browser requires actual PostgreSQL")
	}
	base, err := url.Parse(os.Getenv("HASH_PRESIGN_REGISTRY_BROWSER_BASE"))
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() != "43192" || base.Path != "" || base.RawPath != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		t.Fatal("registry browser requires exact HTTPS loopback origin")
	}
	frontend, inputPath, donePath, artifacts := os.Getenv("HASH_PRESIGN_REGISTRY_BROWSER_FRONTEND"), os.Getenv("HASH_PRESIGN_REGISTRY_BROWSER_INPUT"), os.Getenv("HASH_PRESIGN_REGISTRY_BROWSER_DONE"), os.Getenv("HASH_PRESIGN_REGISTRY_BROWSER_ARTIFACTS")
	for _, path := range []string{frontend, inputPath, donePath, artifacts} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatal("registry browser requires absolute canonical task paths")
		}
	}
	if inputPath == donePath {
		t.Fatal("registry handoff and completion paths must differ")
	}
	for _, path := range []string{inputPath, donePath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("registry handoff paths must be fresh")
		}
	}
	if info, err := os.Lstat(artifacts); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("registry artifacts require existing private directory")
	}
	// Only the unique database created here is disposed; no immutable evidence
	// trigger is disabled and no parent database is truncated.
	_ = isolateHTMLTemplateDatabaseE2E(t)
	ctx, pool, q, s, orgID, ownerID := setupDSRE2E(t)
	ctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()
	s.Environment, s.PublicURL = "development", base.String()
	owner, err := q.GetUser(ctx, ownerID)
	if err != nil {
		t.Fatal("read original owner")
	}
	newMember := func(org uuid.UUID, name, role string) *generated.User {
		t.Helper()
		user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org, Name: name, Role: role, Email: "registry-" + uuid.NewString() + "@example.test", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
		if err != nil {
			t.Fatal("seed isolated registry member")
		}
		return user
	}
	sender := newMember(orgID, "Synthetic Named Sender", "sender")
	viewer := newMember(orgID, "Synthetic Readonly Member", "viewer")
	foreignOrg, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Synthetic foreign registry", Plan: "pro"})
	if err != nil {
		t.Fatal("seed foreign registry organization")
	}
	foreign := newMember(foreignOrg.ID, "Synthetic Foreign Sender", "sender")
	cookie := func(user *generated.User) string {
		return dsrSessionCookieE2E(t, s, user.ID, user.SessionGeneration, time.Hour)
	}
	ownerCookie, senderCookie, viewerCookie, foreignCookie := cookie(owner), cookie(sender), cookie(viewer), cookie(foreign)
	identities := map[string]uuid.UUID{ownerCookie: owner.ID, senderCookie: sender.ID, viewerCookie: viewer.ID, foreignCookie: foreign.ID}

	input, _, _ := testfixture.HTMLContract(t)
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal("decode approved registry design")
	}
	master.SchemaVersion, master.SigningPage = 3, testfixture.BrandedSigningPolicy()
	master.Sections = []htmlmaster.Section{{Name: "manual_scope", DefaultText: "Approved reviewed registry scope", MaxChars: 1000}}
	master.HTML += `<p data-hash-section="manual_scope"></p>`
	input.Values["provider_name"], input.Values["provider_email"] = sender.Name, sender.Email
	rawMaster, _ := json.Marshal(master)
	rawDefaults, _ := json.Marshal(input.Values)
	canonicalTemplate, err := htmlmaster.CanonicalTemplate(rawMaster, rawDefaults)
	if err != nil {
		t.Fatal("validate exact source3 catalog design")
	}
	templateID := uuid.New()
	templateName, workflowName := "Synthetic registry contract ÅÄÖ", "Reviewed named provider workflow"
	approvedAt := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	templateSHA, _ := hex.DecodeString(canonicalTemplate.SHA256)
	if _, err := pool.Exec(ctx, `INSERT INTO templates(id,org_id,name,source_kind,html_master_json,variables_json,created_by,html_content_sha256) VALUES($1,$2,$3,'html',$4::jsonb,$5::jsonb,$6,$7)`, templateID, orgID, templateName, canonicalTemplate.MasterJSON, canonicalTemplate.DefaultsJSON, ownerID, templateSHA); err != nil {
		t.Fatal("seed approved registry design head")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO html_template_revisions(template_id,version,org_id,html_master_json,variables_json,content_sha256,created_by,approved_by,approved_at) VALUES($1,1,$2,$3::jsonb,$4::jsonb,$5,$6,$6,$7)`, templateID, orgID, canonicalTemplate.MasterJSON, canonicalTemplate.DefaultsJSON, templateSHA, ownerID, approvedAt); err != nil {
		t.Fatal("seed selected immutable catalog approval")
	}
	shell, err := os.ReadFile(filepath.Join(frontend, "index.html"))
	if err != nil || len(shell) == 0 {
		t.Fatal("accepted built frontend unavailable")
	}
	s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(frontend))
	s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join(frontend, filepath.Clean("/"+r.URL.Path))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(frontend, "index.html"))
	})
	router := s.Routes()
	var mu sync.Mutex
	dispatches := []presignRegistryBrowserDispatchE2E{}
	fonts := []presignRegistryBrowserFontE2E{}
	recoveries := []int{}
	failures := []string{}
	forbiddenDispatches := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/presign/") && !strings.HasSuffix(r.URL.Path, "/preview")
		fontRead := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/presign/fonts/")
		recovery := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/presign/requests/")
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !strings.HasPrefix(r.URL.Path, "/api/v1/presign/") {
			mu.Lock()
			forbiddenDispatches++
			mu.Unlock()
		}
		tracked := presignRegistryBrowserDispatchE2E{Method: r.Method, Path: r.URL.Path}
		if c, err := r.Cookie(SessionCookieName); err == nil {
			tracked.ActorID = identities[c.Value]
		}
		var raw []byte
		if write {
			var readErr error
			raw, readErr = io.ReadAll(io.LimitReader(r.Body, 512*1024+1))
			_ = r.Body.Close()
			if readErr != nil || len(raw) > 512*1024 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		captured := &presignRegistryBrowserCaptureE2E{ResponseWriter: w, json: write}
		if fontRead {
			captured.digest = sha256.New()
		}
		router.ServeHTTP(captured, r)
		mu.Lock()
		defer mu.Unlock()
		if recovery {
			recoveries = append(recoveries, captured.status)
		}
		if fontRead && captured.status == 200 {
			font := strings.TrimPrefix(r.URL.Path, "/api/v1/presign/fonts/")
			fonts = append(fonts, presignRegistryBrowserFontE2E{Font: font, SHA256: hex.EncodeToString(captured.digest.Sum(nil)), Bytes: captured.bytes})
		}
		if !write {
			return
		}
		tracked.Status = captured.status
		var decodeErr error
		switch {
		case r.URL.Path == "/api/v1/presign/workflows/approve":
			var in presignregistry.ConfirmWorkflowInput
			decodeErr = json.Unmarshal(raw, &in)
			tracked.Operation, tracked.RequestID, tracked.workflow = presignregistry.OperationApproveWorkflow, in.Intent.RequestID, &in.Intent
		case r.URL.Path == "/api/v1/presign/self-grants/create" || strings.HasSuffix(r.URL.Path, "/revise"):
			var in presignregistry.ConfirmGrantInput
			decodeErr = json.Unmarshal(raw, &in)
			tracked.Operation = presignregistry.OperationCreateGrant
			if strings.HasSuffix(r.URL.Path, "/revise") {
				tracked.Operation = presignregistry.OperationReviseGrant
			}
			tracked.RequestID, tracked.grant = in.Intent.RequestID, &in.Intent
		case strings.HasSuffix(r.URL.Path, "/revoke"):
			var in presignregistry.ResourceMutationInput
			decodeErr = json.Unmarshal(raw, &in)
			tracked.Operation = presignregistry.OperationSelfRevoke
			if strings.HasPrefix(r.URL.Path, "/api/v1/presign/grants/") {
				tracked.Operation = presignregistry.OperationOwnerRevoke
			}
			tracked.RequestID, tracked.resource = in.RequestID, &in
		case strings.HasSuffix(r.URL.Path, "/close"):
			var in presignregistry.CloseRequestInput
			decodeErr = json.Unmarshal(raw, &in)
			tracked.Operation, tracked.RequestID = presignregistry.OperationCloseRequest, in.RequestID
		default:
			decodeErr = presignregistry.ErrInvalid
		}
		if decodeErr != nil || tracked.RequestID == uuid.Nil || tracked.ActorID == uuid.Nil || captured.status != 200 || captured.bytes > 8192 || json.Unmarshal(captured.body.Bytes(), &tracked.Outcome) != nil {
			failures = append(failures, "unexpected registry mutation or outcome")
		}
		dispatches = append(dispatches, tracked)
	})
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal("task registry TLS listener unavailable")
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	grantExpiresAt := time.Now().UTC().Truncate(time.Microsecond).Add(2 * time.Hour)
	packet, _ := json.Marshal(map[string]any{
		"base": base.String(), "cookieName": SessionCookieName, "ownerCookie": ownerCookie, "senderCookie": senderCookie, "viewerCookie": viewerCookie, "foreignCookie": foreignCookie,
		"orgID": orgID, "ownerID": ownerID, "senderID": sender.ID, "viewerID": viewer.ID, "foreignOrgID": foreignOrg.ID, "foreignUserID": foreign.ID,
		"ownerName": owner.Name, "ownerEmail": owner.Email, "senderName": sender.Name, "senderEmail": sender.Email, "viewerName": viewer.Name, "viewerEmail": viewer.Email,
		"templateID": templateID, "templateName": templateName, "templateVersion": 1, "templateContentSHA256": canonicalTemplate.SHA256, "templateApprovedBy": ownerID, "templateApprovedAt": approvedAt,
		"workflowName": workflowName, "companyName": input.Values["provider_company"], "companyID": input.Values["provider_company_id"], "authorityBasis": input.Values["provider_authority"], "font": "Caveat", "grantExpiresAt": grantExpiresAt, "maxUses": 2,
	})
	crmDocumentBrowserWriteE2E(t, inputPath, packet)
	defer os.Remove(inputPath)
	for {
		body, readErr := os.ReadFile(donePath)
		if readErr == nil {
			if info, err := os.Lstat(donePath); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatal("registry completion marker must be a private regular file")
			}
			var done struct {
				ExitCode *int `json:"exit_code"`
				Verified bool `json:"verified"`
			}
			if len(body) > 4096 || json.Unmarshal(body, &done) != nil || done.ExitCode == nil || *done.ExitCode != 0 || !done.Verified {
				t.Fatal("external registry browser did not accept journey")
			}
			break
		}
		if !os.IsNotExist(readErr) {
			t.Fatal("registry browser completion marker unavailable")
		}
		select {
		case <-ctx.Done():
			t.Fatal("external registry browser deadline exceeded")
		case <-time.After(100 * time.Millisecond):
		}
	}
	mu.Lock()
	posts := append([]presignRegistryBrowserDispatchE2E(nil), dispatches...)
	fontReads := append([]presignRegistryBrowserFontE2E(nil), fonts...)
	recoveryStatuses := append([]int(nil), recoveries...)
	bad := append([]string(nil), failures...)
	forbidden := forbiddenDispatches
	mu.Unlock()
	if len(bad) != 0 || forbidden != 0 || len(posts) != 7 || len(fontReads) == 0 || !equalRegistryBrowserIntsE2E(recoveryStatuses, []int{200, 404, 200}) {
		t.Fatalf("registry browser dispatch contract changed: writes=%d fonts=%d recoveries=%v fixed_failures=%v forbidden=%d", len(posts), len(fontReads), recoveryStatuses, bad, forbidden)
	}
	for _, f := range fontReads {
		expected, err := render.SignatureFontSHA256(f.Font)
		if err != nil || expected != f.SHA256 || f.Bytes < 1 {
			t.Fatal("browser font HTTP bytes differ from authoritative asset")
		}
	}
	presignRegistryBrowserVerifyE2E(t, ctx, q, pool, s, router, orgID, owner, sender, viewer, foreign, ownerCookie, senderCookie, viewerCookie, foreignCookie, posts, canonicalTemplate, templateID, approvedAt, grantExpiresAt, workflowName, artifacts, fontReads, recoveryStatuses)
}

func equalRegistryBrowserIntsE2E(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func presignRegistryBrowserVerifyE2E(t *testing.T, ctx context.Context, q *generated.Queries, pool *pgxpool.Pool, s *Server, router http.Handler, orgID uuid.UUID, owner, sender, viewer, foreign *generated.User, ownerCookie, senderCookie, viewerCookie, foreignCookie string, posts []presignRegistryBrowserDispatchE2E, template htmlmaster.TemplateCommitment, templateID uuid.UUID, approvedAt, grantExpiresAt time.Time, workflowName, artifacts string, fonts []presignRegistryBrowserFontE2E, recoveryStatuses []int) {
	t.Helper()
	expectedOps := []string{presignregistry.OperationApproveWorkflow, presignregistry.OperationCreateGrant, presignregistry.OperationReviseGrant, presignregistry.OperationSelfRevoke, presignregistry.OperationCreateGrant, presignregistry.OperationOwnerRevoke, presignregistry.OperationCloseRequest}
	seen := map[uuid.UUID]bool{}
	outcomes := []presignregistry.Outcome{}
	for i, post := range posts {
		expectedActor := sender.ID
		if i == 0 || i == 5 {
			expectedActor = owner.ID
		}
		out := post.Outcome
		if post.Operation != expectedOps[i] || post.ActorID != expectedActor || seen[post.RequestID] || post.Status != 200 || out.OrgID != orgID || out.UserID != expectedActor || out.RequestID != post.RequestID || out.Operation != post.Operation {
			t.Fatal("browser operation changed original actor, nonce or outcome")
		}
		seen[post.RequestID] = true
		var expectedDigest string
		switch {
		case post.workflow != nil:
			in := *post.workflow
			in.Definition.Template.ApprovedAt = in.Definition.Template.ApprovedAt.UTC().Truncate(time.Microsecond)
			raw, _, _, err := presignregistry.CanonicalDefinition(in.Definition)
			if err != nil || json.Unmarshal(raw, &in.Definition) != nil || in.ExpectedOrgID != orgID || in.ExpectedUserID != expectedActor || in.ExpectedRevision != 0 {
				t.Fatal("workflow command lost exact approval inputs")
			}
			expectedDigest = presignRegistryBrowserCommandE2E(t, post.Operation, in)
		case post.grant != nil:
			in := *post.grant
			in.ExpiresAt = in.ExpiresAt.UTC().Truncate(time.Microsecond)
			if !in.NotBefore.IsZero() {
				in.NotBefore = in.NotBefore.UTC().Truncate(time.Microsecond)
			}
			if in.ExpectedOrgID != orgID || in.ExpectedUserID != expectedActor || !in.ExpiresAt.Equal(grantExpiresAt) {
				t.Fatal("grant command changed original actor or absolute expiry")
			}
			expectedDigest = presignRegistryBrowserCommandE2E(t, post.Operation, in)
		case post.resource != nil:
			if post.resource.ExpectedOrgID != orgID || post.resource.ExpectedUserID != expectedActor || !post.resource.Confirmed {
				t.Fatal("revocation command changed original actor")
			}
			expectedDigest = presignRegistryBrowserCommandE2E(t, post.Operation, *post.resource)
		}
		if i == 6 {
			if out.State != "closed" || out.Reference != (presign.Reference{}) || out.CommandSHA256 != "" || out.ResourceKind != "" {
				t.Fatal("unsubmitted original request was not closed")
			}
		} else if out.State != "committed" || out.CommandSHA256 != expectedDigest || expectedDigest == "" {
			t.Fatal("outcome changed normalized original command")
		}
		row, err := q.GetOwnPresignMutationRequest(ctx, generated.GetOwnPresignMutationRequestParams{OrgID: orgID, ActorUserID: expectedActor, RequestID: post.RequestID})
		var saved presignregistry.Outcome
		if err != nil || json.Unmarshal(row.OutcomeJson, &saved) != nil || saved != out || row.State != out.State || row.Operation != out.Operation || !row.OccurredAt.Valid || !row.OccurredAt.Time.Equal(out.OccurredAt) || hex.EncodeToString(row.CommandSha256) != out.CommandSHA256 {
			t.Fatal("HTTP outcome differs from actual durable row")
		}
		outcomes = append(outcomes, out)
	}
	if posts[1].Outcome.Reference.ID != posts[2].Outcome.Reference.ID || posts[2].Outcome.Reference != posts[3].Outcome.Reference || posts[4].Outcome.Reference != posts[5].Outcome.Reference || posts[1].Outcome.Reference.ID == posts[4].Outcome.Reference.ID {
		t.Fatal("renewal or revocation changed logical authority")
	}
	wr, err := q.GetPresignWorkflowRevisionForShare(ctx, generated.GetPresignWorkflowRevisionForShareParams{OrgID: orgID, WorkflowID: posts[0].Outcome.Reference.ID, Revision: 1})
	if err != nil {
		t.Fatal("read immutable workflow")
	}
	definition, err := presignregistry.DecodeDefinition(wr.CanonicalDefinition)
	if err != nil {
		t.Fatal("decode immutable definition")
	}
	canonical, definitionSHA, rules, err := presignregistry.CanonicalDefinition(definition)
	policy, policyErr := presign.DecodePolicy(wr.CanonicalPolicy)
	if err != nil || policyErr != nil || !bytes.Equal(canonical, wr.CanonicalDefinition) || definitionSHA != hex.EncodeToString(wr.DefinitionSha256) || posts[0].Outcome.Reference != (presign.Reference{ID: definition.ID, Revision: 1, SHA256: definitionSHA}) || policy.Commitment() != hex.EncodeToString(wr.PolicySha256) {
		t.Fatal("approval canonical commitments changed")
	}
	p := policy.Snapshot()
	if definition.Name != workflowName || definition.Kind != presignregistry.KindReviewedDocument || definition.OrgID != orgID || definition.Revision != 1 || definition.Template != (presign.TemplatePin{ID: templateID, Version: 1, ContentSHA256: template.SHA256, ApprovedBy: owner.ID, ApprovedAt: approvedAt}) || definition.Executor != (presign.ExecutorIdentity{Kind: presign.ExecutorMember, UserID: owner.ID}) || definition.MaxUses != 2 || p.ID != definition.PolicyID || p.OrgID != orgID || p.Revision != 1 || p.Template != definition.Template || p.Executor != definition.Executor || p.Rules != rules || p.ApprovedBy != owner.ID || !p.ApprovedAt.Equal(wr.ApprovedAt.Time) || !p.ApprovedAt.After(approvedAt) || p.Workflow.ContentSHA256 != definitionSHA || p.Workflow.ID != definition.ID || p.Workflow.ApprovedBy != owner.ID || !p.Workflow.ApprovedAt.Equal(p.ApprovedAt) || p.MaxUses != 2 {
		t.Fatal("policy changed owner, actual executor or selected design")
	}
	if err := presignregistry.ValidateDefinitionAgainstTemplate(definition, template.MasterJSON, template.DefaultsJSON); err != nil {
		t.Fatal("approved rules lost declaration coverage")
	}
	fontSHA, err := render.SignatureFontSHA256("Caveat")
	if err != nil {
		t.Fatal("actual bundled font unavailable")
	}
	copy := presignregistry.Disclosure()
	type revisionProof struct {
		Reference presign.Reference     `json:"reference"`
		Snapshot  presign.GrantSnapshot `json:"snapshot"`
	}
	type grantProof struct {
		ID               uuid.UUID       `json:"id"`
		CurrentRevision  int64           `json:"current_revision"`
		RevocationReason string          `json:"revocation_reason"`
		ConsumedUses     int64           `json:"consumed_uses"`
		Revisions        []revisionProof `json:"revisions"`
	}
	grants := []grantProof{}
	for index, id := range []uuid.UUID{posts[1].Outcome.Reference.ID, posts[4].Outcome.Reference.ID} {
		head, err := q.GetPresignGrantHeadForShare(ctx, generated.GetPresignGrantHeadForShareParams{OrgID: orgID, ID: id})
		expectedRevision, reason := int64(2), "self_revoked"
		if index == 1 {
			expectedRevision, reason = 1, "owner_revoked"
		}
		if err != nil || head.GrantorUserID != sender.ID || head.CurrentRevision != expectedRevision || !head.RevokedAt.Valid || head.RevokedReason.String != reason {
			t.Fatal("revocation changed original grantor or current head")
		}
		proof := grantProof{ID: id, CurrentRevision: head.CurrentRevision, RevocationReason: reason, Revisions: []revisionProof{}}
		for revision := int64(1); revision <= expectedRevision; revision++ {
			row, err := q.GetPresignGrantRevisionForShare(ctx, generated.GetPresignGrantRevisionForShareParams{OrgID: orgID, GrantID: id, Revision: revision})
			if err != nil {
				t.Fatal("read retained consent revision")
			}
			grant, err := presign.DecodeGrant(row.CanonicalGrant)
			g := grant.Snapshot()
			if err != nil || !bytes.Equal(grant.CanonicalJSON(), row.CanonicalGrant) || grant.Commitment() != hex.EncodeToString(row.GrantSha256) || g.OrgID != orgID || g.ID != id || g.Revision != revision || g.Policy != policy.Reference() || g.Grantor.UserID != sender.ID || g.Grantor.Name != sender.Name || g.Grantor.Email != sender.Email || g.Grantor.CompanyName != definition.RecipientRules.ProviderCompanyName || g.Grantor.CompanyID != definition.RecipientRules.ProviderCompanyID || g.Grantor.AuthorityBasis != definition.RecipientRules.ProviderAuthorityBasis || g.Signature.Font != "Caveat" || g.Signature.FontSHA256 != fontSHA || g.Disclosure != (presign.CopyPin{Version: copy.Version, SHA256: copy.SHA256}) || !g.NotBefore.Equal(g.GrantedAt) || !g.GrantedAt.Equal(row.GrantedAt.Time) || !g.ExpiresAt.Equal(grantExpiresAt) || !g.ExpiresAt.Equal(row.ExpiresAt.Time) || g.MaxUses != 2 || row.ConsumedUses != 0 {
				t.Fatal("recorded consent lost exact identity, style, deadline or use limit")
			}
			proof.Revisions = append(proof.Revisions, revisionProof{Reference: grant.Reference(), Snapshot: g})
		}
		if len(proof.Revisions) == 2 && (!proof.Revisions[1].Snapshot.GrantedAt.After(proof.Revisions[0].Snapshot.GrantedAt) || proof.Revisions[0].Reference == proof.Revisions[1].Reference) {
			t.Fatal("renewal reused old confirmation time or commitment")
		}
		var revokedAt time.Time
		var why string
		var actor uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT revoked_at,reason,actor_user_id FROM presign_grant_revocations WHERE org_id=$1 AND grant_id=$2`, orgID, id).Scan(&revokedAt, &why, &actor); err != nil || !revokedAt.Equal(head.RevokedAt.Time) || why != reason || actor != map[int]uuid.UUID{0: sender.ID, 1: owner.ID}[index] {
			t.Fatal("terminal revocation lost actor and evidence")
		}
		grants = append(grants, proof)
	}
	events, err := q.ListRecentEventsByOrg(ctx, generated.ListRecentEventsByOrgParams{OrgID: orgID, Limit: 8})
	if err != nil || len(events) != 7 {
		t.Fatal("audit cardinality changed")
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	chain := audit.NewChainVerifier()
	chain.VerifyPage(events)
	if result := chain.Result(); !result.OK || !result.Complete || result.TotalChecked != 7 {
		t.Fatal("actual audit chain failed")
	}
	auditRefs := []map[string]any{}
	for i, event := range events {
		var payload struct {
			RequestID     uuid.UUID `json:"request_id"`
			ResourceKind  string    `json:"resource_kind"`
			ResourceID    uuid.UUID `json:"resource_id"`
			Revision      int64     `json:"revision"`
			SHA256        string    `json:"sha256"`
			CommandSHA256 string    `json:"command_sha256"`
		}
		post := posts[i]
		expectedKind := "presign." + post.Operation
		if i == 6 {
			expectedKind = "presign.request.closed"
		}
		if json.Unmarshal(event.PayloadJson, &payload) != nil || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != post.ActorID || event.DocumentID.Valid || event.RecipientID.Valid || event.Kind != expectedKind || payload.RequestID != post.RequestID || len(event.RowHash) != 32 {
			t.Fatal("audit lost original actor or operation lineage")
		}
		if i < 6 && (payload.ResourceID != post.Outcome.Reference.ID || payload.Revision != post.Outcome.Reference.Revision || payload.SHA256 != post.Outcome.Reference.SHA256 || payload.CommandSHA256 != post.Outcome.CommandSHA256 || payload.ResourceKind != post.Outcome.ResourceKind) {
			t.Fatal("audit changed exact resource or command")
		}
		auditRefs = append(auditRefs, map[string]any{"id": event.ID, "actor_user_id": post.ActorID, "kind": event.Kind, "request_id": post.RequestID, "row_sha256": hex.EncodeToString(event.RowHash)})
	}
	counts := map[string]int{}
	for _, table := range []string{"presign_workflows", "presign_workflow_revisions", "presign_grants", "presign_grant_revisions", "presign_grant_revocations", "presign_mutation_requests", "documents", "recipients", "document_fields", "signatures", "send_sealing_intents", "email_deliveries", "webhook_deliveries", "document_agent_tokens", "api_keys"} {
		var n int
		// Fixed closed allowlist in the exact disposable child database.
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal("read bounded disposable effect inventory")
		}
		counts[table] = n
	}
	expectedCounts := map[string]int{"presign_workflows": 1, "presign_workflow_revisions": 1, "presign_grants": 2, "presign_grant_revisions": 3, "presign_grant_revocations": 2, "presign_mutation_requests": 7, "documents": 0, "recipients": 0, "document_fields": 0, "signatures": 0, "send_sealing_intents": 0, "email_deliveries": 0, "webhook_deliveries": 0, "document_agent_tokens": 0, "api_keys": 0}
	if !maps.Equal(counts, expectedCounts) {
		t.Fatal("settings created duplicates or document/signing/invitation effects")
	}
	// Ordinary read/refusal probes use the actual router and cookie middleware.
	// They add no synthetic browser outcome records or application audit events.
	probe := func(method, path, body, cookie string, status int) {
		t.Helper()
		r := httptest.NewRequest(method, s.PublicURL+path, strings.NewReader(body)).WithContext(ctx)
		if method != http.MethodGet {
			r.Header.Set("Origin", s.PublicURL)
			r.Header.Set("Content-Type", "application/json")
		}
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("ordinary actor isolation status=%d expected=%d", w.Code, status)
		}
	}
	probe(http.MethodGet, "/api/v1/presign/self-grants/"+posts[1].Outcome.Reference.ID.String(), "", foreignCookie, 404)
	probe(http.MethodGet, "/api/v1/presign/requests/"+posts[4].RequestID.String(), "", foreignCookie, 404)
	probe(http.MethodGet, "/api/v1/presign/grants", "", senderCookie, 403)
	probe(http.MethodPost, "/api/v1/presign/self-grants/create", `{}`, viewerCookie, 403)
	probe(http.MethodGet, "/api/v1/presign/self-grants", "", viewerCookie, 200)
	probe(http.MethodGet, "/api/v1/presign/grants", "", ownerCookie, 200)
	var afterRequests, afterEvents int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM presign_mutation_requests),(SELECT count(*) FROM events)`).Scan(&afterRequests, &afterEvents); err != nil || afterRequests != 7 || afterEvents != 7 {
		t.Fatal("read or forbidden-actor probe changed registry effects")
	}
	receipt := map[string]any{
		"result": "pass", "org_id": orgID, "owner_id": owner.ID, "sender_id": sender.ID, "viewer_id": viewer.ID, "foreign_org_id": foreign.OrgID, "foreign_user_id": foreign.ID,
		"template": map[string]any{"id": templateID, "version": 1, "content_sha256": template.SHA256, "approved_by": owner.ID, "approved_at": approvedAt, "schema_version": 3, "approval_is_synthetic_setup": true},
		"workflow": map[string]any{"definition": definition, "definition_sha256": definitionSHA, "policy": p, "policy_reference": policy.Reference()},
		"grants":   grants, "outcomes": outcomes, "dispatches": posts, "audit_refs": auditRefs, "font_reads": fonts, "recovery_statuses": recoveryStatuses, "counts": counts,
		"actual_postgresql": true, "actual_signed_session_routes": true, "actual_bundled_font_bytes": true, "original_actor_requests_verified": true, "audit_chain_verified": true, "immutable_revisions_verified": true, "absolute_expiry_preserved": true, "revision_start_clamped_to_confirmation": true,
		"foreign_actor_refused": true, "viewer_creation_refused": true, "consumed_uses": 0, "documents_sent": 0, "signatures_created": 0, "mail_jobs": 0,
		"execution_available": false, "actual_presign_execution": false, "actual_template_browser_approval": false, "renderer_or_pdf_worker_required": false, "storage_or_provider_peer_used": false, "live_provider": false, "deployment": false,
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil || len(body) > 64*1024 {
		t.Fatal("safe backend receipt exceeds contract")
	}
	for _, secret := range []string{ownerCookie, senderCookie, viewerCookie, foreignCookie} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("private session entered backend receipt")
		}
	}
	crmDocumentBrowserWriteE2E(t, filepath.Join(artifacts, "backend-receipt.json"), append(body, '\n'))
}
