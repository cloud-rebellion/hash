//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// This real public create/Send/Sign/error/readLease-close/retry journey leaves
// the final object durable while cert rendering fails, then recovers from the
// actual frozen finalizing source with no fabricated history/cache/READY.
// Synthetic peers prove local protocol/lifetime/order; no Chromium layout,
// Object Lock efficacy, remote-job termination or fleet/RSS claim is made.
func TestOwnedHistoricalNativeCertificateOutageRetiresAndRecoversE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	const originalBody = "NATIVE_CONTRACT_BODY_BEFORE_DETACHED_CERTIFICATE_20261016"
	request := `{"name":"Native certificate output recovery","source_kind":"blocks","blocks_json":{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"` + originalBody + `"},{"id":"sign","type":"signature_field","attrs":{"recipient_role":"signer"}}]},"variables_json":{}}`
	response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents", request, q.cookie)
	var doc struct{ ID uuid.UUID }
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &doc) != nil || doc.ID == uuid.Nil {
		t.Fatalf("actual native certificate source=%d %s", response.Code, response.Body.String())
	}
	base := "/api/v1/documents/" + doc.ID.String()
	response = submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", `{"email":"certificate-output@example.test","name":"Native Certificate Signer","role":"signer","locale":"en"}`, q.cookie)
	if response.Code != http.StatusCreated {
		t.Fatalf("actual party=%d %s", response.Code, response.Body.String())
	}
	response = submitSessionOperationE2E(f.s, http.MethodPost, base+"/send", `{"lawful_basis":"contract"}`, q.cookie)
	var sent sendDocumentResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sent) != nil || len(sent.Links) != 1 {
		t.Fatalf("actual Send=%d %s", response.Code, response.Body.String())
	}
	ownedPlainAssertDrainedV1(t, q)
	var restored atomic.Bool
	var bodySeen atomic.Bool
	var failedCert atomic.Int64
	var actualCertificate atomic.Pointer[[]byte]
	peer := &ownedA4ProtocolRendererV1{}
	renderer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, (20<<20)+1))
		if err != nil || len(raw) > 20<<20 {
			http.Error(w, "invalid protocol request", http.StatusBadRequest)
			return
		}
		if bytes.Contains(raw, []byte(originalBody)) {
			bodySeen.Store(true)
		}
		if bytes.Contains(raw, []byte("<h2>Audit Certificate</h2>")) {
			if !restored.Load() {
				failedCert.Add(1)
				http.Error(w, "synthetic actual detached certificate outage", http.StatusServiceUnavailable)
				return
			}
			copy := bytes.Clone(raw)
			actualCertificate.Store(&copy)
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		peer.ServeHTTP(w, r)
	}))
	t.Cleanup(renderer.Close)
	f.s.Sign.PDF = render.NewGotenberg(renderer.URL)
	link, err := url.Parse(sent.Links[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimPrefix(link.Path, "/sign/")
	rc := q.lookupV1(t, token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: "Native Certificate Signer", Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "native certificate output recovery"})
	if err != nil || result == nil || result.Completed || !bodySeen.Load() || failedCert.Load() != 3 {
		t.Fatal("original final-body-before-cert/3retry/error boundary changed", err, result, failedCert.Load())
	}
	if snapshot, err := q.runtime.SnapshotV1(f.org); err != nil || snapshot.Global.ParentBytes <= 0 || snapshot.Global.ProviderStreams != 0 {
		t.Fatal("actual retained certificate error/IO lifetimes changed", snapshot, err)
	}
	if err = rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	ownedPlainAssertDrainedV1(t, q)
	incomplete, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || incomplete.Status != "finalizing" || !incomplete.CompletionEffectiveAtBound || incomplete.FinalPdfKey.Valid {
		t.Fatal("real recoverable finalizing boundary differs", err)
	}
	if _, err = f.q.GetDocumentFinalizationIntent(f.ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: doc.ID, OrgID: f.org}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("intent published before actual detached evidence completed", err)
	}
	restored.Store(true)
	if err = f.s.Sign.FinalizeStranded(f.ctx, f.org, doc.ID); err != nil {
		t.Fatal("actual original-source recovery failed", err)
	}
	ownedPlainAssertDrainedV1(t, q)
	completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || completed.Status != "completed" {
		t.Fatal("actual recovered publication failed", err)
	}
	type artifact struct {
		key, version pgtype.Text
		sha          []byte
	}
	var bodies [][]byte
	for _, a := range []artifact{{completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha}, {completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256}, {completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256}, {completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256}} {
		if !a.key.Valid || !a.version.Valid || len(a.sha) != sha256.Size {
			t.Fatal("actual recovered artifact pin incomplete")
		}
		raw, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, a.key.String, a.sha, a.version)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, raw)
	}
	actual := actualCertificate.Load()
	if actual == nil || !bytes.Contains(*actual, bodies[2]) || bytes.Contains(bodies[2], []byte(originalBody)) || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(bodies[2]), string(bodies[3])) {
		t.Fatal("stored signed payload differs from actual detached certificate or contract body leaked into it")
	}
	ownedPlainAssertDrainedV1(t, q)
}
