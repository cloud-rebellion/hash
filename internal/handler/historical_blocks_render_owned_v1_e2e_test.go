//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// All source, recipient, Send/Sign, native SQL/formatter/archive and terminal
// publication flows are real. Protocol peers do not claim Chromium fidelity,
// remote-job termination, Object Lock efficacy or production capacity.
func TestOwnedHistoricalCanonicalBlocksUseActualArchiveAndConditionalE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	payload := `{"name":"Native canonical final body","source_kind":"blocks","blocks_json":{"version":1,"blocks":[{"id":"condition","type":"conditional","attrs":{"expression":"var(amount) > 100"},"content":[{"id":"terms","type":"paragraph","text":"NATIVE_CANONICAL_FROZEN_TERMS_20261015 {{amount}}"}]},{"id":"sign","type":"signature_field","attrs":{"recipient_role":"signer"}}]},"variables_json":{"amount":"200"}}`
	created := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents", payload, q.cookie)
	var document struct{ ID uuid.UUID }
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &document) != nil || document.ID == uuid.Nil {
		t.Fatalf("actual canonical creator=%d %s", created.Code, created.Body.String())
	}
	base := "/api/v1/documents/" + document.ID.String()
	party := submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", `{"email":"canonical@example.test","name":"Native Canonical Signer","role":"signer","locale":"en"}`, q.cookie)
	if party.Code != http.StatusCreated {
		t.Fatalf("actual canonical participant=%d %s", party.Code, party.Body.String())
	}
	response := submitSessionOperationE2E(f.s, http.MethodPost, base+"/send", `{"lawful_basis":"contract"}`, q.cookie)
	var sent sendDocumentResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sent) != nil || len(sent.Links) != 1 {
		t.Fatalf("actual canonical Send=%d %s", response.Code, response.Body.String())
	}
	ownedPlainAssertDrainedV1(t, q)
	var actualBody atomic.Bool
	var actualRequest atomic.Pointer[[]byte]
	peer := &ownedA4ProtocolRendererV1{}
	renderer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, (20<<20)+1))
		if err != nil || len(body) > 20<<20 {
			http.Error(w, "invalid synthetic protocol request", http.StatusBadRequest)
			return
		}
		if bytes.Contains(body, []byte("NATIVE_CANONICAL_FROZEN_TERMS_20261015 200")) && bytes.Contains(body, []byte("hash-signature")) && bytes.Contains(body, []byte("Native Canonical Signer")) {
			actualBody.Store(true)
			copy := bytes.Clone(body)
			actualRequest.Store(&copy)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
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
	result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: "Native Canonical Signer", Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "native canonical block renderer"})
	if err != nil || result == nil || !result.Completed {
		t.Fatal("actual native canonical Sign completion", err, result)
	}
	if err = rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	if !actualBody.Load() {
		t.Fatal("actual final renderer did not receive frozen conditional body with exact archived signature span")
	}
	signatures, err := f.q.ListSignaturesByDocument(f.ctx, document.ID)
	if err != nil || len(signatures) != 1 {
		t.Fatal("actual archive oracle inventory", err)
	}
	archive, err := f.s.Storage.GetVerifiedVersionForSendV1(f.ctx, signatures[0].ImageStorageKey, signatures[0].ImageVersionID.String, signatures[0].ImageSha256)
	if err != nil {
		t.Fatal("actual retained exact archive oracle", err)
	}
	request := actualRequest.Load()
	if request == nil || len(archive) == 0 || !bytes.Contains(*request, archive) {
		t.Fatal("native formatter reserialized or lost actual committed archive span bytes")
	}
	ownedPlainAssertDrainedV1(t, q)
}
