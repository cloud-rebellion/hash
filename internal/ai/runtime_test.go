// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package ai

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"strings"
	"testing"
)

// stubProvider records the request it received so tests can inspect what
// crossed the Shield boundary.
type stubProvider struct {
	got      Request
	response string
}

func (s *stubProvider) Name() string     { return "stub" }
func (s *stubProvider) Model() string    { return "stub-model" }
func (s *stubProvider) Endpoint() string { return "" }
func (s *stubProvider) Complete(_ context.Context, req Request) (Response, error) {
	s.got = req
	resp := s.response
	if resp == "" {
		resp = "echo: " + req.User
	}
	return Response{Text: resp, Provider: "stub", Model: "stub-model"}, nil
}

func TestRuntime_PIIDoesNotReachProvider(t *testing.T) {
	// Build a LocalShield with a real key so PII gets tokenized.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	shield, err := NewLocalShield(key)
	if err != nil {
		t.Fatalf("shield init: %v", err)
	}

	stub := &stubProvider{}
	rt := New(nil, shield, NoopEmbedder{}, stub)

	req := Request{
		System: "You are helpful.",
		User:   "My email is alice@example.com and my phone is +46 70 123 4567. Help me.",
	}
	resp, err := rt.Complete(context.Background(), req, CompleteOptions{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	// The stub received tokenized input, not the raw email/phone.
	if strings.Contains(stub.got.User, "alice@example.com") {
		t.Fatalf("plaintext email leaked to provider: %q", stub.got.User)
	}
	if strings.Contains(stub.got.User, "+46 70 123 4567") {
		t.Fatalf("plaintext phone leaked to provider: %q", stub.got.User)
	}
	if !strings.Contains(stub.got.User, "[shield:email:") {
		t.Fatalf("expected shielded token in provider input, got %q", stub.got.User)
	}
	// The response is the stub's echo; since the stub didn't include any
	// shielded tokens in its response, Untokenize is a no-op and we see
	// the raw echo back (which itself contains the tokens).
	if !strings.Contains(resp.Text, "echo:") {
		t.Fatalf("unexpected response: %q", resp.Text)
	}
}

func TestRuntime_ShieldUntokenizeRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	shield, _ := NewLocalShield(key)

	// Stub that echoes the request prefixed so we can spot tokens.
	stub := &stubProvider{response: ""}
	stub.response = "Reply for [shield:email:tok_xxx]" // bogus, gets replaced in Untokenize only if stub.response matches a real token
	rt := New(nil, shield, NoopEmbedder{}, stub)

	req := Request{User: "Email me at bob@example.com please."}
	resp, err := rt.Complete(context.Background(), req, CompleteOptions{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	// We can't easily craft a "real" token in the stub response without
	// resolving the actual hex, so this test mostly proves the round-trip
	// doesn't error and that the response is returned.
	if resp.Text == "" {
		t.Fatalf("empty response")
	}
}

func TestRuntime_NoProviderForUnknownName(t *testing.T) {
	rt := New(nil, NoopShield{}, NoopEmbedder{})
	_, err := rt.Complete(context.Background(), Request{User: "hi"}, CompleteOptions{Provider: "nope"})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestCache(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	shield, _ := NewLocalShield(key)
	calls := 0
	provider := stubProviderFunc(func(req Request) (Response, error) {
		calls++
		return Response{Text: "answer"}, nil
	})
	rt := New(nil, shield, NoopEmbedder{}, provider)
	cacheKey := "k1"
	req := Request{User: "Q"}
	org, doc, user := uuid.New(), uuid.New(), uuid.New()
	for i := 0; i < 3; i++ {
		_, err := rt.Complete(context.Background(), req, CompleteOptions{CacheKey: cacheKey, OrgID: org, DocumentID: &doc, UserID: &user})
		if err != nil {
			t.Fatalf("complete: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("cache miss: want 1 call, got %d", calls)
	}
}

func TestStatus_NoProviders(t *testing.T) {
	rt := New(nil, NoopShield{}, NoopEmbedder{})
	st := rt.Status()
	if st.ShieldActive {
		t.Fatal("NoopShield should report Active=false")
	}
	if len(st.Providers) != 0 {
		t.Fatalf("unexpected providers: %+v", st.Providers)
	}
	if st.PromptCount == 0 {
		t.Fatal("expected built-in prompts to be registered")
	}
}

// stubProviderFunc is a tiny adapter so tests don't need a full struct.
type stubProviderFunc func(req Request) (Response, error)

func (f stubProviderFunc) Name() string     { return "stub" }
func (f stubProviderFunc) Model() string    { return "stub-model" }
func (f stubProviderFunc) Endpoint() string { return "" }
func (f stubProviderFunc) Complete(_ context.Context, req Request) (Response, error) {
	return f(req)
}

func TestRuntimeCacheScopesAndOptions(t *testing.T) {
	calls := 0
	p := stubProviderFunc(func(Request) (Response, error) { calls++; return Response{Text: "answer"}, nil })
	rt := New(nil, NoopShield{}, nil, p)
	org, doc, user := uuid.New(), uuid.New(), uuid.New()
	opts := CompleteOptions{OrgID: org, DocumentID: &doc, UserID: &user, CacheKey: "same"}
	req := Request{User: "same", PromptName: "test", PromptVersion: 1, MaxTokens: 32, Temperature: 0.1}
	complete := func(o CompleteOptions, r Request) {
		t.Helper()
		if _, err := rt.Complete(context.Background(), r, o); err != nil {
			t.Fatal(err)
		}
	}
	complete(opts, req)
	complete(opts, req)
	if calls != 1 {
		t.Fatal("same scoped cache miss")
	}
	changed := opts
	changed.OrgID = uuid.New()
	complete(changed, req)
	otherDoc := uuid.New()
	changed = opts
	changed.DocumentID = &otherDoc
	complete(changed, req)
	otherUser := uuid.New()
	changed = opts
	changed.UserID = &otherUser
	complete(changed, req)
	changed = opts
	changed.KnownPII = []string{"Named guarantor"}
	complete(changed, req)
	changedReq := req
	changedReq.MaxTokens++
	complete(opts, changedReq)
	changedReq = req
	changedReq.Temperature = 0.5
	complete(opts, changedReq)
	changedReq = req
	changedReq.PromptVersion++
	complete(opts, changedReq)
	if calls != 8 {
		t.Fatalf("unsafe cache reuse calls=%d", calls)
	}
	rt.ResolveOrgProvider = func(context.Context, uuid.UUID, *generated.Queries) (Provider, bool, error) { return p, true, nil }
	complete(opts, req)
	complete(opts, req)
	if calls != 10 {
		t.Fatal("mutable BYOAI incorrectly cached")
	}
}

func TestAuditedRequestRequiresUsageAndDoesNotReuseCache(t *testing.T) {
	calls, audits := 0, 0
	rt := New(nil, NoopShield{}, nil, stubProviderFunc(func(Request) (Response, error) {
		calls++
		return Response{Text: "answer", InputTokens: 4, OutputTokens: 3}, nil
	}))
	org, doc, user := uuid.New(), uuid.New(), uuid.New()
	opts := CompleteOptions{OrgID: org, DocumentID: &doc, UserID: &user, CacheKey: "same"}
	scoped := rt.ForAuditedRequest(nil, func(_ context.Context, p generated.InsertAICompletionAuditParams) error {
		audits++
		if p.OrgID != org || !p.DocumentID.Valid || uuid.UUID(p.DocumentID.Bytes) != doc || p.InputTokens != 4 || p.OutputTokens != 3 || !p.Success {
			t.Fatal("usage attribution changed")
		}
		return nil
	})
	for i := 0; i < 2; i++ {
		if _, err := scoped.Complete(context.Background(), Request{User: "same"}, opts); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 || audits != 2 || rt.Cache == nil {
		t.Fatal("audited request cached or mutated global runtime")
	}
	refusal := rt.ForAuditedRequest(nil, func(context.Context, generated.InsertAICompletionAuditParams) error {
		return errors.New("private upstream credential")
	})
	if result, err := refusal.Complete(context.Background(), Request{User: "same"}, opts); !errors.Is(err, ErrCompletionAudit) || result.Text != "" || strings.Contains(err.Error(), "private upstream") {
		t.Fatal("usage failure disclosed completion/diagnostic")
	}
}

func TestAuditedRequestProviderLookupUsesBoundQueriesAndFailsClosed(t *testing.T) {
	calls := 0
	rt := New(nil, NoopShield{}, nil, stubProviderFunc(func(Request) (Response, error) {
		calls++
		return Response{Text: "unsafe fallback"}, nil
	}))
	requestQueries := generated.New(nil)
	rt.ResolveOrgProvider = func(_ context.Context, _ uuid.UUID, q *generated.Queries) (Provider, bool, error) {
		if q != requestQueries {
			t.Fatal("audited request used pooled provider lookup")
		}
		return nil, false, errors.New("private provider credential database failure")
	}
	scoped := rt.ForAuditedRequest(requestQueries, func(context.Context, generated.InsertAICompletionAuditParams) error { return nil })
	_, err := scoped.Complete(context.Background(), Request{User: "private clause"}, CompleteOptions{OrgID: uuid.New()})
	if err == nil || err.Error() != "AI organization provider unavailable" || calls != 0 {
		t.Fatalf("failed BYOAI lookup fell back/disclosed: calls%d err%v", calls, err)
	}
}
