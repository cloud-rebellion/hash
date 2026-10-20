// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ai

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func nativeProviderCoordinator282(t *testing.T, parent int64) *workguard.CoordinatorV1 {
	t.Helper()
	v := workguard.VectorV1{ParentBytes: parent, ProviderStreams: 1}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func nativeProviderZero282(t *testing.T, c *workguard.CoordinatorV1, org uuid.UUID) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		state := c.SnapshotV1(org)
		if state.Global == (workguard.VectorV1{}) && state.GlobalGrants == 0 {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("actual native IO/consumer debt not retired: %+v", state)
		case <-tick.C:
		}
	}
}

type nativeProviderConstructor282 struct {
	name     string
	new      func(string) Provider
	complete func(Provider, context.Context, Request, *workguard.CoordinatorV1, uuid.UUID) (*NativeCompletionV1, error)
	response string
}

func nativeProviderConstructors282() []nativeProviderConstructor282 {
	return []nativeProviderConstructor282{
		{"mistral", func(url string) Provider {
			return NewMistralProvider(url, "synthetic-provider-key", "configured-model", true)
		}, func(p Provider, ctx context.Context, r Request, c *workguard.CoordinatorV1, org uuid.UUID) (*NativeCompletionV1, error) {
			return p.(*MistralProvider).CompleteNativeV1(ctx, r, c, org)
		}, `{"choices":[{"message":{"role":"assistant","content":"Reviewed clause"}}],"model":"response-model","usage":{"prompt_tokens":23,"completion_tokens":11}}`},
		{"anthropic", func(url string) Provider {
			return NewAnthropicProvider(url, "synthetic-provider-key", "configured-model", true)
		}, func(p Provider, ctx context.Context, r Request, c *workguard.CoordinatorV1, org uuid.UUID) (*NativeCompletionV1, error) {
			return p.(*AnthropicProvider).CompleteNativeV1(ctx, r, c, org)
		}, `{"content":[{"type":"text","text":"Reviewed "},{"type":"tool","text":"ignored"},{"type":"text","text":"clause"}],"model":"response-model","usage":{"input_tokens":23,"output_tokens":11}}`},
	}
}

// Compare the actual HTTP wire to the existing concrete provider, including
// default fields, escaping, headers and multi-part Anthropic result order.
// A real local HTTP client/server and real coordinator execute; no SQL/M94 or
// production provider-configuration qualification is claimed by these tests.
func TestNativeProviderActualHTTPWireAndOwnedResult282(t *testing.T) {
	for _, kind := range nativeProviderConstructors282() {
		t.Run(kind.name, func(t *testing.T) {
			var seen [][]byte
			var mu sync.Mutex
			var headers []http.Header
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				mu.Lock()
				seen = append(seen, body)
				headers = append(headers, r.Header.Clone())
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, kind.response)
			}))
			defer server.Close()
			provider := kind.new(server.URL)
			request := Request{System: "PII already shielded <>&\n", User: "Reviewed ö clause \" with emoji 🧾", PromptName: "negotiation_counter", PromptVersion: 1, Temperature: .5}
			ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			ordinary, err := provider.Complete(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			org := uuid.New()
			c := nativeProviderCoordinator282(t, 64<<20)
			owner, err := kind.complete(provider, ctx, request, c, org)
			if owner != nil {
				defer owner.CloseConsumerV1()
			}
			if err != nil || owner == nil {
				t.Fatal("actual native completion", err)
			}
			var actual Response
			if err := owner.WithResponseV1(func(value Response) error { actual = value; return nil }); err != nil || actual != ordinary {
				t.Fatalf("owned response differs: %+v vs %+v err=%v", actual, ordinary, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != 2 || !bytes.Equal(seen[0], seen[1]) {
				t.Fatalf("native HTTP JSON changed: %#v", seen)
			}
			for _, key := range []string{"Authorization", "Content-Type", "Accept", "X-Api-Key", "Anthropic-Version"} {
				if headers[0].Get(key) != headers[1].Get(key) {
					t.Fatalf("native header changed: %s", key)
				}
			}
			if state := c.SnapshotV1(org); state.Global.ProviderStreams != 0 || state.Global.ParentBytes <= 0 {
				t.Fatalf("local stream must join while actual result remains owned: %+v", state)
			}
			owner.CloseConsumerV1()
			if err := owner.WithResponseV1(func(Response) error { return nil }); !errors.Is(err, ErrNativeIOV1) {
				t.Fatal("closed response borrowed", err)
			}
			nativeProviderZero282(t, c, org)
		})
	}
}

func TestNativeProviderRequestRefusesBeforeHTTPDispatch282(t *testing.T) {
	for _, kind := range nativeProviderConstructors282() {
		t.Run(kind.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, kind.response) }))
			defer server.Close()
			provider := kind.new(server.URL)
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			org := uuid.New()
			c := nativeProviderCoordinator282(t, 1)
			owner, err := kind.complete(provider, ctx, Request{User: strings.Repeat("<&", 2048)}, c, org)
			if owner != nil {
				owner.CloseConsumerV1()
			}
			if !errors.Is(err, workguard.ErrUnavailableV1) || calls.Load() != 0 {
				t.Fatal("unfunded HTTP request dispatched", calls.Load(), err)
			}
			nativeProviderZero282(t, c, org)
		})
	}
}

func TestNativeProviderResponsePrefixRefusesBeforeModelDelivery282(t *testing.T) {
	for _, kind := range nativeProviderConstructors282() {
		t.Run(kind.name, func(t *testing.T) {
			response := kind.response + strings.Repeat(" ", 192<<10)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, response) }))
			defer server.Close()
			provider := kind.new(server.URL)
			ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			org := uuid.New()
			c := nativeProviderCoordinator282(t, 4<<20)
			owner, err := kind.complete(provider, ctx, Request{User: "already shielded"}, c, org)
			if owner == nil {
				t.Fatal("native request never started", err)
			}
			defer owner.CloseConsumerV1()
			if err == nil {
				t.Fatal("unfunded actual response prefix delivered")
			}
			if err := owner.WithResponseV1(func(Response) error {
				t.Fatal("failed delivery borrowed a provider result")
				return nil
			}); !errors.Is(err, ErrNativeIOV1) {
				t.Fatal("failed delivery result authority", err)
			}
			owner.CloseConsumerV1()
			nativeProviderZero282(t, c, org)
		})
	}
}

func TestNativeProviderCancellationJoinsActualLocalIO282(t *testing.T) {
	entered := make(chan struct{})
	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverDone)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	provider := NewMistralProvider(server.URL, "synthetic-provider-key", "configured-model", true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	org := uuid.New()
	c := nativeProviderCoordinator282(t, 64<<20)
	type result struct {
		owner *NativeCompletionV1
		err   error
	}
	done := make(chan result, 1)
	workerJoined := make(chan struct{})
	received := false
	t.Cleanup(func() {
		cancel()
		if !received {
			select {
			case r := <-done:
				if r.owner != nil {
					r.owner.CloseConsumerV1()
				}
			case <-time.After(5 * time.Second):
				t.Error("native cancellation worker result unjoined")
			}
		}
		select {
		case <-workerJoined:
		case <-time.After(5 * time.Second):
			t.Error("native cancellation goroutine unjoined")
		}
	})
	go func() {
		defer close(workerJoined)
		owner, err := provider.CompleteNativeV1(ctx, Request{User: "shielded"}, c, org)
		done <- result{owner, err}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual HTTP dispatch did not enter")
	}
	if state := c.SnapshotV1(org); state.Global.ProviderStreams != 1 || state.Global.ParentBytes <= 0 {
		t.Fatalf("active IO not charged: %+v", state)
	}
	cancel()
	var completed result
	select {
	case completed = <-done:
		received = true
	case <-time.After(time.Second):
		t.Fatal("native request goroutine did not return")
	}
	if completed.owner == nil || !errors.Is(completed.err, context.Canceled) {
		t.Fatal("cancelled native owner absent", completed.err)
	}
	completed.owner.CloseConsumerV1()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("actual HTTP connection did not retire")
	}
	nativeProviderZero282(t, c, org)
}

func TestNativeProviderNoRedirectOrPrivateDialBypass282(t *testing.T) {
	var foreign atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreign.Add(1) }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "private-dial-denied", true: "redirect-denied"}[allow], func(t *testing.T) {
			provider := NewMistralProvider(origin.URL, "synthetic-provider-key", "configured-model", allow)
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			org := uuid.New()
			c := nativeProviderCoordinator282(t, 64<<20)
			owner, err := provider.CompleteNativeV1(ctx, Request{User: "shielded"}, c, org)
			if owner != nil {
				owner.CloseConsumerV1()
			}
			if err == nil || foreign.Load() != 0 {
				t.Fatal("credentialed native call followed redirect or bypassed SSRF", err)
			}
			nativeProviderZero282(t, c, org)
		})
	}
}

func TestNativeProviderCloseRetainsActualResponseBorrower282(t *testing.T) {
	kind := nativeProviderConstructors282()[0]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, kind.response) }))
	defer server.Close()
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	org := uuid.New()
	c := nativeProviderCoordinator282(t, 64<<20)
	owner, err := kind.complete(kind.new(server.URL), ctx, Request{User: "shielded"}, c, org)
	if err != nil || owner == nil {
		t.Fatal(err)
	}
	defer owner.CloseConsumerV1()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	joined := make(chan struct{})
	t.Cleanup(func() {
		closeRelease()
		select {
		case <-joined:
		case <-time.After(3 * time.Second):
			t.Error("actual response borrower goroutine remains")
		}
	})
	go func() {
		defer close(joined)
		done <- owner.WithResponseV1(func(actual Response) error {
			if actual.Text != "Reviewed clause" {
				return errors.New("actual provider text differs")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("response consumer did not enter")
	}
	owner.CloseConsumerV1()
	if state := c.SnapshotV1(org); state.Global.ParentBytes <= 0 || state.Global.ProviderStreams != 0 {
		t.Fatalf("early response credit: %+v", state)
	}
	closeRelease()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("response borrower failed to join")
	}
	nativeProviderZero282(t, c, org)
}
