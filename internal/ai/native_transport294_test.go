// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ai

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Observe a real RoundTrip return without manufacturing its response, replacing
// its transport, trust/dial policy or declaring either body/connection retired.
type nativeHeadersObserver294 struct {
	actual http.RoundTripper
	after  func()
}

func (o *nativeHeadersObserver294) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := o.actual.RoundTrip(r)
	if response != nil && err == nil {
		o.after()
	}
	return response, err
}

// This narrow existing run boundary coordinates after actual concrete provider
// decode but before native delivery. All HTTP, request/response accounting and
// retirement still execute the real adapter and coordinator. Exported entry
// methods remain exercised separately by the six original normal test drafts.
func nativeBoundaryComplete294(ctx context.Context, source Provider, request Request, c *workguard.CoordinatorV1, org uuid.UUID, observe func(*http.Client), decoded func(Response, error)) (*NativeCompletionV1, error) {
	var frame, parent int64
	var err error
	var allow bool
	var complete func(*http.Client) (Response, error)
	switch p := source.(type) {
	case *MistralProvider:
		frame, parent, err = nativeRequestResourcesV1(request, p.BaseURL, p.APIKey, p.ModelID)
		allow = p.nativeAllowPrivate
		complete = func(client *http.Client) (Response, error) {
			copy := *p
			copy.Client = client
			return copy.Complete(ctx, request)
		}
	case *AnthropicProvider:
		frame, parent, err = nativeRequestResourcesV1(request, p.BaseURL, p.APIKey, p.ModelID, p.Version)
		allow = p.nativeAllowPrivate
		complete = func(client *http.Client) (Response, error) {
			copy := *p
			copy.Client = client
			return copy.Complete(ctx, request)
		}
	default:
		return nil, ErrNativeIOV1
	}
	if err != nil {
		return nil, err
	}
	return completeNativeProviderV1(ctx, c, org, frame, parent, allow, func(client *http.Client) (Response, error) {
		if observe != nil {
			observe(client)
		}
		response, err := complete(client)
		if decoded != nil {
			decoded(response, err)
		}
		return response, err
	})
}

func TestNativeProviderEarlyFinalResponseRetainsActualUpload294(t *testing.T) {
	request := Request{User: strings.Repeat("shielded clause ", 128<<10)}
	kind := nativeProviderConstructors282()[0]
	type upload struct {
		sum   [32]byte
		bytes int
		err   error
	}
	var ordinary upload
	for _, native := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "native"}[native], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			allowUpload := make(chan struct{})
			var allowOnce sync.Once
			releaseUpload := func() { allowOnce.Do(func() { close(allowUpload) }) }
			defer releaseUpload()
			uploaded := make(chan upload, 1)
			serverDone := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(serverDone)
				if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
					uploaded <- upload{err: err}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				if err := http.NewResponseController(w).Flush(); err != nil {
					uploaded <- upload{err: err}
					return
				}
				select {
				case <-allowUpload:
				case <-r.Context().Done():
					uploaded <- upload{err: r.Context().Err()}
					return
				}
				body, err := io.ReadAll(r.Body)
				uploaded <- upload{sum: sha256.Sum256(body), bytes: len(body), err: err}
				if err == nil {
					_, _ = io.WriteString(w, kind.response)
				}
			}))
			// A task-local real receive window keeps this moderate upload genuinely
			// in flight when response headers arrive; no host setting is changed.
			server.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
				if tcp, ok := conn.(*net.TCPConn); ok {
					if err := tcp.SetReadBuffer(64 << 10); err != nil {
						t.Error(err)
					}
				}
				return ctx
			}
			server.Start()
			defer server.Close()
			defer server.CloseClientConnections()
			wrote := make(chan struct{})
			var wroteOnce sync.Once
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) {
					conn := info.Conn
					if owned, ok := conn.(*aiNativeConnV1); ok {
						conn = owned.inner
					}
					if tcp, ok := conn.(*net.TCPConn); ok {
						if err := tcp.SetWriteBuffer(4096); err != nil {
							t.Error(err)
						}
					}
				},
				WroteRequest: func(httptrace.WroteRequestInfo) { wroteOnce.Do(func() { close(wrote) }) },
			})
			org := uuid.New()
			c := nativeProviderCoordinator282(t, 256<<20)
			provider := kind.new(server.URL)
			var frame *aiNativeReplayFrameV1
			observe := func(client *http.Client) {
				actual := client.Transport
				client.Transport = &nativeHeadersObserver294{actual: actual, after: func() {
					defer releaseUpload()
					select {
					case <-wrote:
						t.Error("upload ended before the early-final response boundary")
					default:
					}
					if native {
						adapter := actual.(*aiNativeRoundTripperV1)
						adapter.owner.mu.Lock()
						frame = adapter.owner.replay
						adapter.owner.mu.Unlock()
						if frame == nil {
							t.Error("real upload replay owner absent")
							return
						}
						frame.mu.Lock()
						sealed, closed, bodies := frame.sealed, frame.closed, frame.bodies
						frame.mu.Unlock()
						if !sealed || closed || bodies == 0 {
							t.Errorf("early response retired live request body: sealed=%v closed=%v bodies=%d", sealed, closed, bodies)
						}
						if state := c.SnapshotV1(org); state.Global.ProviderStreams != 1 || state.Global.ParentBytes <= 0 {
							t.Errorf("in-flight request body lost native debt: %+v", state)
						}
					}
				}}
			}
			var value Response
			if native {
				owner, err := nativeBoundaryComplete294(ctx, provider, request, c, org, observe, nil)
				if owner != nil {
					defer owner.CloseConsumerV1()
				}
				if err != nil || owner == nil {
					t.Fatal("actual native early response", err)
				}
				if err := owner.WithResponseV1(func(v Response) error { value = v; return nil }); err != nil {
					t.Fatal(err)
				}
				if frame == nil {
					t.Fatal("upload frame was not observed")
				}
				select {
				case <-frame.done:
				default:
					t.Fatal("actual Transport request-body close was not joined")
				}
				if _, err := frame.bodyV1(); !errors.Is(err, ErrNativeIOV1) {
					t.Fatal("retired replay callback remained usable", err)
				}
				if state := c.SnapshotV1(org); state.Global.ProviderStreams != 0 || state.Global.ParentBytes <= 0 {
					t.Fatalf("owned result/debt after upload join: %+v", state)
				}
				owner.CloseConsumerV1()
				nativeProviderZero282(t, c, org)
			} else {
				p := provider.(*MistralProvider)
				observe(p.Client.(*http.Client))
				var err error
				value, err = p.Complete(ctx, request)
				if err != nil {
					t.Fatal("ordinary early response", err)
				}
			}
			if value.Text != "Reviewed clause" || value.InputTokens != 23 || value.OutputTokens != 11 {
				t.Fatalf("actual early response changed: %+v", value)
			}
			var actual upload
			select {
			case actual = <-uploaded:
			case <-ctx.Done():
				t.Fatal("actual upload result absent", ctx.Err())
			}
			if actual.err != nil || actual.bytes <= 1<<20 {
				t.Fatal("actual upload incomplete", actual.bytes, actual.err)
			}
			if native && (actual.sum != ordinary.sum || actual.bytes != ordinary.bytes) {
				t.Fatal("native upload bytes differ from the original provider", actual, ordinary)
			}
			if !native {
				ordinary = actual
			}
			select {
			case <-serverDone:
			case <-ctx.Done():
				t.Fatal("actual HTTP handler failed to join", ctx.Err())
			}
		})
	}
}

func TestNativeProviderCancelledDeliveryKeepsUsageWithoutText294(t *testing.T) {
	for _, kind := range nativeProviderConstructors282() {
		t.Run(kind.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, kind.response) }))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			org := uuid.New()
			c := nativeProviderCoordinator282(t, 64<<20)
			decoded := false
			owner, err := nativeBoundaryComplete294(ctx, kind.new(server.URL), Request{User: "shielded"}, c, org, nil, func(value Response, err error) {
				if err != nil || value.Text != "Reviewed clause" || value.Model != "response-model" || value.InputTokens != 23 || value.OutputTokens != 11 {
					t.Error("actual provider result was not decoded", value, err)
					return
				}
				decoded = true
				cancel()
			})
			if owner != nil {
				defer owner.CloseConsumerV1()
			}
			if !decoded || owner == nil || !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled delivery did not return its numeric owner", decoded, err)
			}
			assertNoText := func() {
				t.Helper()
				if err := owner.WithResponseV1(func(Response) error { t.Error("canceled delivery borrowed private provider result"); return nil }); !errors.Is(err, ErrNativeIOV1) {
					t.Fatal("canceled result authority", err)
				}
				usage, err := owner.UsageObservationV1()
				if err != nil || usage.InputTokens != 23 || usage.OutputTokens != 11 {
					t.Fatal("actual numeric usage lost", usage, err)
				}
			}
			assertNoText()
			select {
			case <-owner.state.joined:
			case <-time.After(3 * time.Second):
				t.Fatal("actual canceled delivery IO not joined")
			}
			assertNoText()
			if state := c.SnapshotV1(org); state.Global.ProviderStreams != 0 || state.Global.ParentBytes <= 0 {
				t.Fatalf("numeric observation debt not held: %+v", state)
			}
			owner.CloseConsumerV1()
			nativeProviderZero282(t, c, org)
		})
	}
}

func TestNativeProviderActualErrorDeniesResultBorrow294(t *testing.T) {
	for _, kind := range nativeProviderConstructors282() {
		t.Run(kind.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, "actual provider refusal")
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			org := uuid.New()
			c := nativeProviderCoordinator282(t, 64<<20)
			owner, err := kind.complete(kind.new(server.URL), ctx, Request{User: "shielded"}, c, org)
			if owner != nil {
				defer owner.CloseConsumerV1()
			}
			if owner == nil || err == nil || !strings.Contains(err.Error(), "actual provider refusal") {
				t.Fatal("original real provider error lost", err)
			}
			if err := owner.WithResponseV1(func(Response) error { t.Error("provider error borrowed a result"); return nil }); !errors.Is(err, ErrNativeIOV1) {
				t.Fatal("provider-error result authority", err)
			}
			owner.CloseConsumerV1()
			nativeProviderZero282(t, c, org)
		})
	}
}
