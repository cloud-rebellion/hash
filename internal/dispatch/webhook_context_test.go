// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestWebhookURLDNSHonorsCancellation(t *testing.T) {
	t.Run("cancelled before lookup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		lookups := 0
		err := validateWebhookURLWithLookup(ctx, "https://subscriber.example.invalid", false, func(context.Context, string) ([]net.IPAddr, error) {
			lookups++
			return nil, nil
		})
		if !errors.Is(err, context.Canceled) || lookups != 0 {
			t.Fatal("cancelled URL validation performed DNS")
		}
	})
	t.Run("stalled lookup receives deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		err := validateWebhookURLWithLookup(ctx, "https://subscriber.example.invalid", false, func(lookupCtx context.Context, host string) ([]net.IPAddr, error) {
			if lookupCtx != ctx || host != "subscriber.example.invalid" {
				t.Fatal("lookup lost caller context or hostname")
			}
			<-lookupCtx.Done()
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("a late resolver success bypassed the deadline")
		}
	})
}

func TestWebhookURLContextPreservesAddressPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		url       string
		addresses []net.IPAddr
		refused   bool
	}{
		{"public", "https://subscriber.example.invalid", []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, false},
		{"mixed private", "https://subscriber.example.invalid", []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("127.0.0.1")}}, true},
		{"metadata", "https://subscriber.example.invalid", []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, true},
		{"invalid address", "https://subscriber.example.invalid", []net.IPAddr{{}}, true},
		{"missing address", "https://subscriber.example.invalid", nil, true},
		{"http", "http://subscriber.example.invalid", []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWebhookURLWithLookup(context.Background(), tc.url, false, func(context.Context, string) ([]net.IPAddr, error) { return tc.addresses, nil })
			if (err != nil) != tc.refused {
				t.Fatal("URL policy changed")
			}
		})
	}
}

func TestWebhookDispatchAndRedirectRejectCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := NewDispatcher(SignaturePair{Primary: "synthetic-strong-signing-secret-0123456789"})
	d.AllowPrivate = true
	result := d.DispatchWithSecret(ctx, "http://127.0.0.1:1", "synthetic-strong-signing-secret-0123456789", WebhookEvent{})
	if !errors.Is(result.Err, context.Canceled) || result.Status != 0 {
		t.Fatal("dispatch ignored cancelled caller context")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.HTTP.CheckRedirect(req, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("redirect validation lost request context")
	}
}
