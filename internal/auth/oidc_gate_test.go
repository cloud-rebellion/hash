// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"errors"
	"golang.org/x/oauth2"
	"testing"
	"time"
)

func TestOIDCDiscoveryWaitRespectsCancellationAndRecovers(t *testing.T) {
	o := &OIDC{oauth2: &oauth2.Config{ClientID: "cached"}}
	o.gateOnce.Do(func() { o.gate = make(chan struct{}, 1) })
	o.gate <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := o.resolve(ctx); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wait error=%v", err)
		}
	case <-time.After(time.Second):
		<-o.gate
		t.Fatal("cancelled discovery waiter remained blocked")
	}
	<-o.gate
	conf, _, err := o.resolve(context.Background())
	if err != nil || conf.ClientID != "cached" {
		t.Fatalf("recovery config=%v error=%v", conf, err)
	}
}

func TestOIDCDiscoveryCancelledContextDoesNotUseCachedConfig(t *testing.T) {
	o := &OIDC{oauth2: &oauth2.Config{ClientID: "cached"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conf, _, err := o.resolve(ctx)
	if conf != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("config=%v error=%v", conf, err)
	}
}
