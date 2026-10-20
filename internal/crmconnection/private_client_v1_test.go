// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package crmconnection

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestTrustedPrivateCRMClientV1RejectsUnsafeConfigurationWithoutCredentialFallback(t *testing.T) {
	for _, test := range []struct{ origin, pins string }{
		{"http://127.0.0.1:8080", "10.42.0.1/32"}, {"https://crm.example.test", ""},
		{"https://crm.example.test", "127.0.0.1/32"}, {"https://crm.example.test", "10.42.0.0/24"},
		{"https://crm.example.test", "100.100.100.200/32"}, {"https://crm.example.test", "fd00:ec2::254/128"},
		{"https://crm.example.test", "fd20:ce::254/128"},
	} {
		if c, err := NewTrustedPrivateClientV1(test.origin, test.pins); err == nil || c != nil {
			t.Fatalf("unsafe strict configuration accepted: %+v", test)
		}
	}
	c, err := NewTrustedPrivateClientV1("https://CRM.EXAMPLE.TEST:443/", "10.42.0.1/32")
	if err != nil || c.origin != "https://crm.example.test" {
		t.Fatalf("canonical strict construction: %v", err)
	}
	calls := 0
	// Existing identity validation must still run before the actual HTTP doer.
	// This synthetic seam proves identity ordering, not real private connectivity.
	c.doer = doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected HTTP dispatch")
	})
	id := testIdentity()
	id.Origin = "https://other.example.test"
	if _, err := c.VerifyCredential(context.Background(), id, testToken); !errors.Is(err, ErrIdentity) || calls != 0 {
		t.Fatalf("private pins widened encrypted origin/account authority: calls=%d err=%v", calls, err)
	}
}
