// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"testing"
)

func TestEmailDiagnostic483NeverPersistsProviderEcho(t *testing.T) {
	secret := "hn1." + strings.Repeat("A", 43)
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""}, {fmt.Errorf("private %s: %w", secret, context.Canceled), "email_delivery_canceled"},
		{fmt.Errorf("private %s: %w", secret, context.DeadlineExceeded), "email_delivery_timeout"},
		{&net.DNSError{Err: secret, Name: secret, IsTimeout: true}, "email_delivery_timeout"},
		{fmt.Errorf("smtp data %s: %w", secret, &textproto.Error{Code: 550, Msg: secret}), "email_delivery_smtp_550"},
		{&textproto.Error{Code: 999, Msg: secret}, "email_delivery_transport_unavailable"},
		{errors.New(secret), "email_delivery_transport_unavailable"}}
	for _, c := range cases {
		got := SafeEmailDiagnosticV1(c.err)
		if got != c.want || strings.Contains(got, secret) {
			t.Fatal("unsafe or unstable email diagnostic", got)
		}
	}
}
