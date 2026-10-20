// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package nethard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCRMPrivatePolicyV1ExactBoundedGrammarAndKnownHardDenials(t *testing.T) {
	const origin = "https://crm.example.test"
	var sixteen strings.Builder
	for i := 1; i <= 16; i++ {
		if i > 1 {
			sixteen.WriteByte(',')
		}
		fmt.Fprintf(&sixteen, "10.42.0.%d/32", i)
	}
	if err := ValidateCRMPrivateEgressV1(origin, sixteen.String()); err != nil {
		t.Fatalf("sixteen explicit host prefixes: %v", err)
	}
	for _, raw := range []string{
		"", "10.42.0.1/32,", ",10.42.0.1/32", "10.42.0.1/32,,10.42.0.2/32", "10.42.0.1/32,10.42.0.1/32",
		"10.42.0.1", "10.42.0.0/24", "fd01::1/64", "10.42.0.01/32", "10.42.0.1/032", " fd01::1/128", "10.42.0.1/32\n",
		"FD01::1/128", "fd01:0:0:0:0:0:0:1/128", "fe80::1%eth0/128", "::ffff:10.42.0.1/128", "crm.example.test/32",
		"1.1.1.1/32", "127.0.0.1/32", "::1/128", "0.0.0.0/32", "::/128", "224.0.0.1/32", "ff02::1/128",
		"169.254.169.254/32", "fe80::1/128", "198.18.0.1/32", "255.255.255.255/32",
		"100.100.100.200/32", "fd00:ec2::254/128", "fd20:ce::254/128",
		sixteen.String() + ",10.42.0.17/32", strings.Repeat("x", crmPrivateSettingBytesV1+1),
	} {
		if err := ValidateCRMPrivateEgressV1(origin, raw); !errors.Is(err, ErrCRMPrivateEgressV1) {
			t.Errorf("unsafe host-prefix grammar accepted: %q err=%v", raw, err)
		}
	}
	for _, raw := range []string{"10.42.0.1/32", "172.16.0.1/32", "192.168.1.1/32", "100.64.0.1/32", "100.127.255.254/32", "fd01::1/128"} {
		if err := ValidateCRMPrivateEgressV1(origin, raw); err != nil {
			t.Errorf("eligible explicit host prefix refused: %q: %v", raw, err)
		}
	}
	for _, badOrigin := range []string{"http://crm.example.test", "https://CRM.EXAMPLE.TEST", "https://crm.example.test/", "https://u:p@crm.example.test", "https://crm.example.test/api", "https://crm.example.test?x=1", "https://crm.example.test#fragment", "https://crm.example.test:0443", "https://crm.example.test:", "https://crm.example.test.", "https://[fd01::1%25eth0]"} {
		if _, err := CRMPrivateClientV1(time.Second, badOrigin, "10.42.0.1/32"); !errors.Is(err, ErrCRMPrivateEgressV1) {
			t.Errorf("unsafe/noncanonical origin accepted: %q %v", badOrigin, err)
		}
	}
}

func TestCRMPrivatePolicyV1ActualNumericControlHasNoPublicOrDevelopmentFallback(t *testing.T) {
	p, err := parseCRMPrivatePolicyV1("https://crm.example.test:8443", "10.42.0.1/32,100.64.0.1/32,fd01::1/128")
	if err != nil {
		t.Fatal(err)
	}
	// These directly exercise the exact Control predicate, not a claim of real
	// private TCP/TLS or DNS acceptance. The real private-network gate is separate.
	for _, target := range []string{"10.42.0.1:8443", "100.64.0.1:8443", "[fd01::1]:8443", "[::ffff:10.42.0.1]:8443"} {
		if err := p.control("tcp", target, nil); err != nil {
			t.Errorf("pinned numeric attempt: %s: %v", target, err)
		}
	}
	// Model changed/mixed resolver answers: each actual attempt is checked. A
	// prior allowed answer conveys no authority to a subsequent unpinned answer.
	for _, target := range []string{"10.42.0.2:8443", "100.64.0.2:8443", "[fd01::2]:8443", "1.1.1.1:8443", "127.0.0.1:8443", "[::1]:8443", "169.254.169.254:8443", "100.100.100.200:8443", "[fd00:ec2::254]:8443", "[fd20:ce::254]:8443", "[fe80::1%eth0]:8443", "10.42.0.1:443", "crm.example.test:8443", "broken"} {
		if !errors.Is(p.control("tcp", target, nil), ErrCRMPrivateEgressV1) {
			t.Errorf("untrusted numeric attempt accepted: %s", target)
		}
	}
	for _, hardDenied := range []string{"100.100.100.200", "fd00:ec2::254", "fd20:ce::254", "127.0.0.1", "169.254.169.254"} {
		// Even a malformed internal policy state cannot let exact pin membership
		// override a hard denial. Production parsing refuses these states first.
		damaged := p
		damaged.count = 1
		damaged.pins[0] = netip.MustParseAddr(hardDenied)
		if !errors.Is(damaged.control("tcp", net.JoinHostPort(hardDenied, "8443"), nil), ErrCRMPrivateEgressV1) {
			t.Errorf("hard denial lost to exact pin: %s", hardDenied)
		}
	}
	if !errors.Is(p.control("udp", "10.42.0.1:8443", nil), ErrCRMPrivateEgressV1) {
		t.Fatal("non-TCP socket accepted")
	}
	for _, target := range []string{"other.example.test:8443", "crm.example.test:443", "10.42.0.1:8443"} {
		if p.dialTargetAllowed(target) {
			t.Errorf("original hostname/port replaced: %s", target)
		}
	}
	if !p.dialTargetAllowed("CRM.EXAMPLE.TEST:8443") {
		t.Fatal("normal hostname case should match")
	}
}

func TestCRMPrivateClientV1RequestFencePrecedesEveryDial(t *testing.T) {
	c, err := CRMPrivateClientV1(time.Second, "https://crm.example.test", "10.42.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	tr := c.Transport.(*crmPrivateTransportV1)
	var dials atomic.Int32
	noSocket := errors.New("test observation: no socket producer")
	// Test-only downstream dial observation; this does not prove private connect.
	tr.base.DialContext = func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, noSocket }
	for _, test := range []struct{ target, host, method string }{
		{"https://other.example.test", "", http.MethodGet}, {"http://crm.example.test", "", http.MethodGet},
		{"https://crm.example.test:8443", "", http.MethodGet}, {"https://user:pass@crm.example.test", "", http.MethodGet},
		{"https://crm.example.test", "other.example.test", http.MethodGet}, {"https://crm.example.test", "crm.example.test:8443", http.MethodGet},
		{"https://crm.example.test", "crm.example.test:", http.MethodGet}, {"https://crm.example.test", "crm.example.test.", http.MethodGet},
		{"https://crm.example.test", "crm.example.test/path", http.MethodGet}, {"https://crm.example.test", "crm.example.test", http.MethodPost},
	} {
		r, err := http.NewRequest(test.method, test.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.host != "" {
			r.Host = test.host
		}
		r.Header.Set("Authorization", "Bearer synthetic-not-a-live-key")
		before := dials.Load()
		if _, err := c.Do(r); !errors.Is(err, ErrCRMPrivateEgressV1) {
			t.Fatalf("wrong target/Host/method did not fail at fence: %+v: %v", test, err)
		}
		if dials.Load() != before {
			t.Fatal("rejected request reached dial/DNS producer")
		}
	}
	for _, host := range []string{"crm.example.test", "CRM.EXAMPLE.TEST", "crm.example.test:443", "CRM.EXAMPLE.TEST:443"} {
		r, _ := http.NewRequest(http.MethodGet, "https://CRM.EXAMPLE.TEST:443/api/v1/auth/me", nil)
		r.Host = host
		before := dials.Load()
		if _, err := c.Do(r); !errors.Is(err, noSocket) || dials.Load() != before+1 {
			t.Fatalf("normal exact Host/effective-port equivalence refused: %s: %v", host, err)
		}
	}
	r, _ := http.NewRequest(http.MethodGet, "https://crm.example.test", nil)
	r.URL.Opaque = "//crm.example.test/api"
	before := dials.Load()
	if _, err := c.Do(r); !errors.Is(err, ErrCRMPrivateEgressV1) || dials.Load() != before {
		t.Fatal("opaque URL reached dial")
	}
}

func TestCRMPrivateClientV1KeepsLiteralTLSProxyTimeoutAndRedirectProfile(t *testing.T) {
	c, err := CRMPrivateClientV1(7*time.Second, "https://crm.example.test:8443", "10.42.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	tr := c.Transport.(*crmPrivateTransportV1)
	base := tr.base
	if c.Timeout != 7*time.Second || c.Jar != nil || base.Proxy != nil || !base.ForceAttemptHTTP2 ||
		base.TLSHandshakeTimeout != 10*time.Second || base.ResponseHeaderTimeout != 25*time.Second ||
		base.MaxIdleConns != 10 || base.IdleConnTimeout != 60*time.Second || base.DialTLSContext != nil {
		t.Fatal("strict client changed original finite timeout/proxy/connection profile")
	}
	tls := base.TLSClientConfig
	if tls == nil || tls.ServerName != "crm.example.test" || tls.InsecureSkipVerify || tls.RootCAs != nil ||
		tls.VerifyConnection != nil || tls.VerifyPeerCertificate != nil || tls.GetClientCertificate != nil {
		t.Fatal("strict client bypassed normal system-root/hostname TLS verification")
	}
	// Every redirect status is handled by the same unconditional refusal callback.
	// Actual private-peer redirect delivery remains in the required service gate.
	for _, status := range []int{301, 302, 303, 307, 308} {
		r, _ := http.NewRequest(http.MethodGet, "https://crm.example.test:8443/next", nil)
		r.Response = &http.Response{StatusCode: status}
		if err := c.CheckRedirect(r, []*http.Request{}); err == nil {
			t.Errorf("redirect %d accepted", status)
		}
	}
	c.CloseIdleConnections()
}

func TestCRMPrivateClientV1RealDialBlocksLoopbackEvenWithHostileProxyEnvironment(t *testing.T) {
	var proxyRequests, authenticatedRequests, acceptedConnections atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyRequests.Add(1); w.WriteHeader(502) }))
	t.Cleanup(proxy.Close)
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			authenticatedRequests.Add(1)
		}
		w.WriteHeader(200)
	}))
	peer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			acceptedConnections.Add(1)
		}
	}
	peer.StartTLS()
	t.Cleanup(peer.Close)
	// The origin can be syntactically loopback; it cannot acquire a loopback pin.
	// Real net.Dialer.Control rejects before connect, rather than swapping dialers
	// or disabling TLS to manufacture a positive private-connect result.
	c, err := CRMPrivateClientV1(time.Second, peer.URL, "10.42.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	r, _ := http.NewRequest(http.MethodGet, peer.URL+"/api/v1/auth/me", nil)
	r.Header.Set("Authorization", "Bearer synthetic-not-a-live-key")
	if _, err := c.Do(r); !errors.Is(err, ErrCRMPrivateEgressV1) {
		t.Fatalf("real loopback socket did not fail strict Control: %v", err)
	}
	if proxyRequests.Load() != 0 || authenticatedRequests.Load() != 0 || acceptedConnections.Load() != 0 {
		t.Fatal("refused real socket or environment proxy received a connection/credential")
	}
}
