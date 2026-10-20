//go:build crm_private_egress_integration

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package nethard

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Selecting this tag requires an owned real private interface, ordinary system
// DNS for both hostnames and a leaf/key whose issuing CA is already trusted by
// the fresh test process's normal OS/container trust store. No test dialer,
// resolver, RootCAs or verification override enters the production client.
// Missing setup fails; it never silently skips or invents an actual destination.
func TestCRMPrivateClientV1OwnedPrivateTLSAndRedirectAcceptance(t *testing.T) {
	required := func(key string) string {
		t.Helper()
		value := os.Getenv(key)
		if value == "" {
			t.Fatalf("required owned private-egress fixture setting absent: %s", key)
		}
		return value
	}
	host := required("HASH_CRM_PRIVATE_EGRESS_TEST_HOST")
	wrongHost := required("HASH_CRM_PRIVATE_EGRESS_TEST_WRONG_HOST")
	rawIP := required("HASH_CRM_PRIVATE_EGRESS_TEST_IP")
	addr, err := netip.ParseAddr(rawIP)
	if err != nil || addr.Is4In6() || addr.String() != rawIP || !crmPrivateEligibleV1(addr) {
		t.Fatal("fixture requires a canonical eligible real private interface IP")
	}
	for _, h := range []string{host, wrongHost} {
		gotHost, port, err := crmPrivateAuthorityV1(h)
		if err != nil || gotHost != h || port != "443" || strings.Contains(h, ":") {
			t.Fatal("fixture hostnames must be canonical DNS names without ports")
		}
		if _, err := netip.ParseAddr(h); err == nil {
			t.Fatal("fixture must exercise ordinary DNS, not an IP URL substitute")
		}
	}
	if host == wrongHost {
		t.Fatal("wrong-host fixture must be a distinct DNS name resolving to the same owned interface")
	}
	pair, err := tls.LoadX509KeyPair(required("HASH_CRM_PRIVATE_EGRESS_TEST_CERT_FILE"), required("HASH_CRM_PRIVATE_EGRESS_TEST_KEY_FILE"))
	if err != nil {
		t.Fatal("fixture TLS leaf/key could not load")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(rawIP, "0"))
	if err != nil {
		t.Fatal("owned private interface could not bind")
	}
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyRequests.Add(1); w.WriteHeader(502) }))
	t.Cleanup(proxy.Close)
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	var accepted, destinations, authorized atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-private-egress-probe" {
			t.Error("fixture request lost original synthetic authorization header")
			w.WriteHeader(401)
			return
		}
		authorized.Add(1)
		if r.URL.Path == "/destination" {
			destinations.Add(1)
		}
		if strings.HasPrefix(r.URL.Path, "/redirect/") {
			n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/redirect/"))
			if err != nil {
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Location", "/destination")
			w.WriteHeader(n)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{\"owned_private_peer\":true}")
	}))
	// Close httptest's unused loopback listener. The actual server binds only the
	// explicitly provisioned eligible private interface, never a loopback alias.
	if err := server.Listener.Close(); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	origin := "https://" + net.JoinHostPort(host, port)
	prefix := netip.PrefixFrom(addr, addr.BitLen()).String()
	c, err := CRMPrivateClientV1(3*time.Second, origin, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	request := func(client *http.Client, target string) (*http.Response, error) {
		r, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", "Bearer synthetic-private-egress-probe")
		return client.Do(r)
	}
	resp, err := request(c, origin+"/api/v1/auth/me")
	if err != nil {
		t.Fatalf("genuine private DNS/Control/system-trusted TLS request: %v", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 128))
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || resp.StatusCode != 200 || string(body) != "{\"owned_private_peer\":true}" || authorized.Load() != 1 || accepted.Load() < 1 {
		t.Fatal("actual private authenticated peer response missing")
	}
	for _, code := range []int{301, 302, 303, 307, 308} {
		resp, err := request(c, origin+"/redirect/"+strconv.Itoa(code))
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
			t.Fatalf("real same-origin redirect %d followed or misclassified: %v", code, err)
		}
	}
	if destinations.Load() != 0 || authorized.Load() != 6 {
		t.Fatal("redirect destination received a credential or source request missing")
	}
	before := authorized.Load()
	badNameOrigin := "https://" + net.JoinHostPort(wrongHost, port)
	badName, err := CRMPrivateClientV1(3*time.Second, badNameOrigin, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(badName.CloseIdleConnections)
	if resp, err := request(badName, badNameOrigin+"/api/v1/auth/me"); err == nil {
		resp.Body.Close()
		t.Fatal("wrong TLS hostname accepted")
	} else {
		var nameErr x509.HostnameError
		if !errors.As(err, &nameErr) {
			t.Fatalf("fixture must fail actual verified TLS hostname, not DNS/policy/setup: %v", err)
		}
	}
	if authorized.Load() != before {
		t.Fatal("wrong TLS identity received authenticated HTTP")
	}
	// Real DNS still reaches the owned IP; the different immutable pin refuses
	// that actual resolved socket before connect. No earlier allowed result lends
	// authority to this fresh client or to another address.
	otherPin := "fd01::1/128"
	if addr.Is6() {
		otherPin = "10.42.0.1/32"
	}
	wrongPin, err := CRMPrivateClientV1(3*time.Second, origin, otherPin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrongPin.CloseIdleConnections)
	beforeConnections := accepted.Load()
	if resp, err := request(wrongPin, origin+"/api/v1/auth/me"); !errors.Is(err, ErrCRMPrivateEgressV1) {
		if resp != nil {
			resp.Body.Close()
		}
		t.Fatalf("actual resolved unpinned socket was not refused: %v", err)
	}
	if accepted.Load() != beforeConnections || authorized.Load() != before {
		t.Fatal("unpinned actual DNS/socket attempt reached the peer")
	}
	// An independently self-signed real TLS peer is not trusted merely because
	// its private numeric IP is pinned. The production client keeps system roots.
	untrustedListener, err := net.Listen("tcp", net.JoinHostPort(rawIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	var untrustedHTTP atomic.Int32
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { untrustedHTTP.Add(1); w.WriteHeader(200) }))
	if err := untrusted.Listener.Close(); err != nil {
		untrustedListener.Close()
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		untrustedListener.Close()
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	if err != nil {
		untrustedListener.Close()
		t.Fatal(err)
	}
	untrusted.Listener = untrustedListener
	untrusted.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
	untrusted.StartTLS()
	t.Cleanup(untrusted.Close)
	untrustedOrigin := "https://" + net.JoinHostPort(host, strconv.Itoa(untrustedListener.Addr().(*net.TCPAddr).Port))
	untrustedClient, err := CRMPrivateClientV1(3*time.Second, untrustedOrigin, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(untrustedClient.CloseIdleConnections)
	if resp, err := request(untrustedClient, untrustedOrigin+"/api/v1/auth/me"); err == nil {
		resp.Body.Close()
		t.Fatal("untrusted TLS peer accepted")
	} else {
		var verifyErr x509.UnknownAuthorityError
		if !errors.As(err, &verifyErr) {
			t.Fatalf("fixture must fail actual unknown-authority verification with a matching hostname: %v", err)
		}
	}
	if untrustedHTTP.Load() != 0 {
		t.Fatal("untrusted TLS peer received authenticated HTTP")
	}
	if proxyRequests.Load() != 0 {
		t.Fatal("hostile environment proxy received any real private or refused request")
	}
}
