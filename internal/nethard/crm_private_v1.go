// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package nethard

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrCRMPrivateEgressV1 deliberately contains no configuration or credential data.
var ErrCRMPrivateEgressV1 = errors.New("nethard: trusted CRM private egress refused")

// This is a new startup-configuration grammar bound, not a traffic/worker limit.
const crmPrivatePinCountV1 = 16
const crmPrivateTokenBytesV1 = 43 // longest canonical IPv6 host prefix, including /128
const crmPrivateSettingBytesV1 = crmPrivatePinCountV1*(crmPrivateTokenBytesV1+1) - 1

var crmPrivateCGNATV1 = netip.MustParsePrefix("100.64.0.0/10")
var crmPrivateBenchmarkV1 = netip.MustParsePrefix("198.18.0.0/15")

// Finite known metadata destinations, verified against provider documentation on
// 2026-10-16. This is not an exhaustive metadata/service or directed-broadcast
// inventory. Link-local metadata is denied by the whole link-local predicate.
// AWS: docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
// Google: docs.cloud.google.com/compute/docs/metadata/overview
// Alibaba: www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata
var crmPrivateMetadataV1 = [...]netip.Addr{
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("fd20:ce::254"),
}

// All policy fields are private values, copied into each constructed client.
// No resolver, transport, TLS, proxy, redirect or development callback is accepted.
type crmPrivatePolicyV1 struct {
	host  string
	port  string
	pins  [crmPrivatePinCountV1]netip.Addr
	count int
}

func crmPrivateEligibleV1(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() ||
		crmPrivateBenchmarkV1.Contains(addr) {
		return false
	}
	for _, denied := range crmPrivateMetadataV1 {
		if addr == denied {
			return false
		}
	}
	return addr.IsPrivate() || crmPrivateCGNATV1.Contains(addr)
}

// crmPrivateAuthorityV1 permits hostname case and omitted/explicit HTTPS 443
// equivalence. It refuses userinfo, paths, zones and noncanonical port spellings.
func crmPrivateAuthorityV1(authority string) (string, string, error) {
	if authority == "" || len(authority) > 2048 || strings.TrimSpace(authority) != authority ||
		strings.ContainsAny(authority, "/?#@\\") || strings.HasSuffix(authority, ":") {
		return "", "", ErrCRMPrivateEgressV1
	}
	u, err := url.Parse("https://" + authority)
	if err != nil || u.User != nil || u.Host != authority || u.Opaque != "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", ErrCRMPrivateEgressV1
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") {
		return "", "", ErrCRMPrivateEgressV1
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" || addr.Is4In6() {
			return "", "", ErrCRMPrivateEgressV1
		}
	} else {
		// CanonicalOrigin has the same ASCII DNS-label grammar; do not accept zones,
		// alternate host syntaxes or a Unicode hostname at this transport boundary.
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", "", ErrCRMPrivateEgressV1
			}
			for i := range len(label) {
				c := label[i]
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", "", ErrCRMPrivateEgressV1
				}
			}
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	} else {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", "", ErrCRMPrivateEgressV1
		}
	}
	return host, port, nil
}

func parseCRMPrivatePolicyV1(origin, raw string) (crmPrivatePolicyV1, error) {
	var p crmPrivatePolicyV1
	if origin == "" || len(origin) > 2048 || raw == "" || len(raw) > crmPrivateSettingBytesV1 {
		return p, ErrCRMPrivateEgressV1
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.RawFragment != "" {
		return p, ErrCRMPrivateEgressV1
	}
	p.host, p.port, err = crmPrivateAuthorityV1(u.Host)
	if err != nil {
		return crmPrivatePolicyV1{}, err
	}
	canonicalHost := p.host
	if p.port != "443" {
		canonicalHost = net.JoinHostPort(p.host, p.port)
	} else if strings.Contains(p.host, ":") {
		canonicalHost = "[" + p.host + "]"
	}
	if origin != "https://"+canonicalHost {
		return crmPrivatePolicyV1{}, ErrCRMPrivateEgressV1
	}
	// Scan in place. Never Split an operator-sized list or append an unbounded
	// collection; reject a seventeenth token before parsing or retaining it.
	for start := 0; ; {
		if p.count == len(p.pins) {
			return crmPrivatePolicyV1{}, ErrCRMPrivateEgressV1
		}
		end := start
		for end < len(raw) && raw[end] != ',' {
			end++
		}
		token := raw[start:end]
		if token == "" || len(token) > crmPrivateTokenBytesV1 || strings.TrimSpace(token) != token {
			return crmPrivatePolicyV1{}, ErrCRMPrivateEgressV1
		}
		prefix, err := netip.ParsePrefix(token)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() ||
			prefix.Bits() != prefix.Addr().BitLen() || prefix.String() != token ||
			!crmPrivateEligibleV1(prefix.Addr()) {
			return crmPrivatePolicyV1{}, ErrCRMPrivateEgressV1
		}
		addr := prefix.Addr()
		for i := 0; i < p.count; i++ {
			if p.pins[i] == addr {
				return crmPrivatePolicyV1{}, ErrCRMPrivateEgressV1
			}
		}
		p.pins[p.count] = addr
		p.count++
		if end == len(raw) {
			break
		}
		start = end + 1
	}
	return p, nil
}

// ValidateCRMPrivateEgressV1 is pure startup validation, with no DNS or sockets.
func ValidateCRMPrivateEgressV1(canonicalOrigin, hostPrefixes string) error {
	_, err := parseCRMPrivatePolicyV1(canonicalOrigin, hostPrefixes)
	return err
}

func (p crmPrivatePolicyV1) requestAllowed(r *http.Request) bool {
	if r == nil || r.URL == nil || r.Method != http.MethodGet || r.URL.Scheme != "https" ||
		r.URL.User != nil || r.URL.Opaque != "" {
		return false
	}
	host, port, err := crmPrivateAuthorityV1(r.URL.Host)
	if err != nil || host != p.host || port != p.port {
		return false
	}
	if r.Host != "" {
		host, port, err = crmPrivateAuthorityV1(r.Host)
		if err != nil || host != p.host || port != p.port {
			return false
		}
	}
	return true
}

func (p crmPrivatePolicyV1) dialTargetAllowed(address string) bool {
	host, port, err := net.SplitHostPort(address)
	return err == nil && strings.ToLower(host) == p.host && port == p.port
}

// This receives net.Dialer's actual numeric socket target after ordinary DNS
// resolution, immediately before connect. Every DNS answer/attempt must pass.
func (p crmPrivatePolicyV1) control(network, address string, _ syscall.RawConn) error {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return ErrCRMPrivateEgressV1
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != p.port {
		return ErrCRMPrivateEgressV1
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return ErrCRMPrivateEgressV1
	}
	addr = addr.Unmap()
	if !crmPrivateEligibleV1(addr) {
		return ErrCRMPrivateEgressV1
	}
	for i := 0; i < p.count; i++ {
		if addr == p.pins[i] {
			return nil
		}
	}
	return ErrCRMPrivateEgressV1
}

type crmPrivateTransportV1 struct {
	policy crmPrivatePolicyV1
	base   *http.Transport
}

func (t *crmPrivateTransportV1) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.policy.requestAllowed(r) {
		return nil, ErrCRMPrivateEgressV1
	}
	return t.base.RoundTrip(r)
}
func (t *crmPrivateTransportV1) CloseIdleConnections() { t.base.CloseIdleConnections() }

// CRMPrivateClientV1 is the sole strict CRM-only constructor. hostPrefixes must
// be an operator setting, never a request, credential or tenant-provided value.
// TLS keeps normal system roots and hostname verification; proxies and redirects
// remain disabled. It accepts no development bypass or arbitrary client hooks.
func CRMPrivateClientV1(timeout time.Duration, canonicalOrigin, hostPrefixes string) (*http.Client, error) {
	p, err := parseCRMPrivatePolicyV1(canonicalOrigin, hostPrefixes)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: p.control}
	base := Transport(nil)
	base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if !p.dialTargetAllowed(address) {
			return nil, ErrCRMPrivateEgressV1
		}
		return d.DialContext(ctx, network, address)
	}
	base.TLSClientConfig = &tls.Config{ServerName: p.host}
	client := Client(timeout, nil)
	client.Transport = &crmPrivateTransportV1{policy: p, base: base}
	return client, nil
}
