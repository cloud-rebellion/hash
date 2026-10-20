// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"net"
	"net/http"
	"os"
	"time"
)

// This is Hash's constructor-owned pinned MinIO77 profile. No mutable global
// DefaultTransport or arbitrary caller dial/TLS/cookie/redirect callback proves
// native ownership. Its TLS, proxy, timeout, compression and certificate-file
// behavior is the same original first-party profile used by ordinary storage.
func storageHTTPTransportBaseV1(secure bool) *http.Transport {
	t := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext, MaxIdleConns: 256, MaxIdleConnsPerHost: 16, ResponseHeaderTimeout: time.Minute, IdleConnTimeout: time.Minute, TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: 10 * time.Second, DisableCompression: true}
	if secure {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if file := os.Getenv("SSL_CERT_FILE"); file != "" {
			roots, err := x509.SystemCertPool()
			if err != nil {
				roots = x509.NewCertPool()
			}
			if pem, err := os.ReadFile(file); err == nil {
				roots.AppendCertsFromPEM(pem)
			}
			t.TLSClientConfig.RootCAs = roots
		}
	}
	t.MaxResponseHeaderBytes = boundedStorageHeaderBytesV1
	t.MaxConnsPerHost = boundedStorageConnectionsPerHostV1
	t.MaxIdleConnsPerHost = boundedStorageConnectionsPerHostV1
	t.MaxIdleConns = boundedStorageConnectionsPerHostV1
	return t
}

// Captured only by New after its real endpoint/SSE/bucket policy succeeds.
// The static credential object is the very one used by the original SDK; no
// extra secret string is copied or exposed. Each native operation gets a private
// SDK cookie/region cache and HTTP transport, so response/error aliases cannot
// escape into the ordinary client's long-lived cookie jar or connection pool.
type evidenceLocalClientProfileV1 struct {
	self             *evidenceLocalClientProfileV1
	client           *Client
	sdk              *minio.Client
	endpoint, region string
	secure           bool
	lookup           minio.BucketLookupType
	creds            *credentials.Credentials
	base             *http.Transport
	connections      *storageConnectionAdmissionV1
	packageBucket    string
	packageLock      bool
	packageNamespace [32]byte
}

func newEvidenceLocalClientProfileV1(c *Client, mc *minio.Client, cfg Config, creds *credentials.Credentials, lookup minio.BucketLookupType, transport http.RoundTripper) *evidenceLocalClientProfileV1 {
	actual, ok := transport.(*boundedStorageTransportV1)
	if !ok || actual == nil || actual.connections == nil {
		return nil
	}
	base, ok := actual.base.(*http.Transport)
	if !ok || base == nil {
		return nil
	}
	p := &evidenceLocalClientProfileV1{client: c, sdk: mc, endpoint: cfg.Endpoint, region: cfg.Region, secure: cfg.UseSSL, lookup: lookup, creds: creds, base: base.Clone(), connections: actual.connections}
	p.self = p
	p.packageBucket = cfg.Bucket
	p.packageLock = cfg.RequireObjectLock
	p.packageNamespace = packageEvidenceNamespaceForProfileV1(p)
	return p
}
func (c *Client) evidenceLocalProfileV1() (*evidenceLocalClientProfileV1, error) {
	if c == nil || c.mc == nil || c.bucket == "" || c.localProfile == nil {
		return nil, ErrEvidenceLocalIOV1
	}
	p := c.localProfile
	if p.self != p || p.client != c || p.sdk != c.mc || p.creds == nil || p.base == nil || p.connections == nil || p.connections.self != p.connections || p.base.DialContext == nil {
		return nil, ErrEvidenceLocalIOV1
	}
	return p, nil
}
