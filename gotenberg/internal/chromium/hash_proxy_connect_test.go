// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func TestHashProxyCONNECTResponseHeadBounds(t *testing.T) {
	payload := "\x00\xffraw tunnel bytes"
	for name, fixture := range map[string]struct {
		head  string
		valid bool
	}{
		"fragmented-long-header": {"HTTP/1.1 200 OK\r\nX-Long: " + strings.Repeat("a", 4088) + "\r\nX-Next: retained\r\n\r\n", true},
		"exact-limit":            {"HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("a", (64<<10)-len("HTTP/1.1 200 OK\r\nX-Pad: ")-4) + "\r\n\r\n", true},
		"over-limit":             {"HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("a", 64<<10) + "\r\n\r\n", false},
		"missing-blank-line":     {"HTTP/1.1 200 OK\r\nX-Pad: incomplete", false},
		"invalid-status":         {"HTTP/1.1 private-secret\r\n\r\n", false},
		"invalid-version":        {"PRIVATE/1.1 200 private-secret\r\n\r\n", false},
		"invalid-field":          {"HTTP/1.1 200 OK\r\nprivate-secret\r\n\r\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(fixture.head + payload))
			status, err := hashReadProxyConnectStatus(br)
			if !fixture.valid {
				if err == nil || strings.Contains(err.Error(), "private-secret") {
					t.Fatal("invalid/oversized head admitted or untrusted data reflected: ", err)
				}
				return
			}
			if err != nil || status != http.StatusOK {
				t.Fatal("valid bounded head refused: ", status, err)
			}
			out, err := io.ReadAll(br)
			if err != nil || string(out) != payload {
				t.Fatal("head parser consumed tunnel payload: ", err)
			}
		})
	}
}

func TestHashProxyCorporateRefusalDoesNotDrain(t *testing.T) {
	for name, head := range map[string]string{
		"authentication-refused": "HTTP/1.1 407 Authentication Required\r\nContent-Length: 999999999\r\n\r\n",
		"malformed-head":         "HTTP/1.1 200 OK\r\ninvalid-private-response-line\r\n\r\n",
		"oversized-head":         "HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("a", 64<<10) + "\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			closed := make(chan struct{})
			peer := hashNewProxyPeer(t, func(c net.Conn) {
				defer close(closed)
				br := bufio.NewReader(c)
				if req, err := http.ReadRequest(br); err != nil || req.Method != http.MethodConnect {
					t.Error("CONNECT refusal peer not reached: ", err)
					return
				}
				if _, err := io.WriteString(c, head); err != nil {
					t.Error(err)
					return
				}
				var b [1]byte
				// Oversized heads can leave unread bytes when the exact raw
				// socket is closed; TCP reset is also a terminal owned close.
				if n, err := br.Read(b[:]); n != 0 || (!errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET)) {
					t.Error("rejected handshake socket was not closed without data: ", n, err)
				}
			})
			p := hashProxyForPeer(peer)
			u := &url.URL{Scheme: "http", Host: peer.listener.Addr().String()}
			p.upstreamProxy = func(*url.URL) (*url.URL, error) { return u, nil }
			hashStartProxyFixture(t, p, nil)
			c := hashProxyClient(t, mustParseURL(t, p.URL()).Host)
			if _, err := io.WriteString(c, "CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusBadGateway || bytes.Contains(body, []byte("invalid-private-response-line")) {
				t.Fatal("corporate refusal response: ", err)
			}
			hashAwait(t, "rejected corporate handshake raw socket EOF", closed)
			if err := p.Stop(testLogger()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
