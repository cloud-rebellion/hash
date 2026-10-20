package chromium

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// Adapted from the pinned Gotenberg outbound.go helpers; see UPSTREAM.json
// and LICENSE. Successful CONNECT switches immediately to the raw tunnel:
// RFC 9110 section 9.3.6 requires ignoring Content-Length/Transfer-Encoding.
// Parsing a normal response body, including closing/draining it, loses bytes.
func hashDialThroughProxy(ctx context.Context, proxyURL *url.URL, target string, dialProxy func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	port := proxyURL.Port()
	if port == "" {
		port = "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
	}
	conn, err := dialProxy(ctx, "tcp", net.JoinHostPort(proxyURL.Hostname(), port))
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	if conn == nil {
		return nil, errors.New("proxy dial returned no connection")
	}
	established := false
	defer func() {
		if !established {
			_ = conn.Close() // tracked raw socket records close uncertainty
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set proxy handshake deadline: %w", err)
		}
	}
	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname()})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake with proxy: %w", err)
		}
		conn = tlsConn
	}
	connectReq := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if user := proxyURL.User; user != nil {
		password, _ := user.Password()
		connectReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user.Username()+":"+password)))
	}
	if err := connectReq.Write(conn); err != nil {
		return nil, fmt.Errorf("write CONNECT to proxy: %w", err)
	}
	br := bufio.NewReader(conn)
	status, err := hashReadProxyConnectStatus(br)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response from proxy: %w", err)
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("proxy refused CONNECT with status %d", status)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear proxy handshake deadline: %w", err)
	}
	established = true
	return &hashProxyBufferedConn{Conn: conn, reader: br}, nil
}

// Read only a bounded response head. Body framing is deliberately never
// parsed; all bytes after the empty line remain in the exact tunnel reader.
func hashReadProxyConnectStatus(br *bufio.Reader) (int, error) {
	const maxHead = 64 << 10
	var head []byte
	continued := false
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > maxHead-len(head) {
			return 0, errors.New("CONNECT response head exceeds limit")
		}
		head = append(head, line...)
		if err == bufio.ErrBufferFull {
			continued = true
			continue
		}
		if err != nil {
			return 0, errors.New("incomplete CONNECT response head")
		}
		if !continued && (bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n"))) {
			break
		}
		continued = false
	}
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(head)))
	line, err := tp.ReadLine()
	if err != nil {
		return 0, errors.New("invalid CONNECT status line")
	}
	// Reuse standard status-line validation on a synthetic bodyless head.
	// Never pass the actual framing headers or tunnel reader to readTransfer.
	status, err := http.ReadResponse(bufio.NewReader(strings.NewReader(line+"\r\n\r\n")), &http.Request{Method: http.MethodHead})
	if err != nil || status.ProtoMajor != 1 {
		return 0, errors.New("invalid CONNECT status line")
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		return 0, errors.New("invalid CONNECT response headers")
	}
	return status.StatusCode, nil
}

type hashProxyBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *hashProxyBufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (c *hashProxyBufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("underlying %T does not support half-close", c.Conn)
}
