// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type receivedMessage struct {
	from, body string
	to         []string
}

// The owned sink independently decodes SMTP transparency using textproto.
func smtpSink(t *testing.T) (string, <-chan receivedMessage, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	messages := make(chan receivedMessage, 1)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	var mu sync.Mutex
	var active net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := l.Accept()
		if err != nil {
			return
		}
		accepted.Add(1)
		mu.Lock()
		active = c
		mu.Unlock()
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		r := textproto.NewReader(bufio.NewReader(c))
		io.WriteString(c, "220 owned test sink\r\n")
		var message receivedMessage
		for {
			line, err := r.ReadLine()
			if err != nil {
				return
			}
			verb, _, _ := strings.Cut(line, " ")
			switch verb {
			case "EHLO", "HELO":
				io.WriteString(c, "250 owned test sink\r\n")
			case "MAIL", "RCPT":
				begin, end := strings.IndexByte(line, '<'), strings.IndexByte(line, '>')
				if begin < 0 || end < begin {
					return
				}
				address := line[begin+1 : end]
				if verb == "MAIL" {
					message.from = address
				} else {
					message.to = append(message.to, address)
				}
				io.WriteString(c, "250 accepted\r\n")
			case "DATA":
				io.WriteString(c, "354 send data\r\n")
				body, err := io.ReadAll(r.DotReader())
				if err != nil {
					return
				}
				message.body = strings.ReplaceAll(string(body), "\n", "\r\n")
				messages <- message
				io.WriteString(c, "250 saved\r\n")
			case "QUIT":
				io.WriteString(c, "221 bye\r\n")
				return
			default:
				return
			}
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		if active != nil {
			active.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l.Addr().String(), messages, &accepted
}

func testFixture(t *testing.T, relay string) (*fixtureServer, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	s, err := startFixture(config{"127.0.0.1:0", "127.0.0.1:0", relay, caPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	ca, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("public CA certificate missing")
	}
	entries, _ := os.ReadDir(dir)
	info, _ := os.Stat(caPath)
	if len(entries) != 1 || info.Mode().Perm() != 0644 || strings.Contains(string(ca), "PRIVATE KEY") {
		t.Fatal("only the public, readable CA should be published")
	}
	return s, roots
}

func TestTrustedTLSRelaysExactMessage(t *testing.T) {
	relay, messages, _ := smtpSink(t)
	s, roots := testFixture(t, relay)
	httpClient := &http.Client{Timeout: 2 * time.Second}
	response, err := httpClient.Get("http://" + s.health.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("fixture did not become ready")
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.smtp.Addr().String(), &tls.Config{RootCAs: roots, ServerName: fixtureHost, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	client, err := smtp.NewClient(c, fixtureHost)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Mail("owner@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := client.Rcpt("external@example.org"); err == nil {
		t.Fatal("fixture accepted an external recipient")
	}
	recipients := []string{"sales-customer-123@example.test", "sales-provider-456@example.test"}
	for _, address := range recipients {
		if err := client.Rcpt(address); err != nil {
			t.Fatal(err)
		}
	}
	body := "From: owner@example.test\r\nTo: sales-customer-123@example.test\r\nSubject: Fixture\r\n\r\nSvenska: åäö\r\n.\r\n..two dots\r\n<html><p>Exact HTML</p></html>\r\n"
	w, err := client.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(w, body); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = client.Quit(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-messages:
		if got.from != "owner@example.test" || !reflect.DeepEqual(got.to, recipients) || got.body != body {
			t.Fatal("SMTP envelope or byte-exact body changed in transit")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("message was not delivered to the owned sink")
	}
}

func TestUntrustedOrWrongHostnameCannotDeliver(t *testing.T) {
	for _, kind := range []string{"untrusted CA", "wrong hostname"} {
		t.Run(kind, func(t *testing.T) {
			relay, _, accepted := smtpSink(t)
			s, roots := testFixture(t, relay)
			cfg := &tls.Config{RootCAs: roots, ServerName: fixtureHost, MinVersion: tls.VersionTLS12}
			if kind == "untrusted CA" {
				cfg.RootCAs = x509.NewCertPool()
			} else {
				cfg.ServerName = "wrong.hash.test"
			}
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.smtp.Addr().String(), cfg)
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Fatal("TLS verification unexpectedly succeeded")
			}
			s.Close()
			if accepted.Load() != 0 {
				t.Fatal("a refused TLS connection reached the SMTP sink")
			}
		})
	}
}

func TestCloseJoinsIdleConnections(t *testing.T) {
	s, _ := testFixture(t, "127.0.0.1:1")
	c, err := net.DialTimeout("tcp", s.smtp.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan struct{})
	go func() { s.Close(); s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture did not join its owned listeners and connections")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle connection remained open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("idle connection was not closed")
	}
}
