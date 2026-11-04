// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func smtpSyntheticTLS730(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(730), Subject: pkix.Name{CommonName: "smtp.example.invalid"}, DNSNames: []string{"smtp.example.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool.AddCert(leaf)
	return cert, pool
}

// Both SMTP modes run over net.Pipe, never a host socket or external server.
func TestWorkspaceSMTPVerifiedTLSModes730(t *testing.T) {
	cert, roots := smtpSyntheticTLS730(t)
	for _, mode := range []string{"starttls", "tls"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				_ = server.SetDeadline(time.Now().Add(4 * time.Second))
				conn := server
				secure := func() error {
					v := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
					if e := v.Handshake(); e != nil {
						return e
					}
					conn = v
					return nil
				}
				if mode == "tls" {
					if e := secure(); e != nil {
						done <- e
						return
					}
				}
				rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
				reply := func(v string) error {
					_, e := rw.WriteString(v + "\r\n")
					if e != nil {
						return e
					}
					return rw.Flush()
				}
				if e := reply("220 synthetic SMTP"); e != nil {
					done <- e
					return
				}
				activeTLS := mode == "tls"
				accepted := false
				for {
					line, e := rw.ReadString('\n')
					if e != nil {
						done <- e
						return
					}
					line = strings.TrimSpace(line)
					switch {
					case strings.HasPrefix(line, "EHLO "):
						if activeTLS {
							e = reply("250-synthetic\r\n250 AUTH PLAIN")
						} else {
							e = reply("250-synthetic\r\n250 STARTTLS")
						}
					case line == "STARTTLS":
						e = reply("220 begin TLS")
						if e == nil {
							e = secure()
							activeTLS = e == nil
							rw = bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
						}
					case strings.HasPrefix(line, "AUTH PLAIN "):
						if !activeTLS {
							done <- fmt.Errorf("auth before TLS")
							return
						}
						e = reply("235 authenticated")
					case strings.HasPrefix(line, "MAIL FROM:"):
						if !activeTLS {
							done <- fmt.Errorf("message before TLS")
							return
						}
						e = reply("250 sender")
					case strings.HasPrefix(line, "RCPT TO:"):
						e = reply("250 recipient")
					case line == "DATA":
						e = reply("354 data")
						if e == nil {
							for {
								part, readErr := rw.ReadString('\n')
								if readErr != nil {
									e = readErr
									break
								}
								if part == ".\r\n" {
									break
								}
							}
						}
						if e == nil {
							accepted = true
							e = reply("250 accepted")
						}
					case line == "QUIT":
						if !accepted {
							done <- fmt.Errorf("no accepted DATA")
							return
						}
						_ = reply("221 bye")
						done <- nil
						return
					default:
						e = fmt.Errorf("unexpected synthetic SMTP command")
					}
					if e != nil {
						done <- e
						return
					}
				}
			}()
			port := 587
			if mode == "tls" {
				port = 465
			}
			m, e := NewSMTPMailer(SMTPConfig{Host: "smtp.example.invalid", Port: port, TLSMode: mode, User: "synthetic", Password: "synthetic", From: "Sender <sender@example.invalid>", PublicOnly: true})
			if e != nil {
				t.Fatal(e)
			}
			m.dialContext = func(context.Context, string, string) (net.Conn, error) { return client, nil }
			m.tlsConfig = &tls.Config{ServerName: "smtp.example.invalid", RootCAs: roots, MinVersion: tls.VersionTLS12}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if e = m.Send(ctx, Message{To: "owner@example.invalid", Subject: "Synthetic", Text: "Synthetic SMTP test"}); e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestWorkspaceSMTPImplicitTLSRefusesUntrustedCertificate730(t *testing.T) {
	cert, _ := smtpSyntheticTLS730(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		v := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		_ = v.Handshake()
		_ = v.Close()
	}()
	m, e := NewSMTPMailer(SMTPConfig{Host: "smtp.example.invalid", Port: 465, TLSMode: "tls", From: "sender@example.invalid", PublicOnly: true})
	if e != nil {
		t.Fatal(e)
	}
	m.dialContext = func(context.Context, string, string) (net.Conn, error) { return client, nil }
	m.tlsConfig = &tls.Config{ServerName: "smtp.example.invalid", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = m.Send(ctx, Message{To: "owner@example.invalid", Subject: "Synthetic", Text: "Synthetic"}); e == nil {
		t.Fatal("untrusted certificate accepted")
	}
	<-done
}
