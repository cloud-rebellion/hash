// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// workspace-smtp is an isolated browser-test fixture, never a production relay.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const fixtureHost = "smtp.hash.test"

type config struct{ smtpAddr, healthAddr, relayAddr, caPath string }

type fixtureServer struct {
	smtp, health net.Listener
	http         *http.Server
	relay        string
	mu           sync.Mutex
	closing      bool
	connections  map[net.Conn]struct{}
	workers      sync.WaitGroup
	once         sync.Once
	slots        chan struct{}
}

func main() {
	s, err := startFixture(config{":465", ":8080", "mailhog:1025", "/trust/ca.pem"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "workspace SMTP fixture startup failed")
		os.Exit(1)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	signal.Stop(stop)
	s.Close()
}

func startFixture(c config) (*fixtureServer, error) {
	cert, ca, err := ephemeralCertificate()
	if err != nil {
		return nil, err
	}
	smtpListener, err := tls.Listen("tcp", c.smtpAddr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, err
	}
	health, err := net.Listen("tcp", c.healthAddr)
	if err != nil {
		smtpListener.Close()
		return nil, err
	}
	if err = publishCA(c.caPath, ca); err != nil {
		smtpListener.Close()
		health.Close()
		return nil, err
	}
	s := &fixtureServer{smtp: smtpListener, health: health, relay: c.relayAddr, connections: make(map[net.Conn]struct{}), slots: make(chan struct{}, 16)}
	s.http = &http.Server{ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ready\n")
	})}
	s.workers.Add(2)
	go func() { defer s.workers.Done(); _ = s.http.Serve(health) }()
	go s.accept()
	return s, nil
}

// Close unblocks every owned connection and joins all fixture handlers.
func (s *fixtureServer) Close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.smtp.Close()
		for c := range s.connections {
			c.Close()
		}
		s.mu.Unlock()
		s.http.Close()
		s.workers.Wait()
	})
}

func (s *fixtureServer) accept() {
	defer s.workers.Done()
	for {
		c, err := s.smtp.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			c.Close()
			return
		}
		select {
		case s.slots <- struct{}{}:
			s.connections[c] = struct{}{}
			s.workers.Add(1)
			go func() {
				defer s.workers.Done()
				defer func() { c.Close(); s.mu.Lock(); delete(s.connections, c); s.mu.Unlock(); <-s.slots }()
				s.session(c)
			}()
		default:
			c.Close()
		}
		s.mu.Unlock()
	}
}

func (s *fixtureServer) session(c net.Conn) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := c.(*tls.Conn).Handshake(); err != nil {
		return
	}
	r := bufio.NewReaderSize(c, 64*1024)
	reply := func(v string) { _, _ = io.WriteString(c, v+"\r\n") }
	reply("220 " + fixtureHost + " test fixture")
	var from string
	var recipients []string
	greeted, hasSender := false, false
	for command := 0; command < 100; command++ {
		c.SetDeadline(time.Now().Add(15 * time.Second))
		line, err := readLine(r, 4096)
		if err != nil {
			return
		}
		v := string(line[:len(line)-2])
		verb, arg, _ := strings.Cut(v, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			greeted, hasSender, recipients = true, false, nil
			reply("250-" + fixtureHost + "\r\n250 8BITMIME")
		case "MAIL":
			address, ok := envelope(arg, "FROM:", true)
			if !greeted || !ok {
				reply("503 invalid sender or sequence")
				continue
			}
			from, hasSender, recipients = address, true, nil
			reply("250 sender accepted")
		case "RCPT":
			address, ok := envelope(arg, "TO:", false)
			domain := address[strings.LastIndexByte(address, '@')+1:]
			if !hasSender || !ok || domain != "example.test" || len(recipients) >= 16 {
				reply("550 test recipients only")
				continue
			}
			recipients = append(recipients, address)
			reply("250 recipient accepted")
		case "DATA":
			if !hasSender || len(recipients) == 0 || arg != "" {
				reply("503 sender and recipient required")
				continue
			}
			reply("354 end with a dot on its own line")
			c.SetDeadline(time.Now().Add(30 * time.Second))
			body, err := readMessage(r)
			if err != nil {
				reply("552 invalid or oversized test message")
				return
			}
			if err = s.deliver(from, recipients, body); err != nil {
				reply("451 test sink unavailable")
			} else {
				reply("250 delivered to test sink")
			}
			hasSender, recipients = false, nil
		case "RSET":
			hasSender, recipients = false, nil
			reply("250 reset")
		case "NOOP":
			reply("250 ok")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unsupported command")
		}
	}
}

func envelope(arg, prefix string, allowEmpty bool) (string, bool) {
	if len(arg) < len(prefix) || !strings.EqualFold(arg[:len(prefix)], prefix) {
		return "", false
	}
	v := strings.TrimSpace(arg[len(prefix):])
	end := strings.IndexByte(v, '>')
	if !strings.HasPrefix(v, "<") || end < 1 {
		return "", false
	}
	address := v[1:end]
	if address == "" {
		return address, allowEmpty
	}
	parsed, err := mail.ParseAddress(address)
	return address, err == nil && parsed.Address == address && !strings.ContainsAny(address, "\r\n")
}

func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err != nil || len(line) > limit || !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, errors.New("invalid SMTP line")
	}
	return line, nil
}

func readMessage(r *bufio.Reader) ([]byte, error) {
	var body bytes.Buffer
	for {
		line, err := readLine(r, 64*1024)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(line, []byte(".\r\n")) {
			return body.Bytes(), nil
		}
		if line[0] == '.' {
			line = line[1:]
		}
		if body.Len()+len(line) > 2*1024*1024 {
			return nil, errors.New("test message too large")
		}
		body.Write(line)
	}
}

func (s *fixtureServer) deliver(from string, recipients []string, body []byte) error {
	c, err := net.DialTimeout("tcp", s.relay, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return errors.New("fixture is closing")
	}
	s.connections[c] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	client, err := smtp.NewClient(c, "mailhog")
	if err != nil {
		return err
	}
	defer client.Close()
	if err = client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err = client.Rcpt(recipient); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err = w.Write(body); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func ephemeralCertificate() (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Hash browser fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{fixtureHost}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), err
}

func publishCA(path string, ca []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".ca-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0644); err != nil {
		return err
	}
	if _, err = f.Write(ca); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
