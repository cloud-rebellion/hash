//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// All keys are generated per selected test and remain in memory. The browser
// receives only the leaf public-key pin; native outbound TLS trusts this CA
// with ordinary chain/hostname checks, never InsecureSkipVerify.
func oidc439TLS() (tls.Certificate, *x509.CertPool, string, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Owned OIDC439 test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Owned OIDC439 loopback"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, leafKey.Public(), caKey)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(leafKey.Public())
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	pin := sha256.Sum256(publicDER)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}, roots, base64.StdEncoding.EncodeToString(pin[:]), nil
}

type oidc439Grant struct{ state, nonce, challenge string }
type oidc439ProviderCounts struct {
	Discovery         int  `json:"discovery"`
	Authorize         int  `json:"authorize"`
	Accept            int  `json:"accept"`
	Token             int  `json:"token"`
	JWKS              int  `json:"jwks"`
	Faults            int  `json:"faults"`
	PendingTickets    int  `json:"pending_tickets"`
	PendingCodes      int  `json:"pending_codes"`
	DistinctHandshake bool `json:"distinct_handshake"`
}
type oidc439Provider struct {
	mu                                         sync.Mutex
	issuer, callback, clientID, subject, email string
	key                                        *ecdsa.PrivateKey
	tickets, codes                             map[string]oidc439Grant
	seenNonce, seenState, seenChallenge        map[string]bool
	counts                                     oidc439ProviderCounts
}

func newOIDC439Provider(issuer, callback, email string) (*oidc439Provider, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	subject, err := oidc439Random()
	if err != nil {
		return nil, err
	}
	return &oidc439Provider{issuer: issuer, callback: callback, clientID: "owned-oidc439-public-client", subject: subject, email: email, key: key, tickets: make(map[string]oidc439Grant), codes: make(map[string]oidc439Grant), seenNonce: make(map[string]bool), seenState: make(map[string]bool), seenChallenge: make(map[string]bool)}, nil
}
func oidc439Random() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
func (p *oidc439Provider) reject(w http.ResponseWriter) {
	p.mu.Lock()
	p.counts.Faults++
	p.mu.Unlock()
	http.Error(w, "owned issuer request refused", http.StatusBadRequest)
}
func oidc439One(v url.Values, key string) (string, bool) {
	x := v[key]
	return v.Get(key), len(x) == 1 && x[0] != ""
}
func oidc439Keys(v url.Values, allowed ...string) bool {
	for key, values := range v {
		found := false
		for _, want := range allowed {
			if key == want {
				found = true
			}
		}
		if !found || len(values) != 1 {
			return false
		}
	}
	return true
}
func (p *oidc439Provider) snapshot() oidc439ProviderCounts {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.counts
	out.PendingTickets, out.PendingCodes = len(p.tickets), len(p.codes)
	out.DistinctHandshake = len(p.seenNonce) == 3 && len(p.seenState) == 3 && len(p.seenChallenge) == 3
	return out
}
func (p *oidc439Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	issuer, _ := url.Parse(p.issuer)
	if r.TLS == nil || r.Host != issuer.Host || len(r.URL.RawQuery) > 4096 {
		p.reject(w)
		return
	}
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			p.reject(w)
			return
		}
		p.mu.Lock()
		p.counts.Discovery++
		n := p.counts.Discovery
		p.mu.Unlock()
		if n != 1 {
			p.reject(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.issuer, "authorization_endpoint": p.issuer + "/authorize", "token_endpoint": p.issuer + "/token", "jwks_uri": p.issuer + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"ES256"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "none"}})
	case "/favicon.ico":
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			p.reject(w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "/authorize":
		p.authorize(w, r)
	case "/authorize/accept":
		p.accept(w, r)
	case "/token":
		p.token(w, r)
	case "/jwks":
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			p.reject(w)
			return
		}
		p.mu.Lock()
		p.counts.JWKS++
		n := p.counts.JWKS
		p.mu.Unlock()
		if n > 2 {
			p.reject(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": "owned439", "x": base64.RawURLEncoding.EncodeToString(p.key.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(p.key.Y.FillBytes(make([]byte, 32)))}}})
	default:
		p.reject(w)
	}
}
func (p *oidc439Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if r.Method != http.MethodGet || err != nil || !oidc439Keys(q, "client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method") {
		p.reject(w)
		return
	}
	state, sok := oidc439One(q, "state")
	nonce, nok := oidc439One(q, "nonce")
	challenge, cok := oidc439One(q, "code_challenge")
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(challenge)
	if !sok || !nok || !cok || len(state) > 128 || len(nonce) > 128 || len(state) < 20 || len(nonce) < 20 || decodeErr != nil || len(decoded) != 32 || q.Get("client_id") != p.clientID || q.Get("redirect_uri") != p.callback || q.Get("response_type") != "code" || q.Get("scope") != "openid profile email" || q.Get("code_challenge_method") != "S256" {
		p.reject(w)
		return
	}
	ticket, err := oidc439Random()
	if err != nil {
		p.reject(w)
		return
	}
	p.mu.Lock()
	if p.counts.Authorize >= 3 || p.seenState[state] || p.seenNonce[nonce] || p.seenChallenge[challenge] {
		p.mu.Unlock()
		p.reject(w)
		return
	}
	p.counts.Authorize++
	p.seenState[state], p.seenNonce[nonce], p.seenChallenge[challenge] = true, true, true
	p.tickets[ticket] = oidc439Grant{state: state, nonce: nonce, challenge: challenge}
	p.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self' "+p.callback+"; base-uri 'none'; frame-ancestors 'none'")
	_, _ = w.Write([]byte("<!doctype html><html><head><title>Owned test identity</title><meta name=viewport content=\"width=device-width, initial-scale=1\"></head><body><h1>Owned test identity</h1><form method=post action=/authorize/accept><input type=hidden name=ticket value=\"" + html.EscapeString(ticket) + "\"><button type=submit>Continue with invited identity</button></form></body></html>"))
}
func (p *oidc439Provider) accept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		p.reject(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if r.ParseForm() != nil || !oidc439Keys(r.PostForm, "ticket") {
		p.reject(w)
		return
	}
	ticket, ok := oidc439One(r.PostForm, "ticket")
	if !ok {
		p.reject(w)
		return
	}
	code, err := oidc439Random()
	if err != nil {
		p.reject(w)
		return
	}
	p.mu.Lock()
	grant, found := p.tickets[ticket]
	if !found || p.counts.Accept >= 3 {
		p.mu.Unlock()
		p.reject(w)
		return
	}
	delete(p.tickets, ticket)
	p.codes[code] = grant
	p.counts.Accept++
	p.mu.Unlock()
	callback, _ := url.Parse(p.callback)
	callback.RawQuery = url.Values{"code": {code}, "state": {grant.state}}.Encode()
	http.Redirect(w, r, callback.String(), http.StatusSeeOther)
}
func (p *oidc439Provider) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		p.reject(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ParseForm() != nil || !oidc439Keys(r.PostForm, "grant_type", "code", "redirect_uri", "code_verifier", "client_id") {
		p.reject(w)
		return
	}
	client, secret, basic := r.BasicAuth()
	if basic {
		if secret != "" || r.PostForm.Get("client_id") != "" {
			p.reject(w)
			return
		}
	} else {
		client = r.PostForm.Get("client_id")
	}
	code, cok := oidc439One(r.PostForm, "code")
	verifier, vok := oidc439One(r.PostForm, "code_verifier")
	if client != p.clientID || !cok || !vok || len(verifier) < 43 || len(verifier) > 128 || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != p.callback {
		p.reject(w)
		return
	}
	challenge := sha256.Sum256([]byte(verifier))
	p.mu.Lock()
	grant, found := p.codes[code]
	if !found || p.counts.Token >= 3 {
		p.mu.Unlock()
		p.reject(w)
		return
	}
	delete(p.codes, code)
	if base64.RawURLEncoding.EncodeToString(challenge[:]) != grant.challenge {
		p.mu.Unlock()
		p.reject(w)
		return
	}
	p.counts.Token++
	p.mu.Unlock()
	idToken, err := p.idToken(grant.nonce)
	if err != nil {
		p.reject(w)
		return
	}
	accessToken, err := oidc439Random()
	if err != nil {
		p.reject(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 120, "id_token": idToken})
}
func (p *oidc439Provider) idToken(nonce string) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "owned439"})
	now := time.Now().Unix()
	claims, err := json.Marshal(map[string]any{"iss": p.issuer, "sub": p.subject, "aud": p.clientID, "iat": now, "exp": now + 120, "nonce": nonce, "email": strings.ToUpper(p.email), "email_verified": true, "name": "Controlled provider display name"})
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(body))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, digest[:])
	if err != nil {
		return "", err
	}
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return "", errors.New("invalid owned issuer signature")
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return body + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
