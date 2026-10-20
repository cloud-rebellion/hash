// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/bright-interaction/hash/internal/signaturefit"
)

var ErrSignatureFitUnavailable = errors.New("signature PDF preparation unavailable")

// NewGotenbergWithSignatureFitToken configures the private preparation route.
// Empty means unconfigured; it never enables a fallback to generic HTML. The
// same startup credential must be provisioned to the private renderer. This
// constructor does not activate a signing policy or change historical reads.
func NewGotenbergWithSignatureFitToken(baseURL, token string) (*Gotenberg, error) {
	if token != "" && !validSignatureFitToken(token) {
		return nil, errors.New("invalid private signature renderer credential")
	}
	g := NewGotenberg(baseURL)
	g.fitToken = token
	return g, nil
}

func validSignatureFitToken(token string) bool {
	if len(token) < 32 || len(token) > 128 {
		return false
	}
	for i := range token {
		if token[i] < 0x21 || token[i] > 0x7e {
			return false
		}
	}
	return true
}

func fitPreparationError(err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %w", ErrSignatureFitUnavailable, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrSignatureFitUnavailable, context.DeadlineExceeded)
	}
	return ErrSignatureFitUnavailable
}

func bundledSignatureFitFont(name string) ([]byte, error) {
	f, ok := signaturefit.Font(name)
	if !ok {
		return nil, ErrSignatureFitUnavailable
	}
	var raw []byte
	switch name {
	case "Caveat":
		raw = fontCaveat
	case "Dancing Script":
		raw = fontDancingScript
	case "Great Vibes":
		raw = fontGreatVibes
	case "Sacramento":
		raw = fontSacramento
	case "Homemade Apple":
		raw = fontHomemadeApple
	default:
		return nil, ErrSignatureFitUnavailable
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != f.SHA256 {
		return nil, ErrSignatureFitUnavailable
	}
	return bytes.Clone(raw), nil
}

// signatureFitHTTPClient keeps proxy, cookie, redirect and compression policy
// separate from the general converter. The request context bounds the whole
// operation, including semaphore admission and reading the response body.
func signatureFitHTTPClient(configured *http.Client) (*http.Client, error) {
	client := http.Client{}
	var transport *http.Transport
	if configured != nil {
		client = *configured
		if configured.Transport != nil {
			var ok bool
			transport, ok = configured.Transport.(*http.Transport)
			if !ok {
				return nil, ErrSignatureFitUnavailable
			}
		}
	}
	if transport == nil {
		var ok bool
		transport, ok = http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, ErrSignatureFitUnavailable
		}
	}
	transport = transport.Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	client.Transport = transport
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client, nil
}

// PrepareManualSignaturePageV1 makes one authenticated, bounded request for a
// single source page's COMPLETE captured target set. The caller constructs the
// expected plan from authoritative objects/geometry, then rebinds all targets
// under the signing lock. This method validates package integrity; isolated
// PDF admission, durable selection/retention and final signing are separate.
// The encoded request is synchronously erased before return, including cancel.
// This owns only the client frame; transport-wide/remote renderer retirement
// and whole-process admission remain separate global-coordinator gates.
func (g *Gotenberg) PrepareManualSignaturePageV1(ctx context.Context, expected signaturefit.Plan) (*signaturefit.Package, error) {
	if g == nil || !validSignatureFitToken(g.fitToken) || signaturefit.ValidatePlan(expected) != nil {
		return nil, ErrSignatureFitUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, fitPreparationError(err)
	}
	// Capture owned slices before a network wait, never hand caller buffers to
	// the request or use them as a mutable expected-plan authority afterward.
	expected.Targets = append([]signaturefit.Target(nil), expected.Targets...)
	u, err := url.Parse(g.BaseURL)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		(u.Scheme != "http" && u.Scheme != "https") ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, ErrSignatureFitUnavailable
	}
	u.Path = signaturefit.RoutePath
	u.RawPath = ""
	font, err := bundledSignatureFitFont(expected.Font)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(signaturefit.Request{Schema: 1, Plan: expected, FontBytes: font})
	if err != nil {
		return nil, ErrSignatureFitUnavailable
	}
	bodyBytes := int64(len(body))
	ownedBody := newOwnedRequestBodyV1(body)
	body = nil
	defer ownedBody.Close()
	if bodyBytes > signaturefit.MaxRequestBytes {
		return nil, ErrSignatureFitUnavailable
	}
	client, err := signatureFitHTTPClient(g.HTTP)
	if err != nil {
		return nil, err
	}
	// Each clone owns its connections and cannot leave an idle credentialed
	// connection pool behind after a canceled or refused preparation.
	defer client.CloseIdleConnections()
	if g.sem != nil {
		select {
		case g.sem <- struct{}{}:
			defer func() { <-g.sem }()
		case <-ctx.Done():
			return nil, fitPreparationError(ctx.Err())
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fitPreparationError(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), ownedBody)
	if err != nil {
		return nil, ErrSignatureFitUnavailable
	}
	req.ContentLength = bodyBytes
	req.GetBody = nil // Opaque private POST frames must never be replayed automatically.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", signaturefit.MediaType)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Authorization", "Bearer "+g.fitToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fitPreparationError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != signaturefit.MediaType ||
		resp.Header.Get("Content-Encoding") != "" || resp.Uncompressed ||
		resp.ContentLength > int64(signaturefit.MaxPackageBytes) {
		return nil, ErrSignatureFitUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(signaturefit.MaxPackageBytes)+1))
	if err != nil {
		return nil, fitPreparationError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fitPreparationError(err)
	}
	if len(raw) > signaturefit.MaxPackageBytes {
		return nil, ErrSignatureFitUnavailable
	}
	pkg, err := signaturefit.Decode(raw, expected)
	if err != nil {
		return nil, ErrSignatureFitUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, fitPreparationError(err)
	}
	return pkg, nil
}
