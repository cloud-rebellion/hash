// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/bright-interaction/hash/internal/ordinarypage"
)

var ErrOrdinaryPageUnavailable = errors.New("ordinary PDF preparation unavailable")

// ordinaryPageFailureV1 keeps caller cancellation identity available without
// printing private cancellation causes, endpoint URLs, tokens or field values.
type ordinaryPageFailureV1 struct{ causes []error }

func (*ordinaryPageFailureV1) Error() string     { return ErrOrdinaryPageUnavailable.Error() }
func (e *ordinaryPageFailureV1) Unwrap() []error { return append([]error(nil), e.causes...) }

func ordinaryPageErrorV1(ctx context.Context, cause error) error {
	causes := []error{ErrOrdinaryPageUnavailable, ordinarypage.ErrUnavailableV1}
	if ctx != nil && ctx.Err() != nil {
		causes = append(causes, ctx.Err())
		if private := context.Cause(ctx); private != nil && private != ctx.Err() {
			causes = append(causes, private)
		}
	} else {
		for _, known := range []error{context.Canceled, context.DeadlineExceeded} {
			if errors.Is(cause, known) {
				causes = append(causes, known)
			}
		}
	}
	return &ordinaryPageFailureV1{causes: causes}
}

// PrepareOrdinaryPageV1 makes one authenticated private POST for the exact
// captured ordinary fields, source page and owned ordinary recipe. It uses the
// existing fitting credential/transport/concurrency gate, never generic HTML.
// A successful package is integrity/layout consistency, not genuine renderer,
// strict isolated PDF admission, source authority, durable originals or Sign.
//
// Caller must own whole-request global working-memory/tenant admission BEFORE
// entering: cloned plan, encoded request, bounded frame, decoded report/sections
// and caller copies still consume resources. The encoded request is erased under
// its Read/Close mutex before this method returns, including on cancellation.
// This is client-frame quiescence only; transport-wide and remote renderer work
// need independent global-coordinator retirement. g.sem bounds fan-in only;
// it does not prove whole-process memory or the all-party processing/ZIP budget.
func (g *Gotenberg) PrepareOrdinaryPageV1(ctx context.Context, expected ordinarypage.PlanV1) (*ordinarypage.PackageV1, error) {
	if ctx == nil || g == nil || !validSignatureFitToken(g.fitToken) {
		return nil, ordinaryPageErrorV1(ctx, nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	own, err := ordinarypage.ClonePlanV1(expected)
	if err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	expected = own
	u, err := url.Parse(g.BaseURL)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		(u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, ordinaryPageErrorV1(ctx, nil)
	}
	u.Path = ordinarypage.RoutePathV1
	u.RawPath = ""
	client, err := signatureFitHTTPClient(g.HTTP)
	if err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	defer client.CloseIdleConnections()
	if g.sem != nil {
		select {
		case g.sem <- struct{}{}:
			defer func() { <-g.sem }()
		case <-ctx.Done():
			return nil, ordinaryPageErrorV1(ctx, ctx.Err())
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	// The fixed embedded Inter bytes are immutable; EncodeRequest verifies their
	// exact length/hash. No user-supplied font or arbitrary branding CSS is sent.
	body, err := ordinarypage.EncodeRequestV1(expected, fontInter)
	if err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	bodyBytes := int64(len(body))
	ownedBody := newOwnedRequestBodyV1(body)
	body = nil
	defer ownedBody.Close()
	if err := ctx.Err(); err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), ownedBody)
	if err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	req.ContentLength = bodyBytes
	req.GetBody = nil // Opaque private POST frames must never be replayed automatically.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", ordinarypage.MediaTypeV1)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Authorization", "Bearer "+g.fitToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(resp.Header.Values("Content-Type")) != 1 || resp.Header.Get("Content-Type") != ordinarypage.MediaTypeV1 ||
		len(resp.Header.Values("Content-Encoding")) != 0 || resp.Uncompressed || resp.ContentLength > int64(ordinarypage.MaxPackageBytesV1) {
		return nil, ordinaryPageErrorV1(ctx, nil)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(ordinarypage.MaxPackageBytesV1)+1))
	defer clear(raw)
	if err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	if len(raw) > ordinarypage.MaxPackageBytesV1 {
		return nil, ordinaryPageErrorV1(ctx, nil)
	}
	pkg, err := ordinarypage.DecodeWithContextV1(ctx, raw, expected)
	if err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, ordinaryPageErrorV1(ctx, err)
	}
	return pkg, nil
}
