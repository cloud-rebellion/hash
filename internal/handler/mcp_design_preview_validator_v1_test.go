// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/sanitize"
)

func TestValidMCPDesignPreviewV1Boundaries(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	good := mcp.DesignActorV1{Actor: authoring.Actor{OrgID: uuid.New(), UserID: uuid.New()}, KeyID: uuid.New()}
	type in struct {
		a                 mcp.DesignActorV1
		id                uuid.UUID
		version           int32
		content, mat, pdf string
		pages             int
	}
	base := in{good, uuid.New(), 1, sha, sha, sha, 1}
	with := func(f func(*in)) in { c := base; f(&c); return c }
	cases := []struct {
		name string
		in   in
		ok   bool
	}{
		{"baseline", base, true},
		{"nil key", with(func(c *in) { c.a.KeyID = uuid.Nil }), false},
		{"nil org", with(func(c *in) { c.a.OrgID = uuid.Nil }), false},
		{"nil user", with(func(c *in) { c.a.UserID = uuid.Nil }), false},
		{"nil template", with(func(c *in) { c.id = uuid.Nil }), false},
		{"version 0", with(func(c *in) { c.version = 0 }), false},
		{"version -1", with(func(c *in) { c.version = -1 }), false},
		{"version min int32", with(func(c *in) { c.version = -1 << 31 }), false},
		{"version max int32", with(func(c *in) { c.version = 1<<31 - 1 }), true},
		{"pages 0", with(func(c *in) { c.pages = 0 }), false},
		{"pages -1", with(func(c *in) { c.pages = -1 }), false},
		{"pages max", with(func(c *in) { c.pages = sanitize.MaxPDFPages }), true},
		{"pages max+1", with(func(c *in) { c.pages = sanitize.MaxPDFPages + 1 }), false},
		{"content empty", with(func(c *in) { c.content = "" }), false},
		{"content uppercase", with(func(c *in) { c.content = strings.ToUpper(sha) }), false},
		{"content 63", with(func(c *in) { c.content = sha[:63] }), false},
		{"content 65", with(func(c *in) { c.content = sha + "a" }), false},
		{"content non-hex", with(func(c *in) { c.content = strings.Repeat("zz", 32) }), false},
		{"content unicode 64 bytes", with(func(c *in) { c.content = strings.Repeat("é", 32) }), false},
		{"material uppercase", with(func(c *in) { c.mat = strings.ToUpper(sha) }), false},
		{"material empty", with(func(c *in) { c.mat = "" }), false},
		{"pdf 63", with(func(c *in) { c.pdf = sha[:63] }), false},
		{"pdf non-hex", with(func(c *in) { c.pdf = strings.Repeat("g", 64) }), false},
		{"digits only sha", with(func(c *in) {
			c.content, c.mat, c.pdf = strings.Repeat("0", 64), strings.Repeat("9", 64), strings.Repeat("1", 64)
		}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.in
			got := validMCPDesignPreviewV1(c.a, c.id, c.version, c.content, c.mat, c.pdf, c.pages)
			if (got == nil) != tc.ok || (got != nil && !errors.Is(got, errHTMLTemplatePreviewReceipt)) {
				t.Fatalf("got %v, want ok=%v", got, tc.ok)
			}
		})
	}
}

func TestMCPPreviewContextErrReportsTimeoutNotReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	err := mcpPreviewContextErr(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errHTMLTemplatePreviewReceipt) {
		t.Fatalf("got %v, want context deadline exceeded", err)
	}
	if got := safeMCPDesignFailureV1(err); !errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("agent sees %v, want deadline exceeded", got)
	}
}
