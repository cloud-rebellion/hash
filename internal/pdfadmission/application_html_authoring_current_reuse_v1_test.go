// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

// Selection tests alone confer no native reader/admission authority. The owned
// PG regression also checks real copy loans, one-shot delivery and retirement.
func TestHTMLAuthoringCurrentReuseRequiresDeliveredExactRetainedSourceV1(t *testing.T) {
	id := uuid.New()
	current := htmlAuthoringCanonicalSourceV1{id: id, version: 5, digestValid: true, master: []byte("master"), defaults: []byte("defaults"), started: true}
	current.digest[0] = 7
	retained := current
	retained.revision = true
	retained.ready, retained.delivered = true, true
	retained.purpose = htmlStoredTemplatePreparationV1
	tests := []struct {
		name   string
		change func(*htmlAuthoringCanonicalSourceV1, *htmlAuthoringCanonicalSourceV1)
		want   bool
	}{
		{"preparation-to-current", func(_, _ *htmlAuthoringCanonicalSourceV1) {}, true},
		{"recheck-to-current", func(_, r *htmlAuthoringCanonicalSourceV1) { r.purpose = htmlStoredTemplateRecheckV1 }, true},
		{"other-id", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.id = uuid.New() }, false},
		{"nil-id", func(c, r *htmlAuthoringCanonicalSourceV1) { c.id, r.id = uuid.Nil, uuid.Nil }, false},
		{"other-version", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.version++ }, false},
		{"zero-version", func(c, r *htmlAuthoringCanonicalSourceV1) { c.version, r.version = 0, 0 }, false},
		{"other-digest", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.digest[0]++ }, false},
		{"current-invalid-digest", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.digestValid = false }, false},
		{"retained-invalid-digest", func(_, r *htmlAuthoringCanonicalSourceV1) { r.digestValid = false }, false},
		{"other-master-bytes", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.master = append(c.master, ' ') }, false},
		{"other-default-bytes", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.defaults = append(c.defaults, ' ') }, false},
		{"current-not-started", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.started = false }, false},
		{"current-ready", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.ready = true }, false},
		{"current-delivered", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.delivered = true }, false},
		{"retained-not-started", func(_, r *htmlAuthoringCanonicalSourceV1) { r.started = false }, false},
		{"retained-not-ready", func(_, r *htmlAuthoringCanonicalSourceV1) { r.ready = false }, false},
		{"retained-not-delivered", func(_, r *htmlAuthoringCanonicalSourceV1) { r.delivered = false }, false},
		{"current-cannot-grant-retained", func(c, _ *htmlAuthoringCanonicalSourceV1) { c.revision = true }, false},
		{"current-cannot-be-retained-producer", func(_, r *htmlAuthoringCanonicalSourceV1) { r.revision = false }, false},
		{"lower-purpose", func(_, r *htmlAuthoringCanonicalSourceV1) { r.purpose = htmlStoredTemplateCurrentV1 }, false},
		{"unknown-purpose", func(_, r *htmlAuthoringCanonicalSourceV1) { r.purpose = htmlStoredTemplatePreparationV1 + 1 }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, r := current, retained
			c.master, c.defaults = bytes.Clone(current.master), bytes.Clone(current.defaults)
			r.master, r.defaults = bytes.Clone(retained.master), bytes.Clone(retained.defaults)
			test.change(&c, &r)
			if got := htmlAuthoringCurrentCanReuseRetainedV1(&c, &r); got != test.want {
				t.Fatalf("current-only exact retained reuse=%v want=%v", got, test.want)
			}
		})
	}
	if htmlAuthoringCurrentCanReuseRetainedV1(nil, &retained) || htmlAuthoringCurrentCanReuseRetainedV1(&current, nil) || htmlAuthoringCurrentCanReuseRetainedV1(&current, &current) {
		t.Fatal("missing or self producer granted reuse")
	}
	// The existing same-view predicate remains closed for retained preparation.
	if htmlAuthoringCanonicalSameV1(&current, &retained) {
		t.Fatal("cross-view optimization widened retained preparation authority")
	}
}
