// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"math"
	"testing"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
)

// Cache-selection arithmetic tests confer no native session/admission authority.
// The paired actual PG journey proves production constructors and consumers.
func TestHTMLAuthoringPreparedReuseExactPrivateSourcesV1(t *testing.T) {
	id := uuid.New()
	digest := bytes.Repeat([]byte{7}, 32)
	first := htmlAuthoringCanonicalSourceV1{id: id, version: 1, revision: true, digestValid: true, master: []byte("{\"html\":\"original\"}"), defaults: []byte("{}"), ready: true, delivered: true, content: htmlmaster.TemplateCommitment{MasterJSON: []byte("canonical"), DefaultsJSON: []byte("{}"), SHA256: "approved"}, prepared: &htmlAuthoringPreparedRetainedTemplateV1{defaults: map[string]string{"customer": "original"}}}
	copy(first.digest[:], digest)
	tests := []struct {
		name   string
		change func(*htmlAuthoringCanonicalSourceV1)
		reuse  bool
	}{
		{"same", func(*htmlAuthoringCanonicalSourceV1) {}, true},
		{"id", func(s *htmlAuthoringCanonicalSourceV1) { s.id = uuid.New() }, false},
		{"version", func(s *htmlAuthoringCanonicalSourceV1) { s.version++ }, false},
		{"purpose", func(s *htmlAuthoringCanonicalSourceV1) { s.revision = false }, false},
		{"digest", func(s *htmlAuthoringCanonicalSourceV1) { s.digest[0]++ }, false},
		{"invalid_digest", func(s *htmlAuthoringCanonicalSourceV1) { s.digestValid = false }, false},
		{"master_transport", func(s *htmlAuthoringCanonicalSourceV1) { s.master = append(bytes.Clone(s.master), ' ') }, false},
		{"defaults_transport", func(s *htmlAuthoringCanonicalSourceV1) { s.defaults = []byte("{ }") }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next := first
			next.master = bytes.Clone(first.master)
			next.defaults = bytes.Clone(first.defaults)
			test.change(&next)
			if got := htmlAuthoringCanonicalSameV1(&first, &next); got != test.reuse {
				t.Fatalf("exact private-source reuse=%v want%v", got, test.reuse)
			}
		})
	}
	reader := &ApplicationHTMLAuthoringReaderV1{}
	reader.canonicalSources[0] = first
	reader.canonicalCount = 1
	if err := reader.rememberCanonicalSourceV1(id, 1, true, first.master, first.defaults, digest); err != nil {
		t.Fatal(err)
	}
	next := &reader.canonicalSources[1]
	if !next.reused || !next.ready || next.delivered || next.started || next.prepared != first.prepared {
		t.Fatal("fresh exact read lost one-delivery/private prepared identity")
	}
	first.master[0] = 'X'
	if next.master[0] == 'X' {
		t.Fatal("fresh raw snapshot aliases earlier/raw caller bytes")
	}
	reader.canonicalSources[0].ready = false
	reader.canonicalSources[1].ready = false
	if err := reader.rememberCanonicalSourceV1(id, 1, true, next.master, next.defaults, digest); err != nil {
		t.Fatal(err)
	}
	if reader.canonicalSources[2].reused {
		t.Fatal("failed/incomplete prior producer reused")
	}
}
func TestHTMLAuthoringPreparedCopyComponentV1(t *testing.T) {
	small, err := htmlAuthoringCanonicalCopyResourcesV1(htmlmaster.TemplateCommitment{MasterJSON: []byte{1}, DefaultsJSON: []byte{2}}, 0, 0)
	if err != nil || small < 32 || small%8192 != 0 {
		t.Fatalf("tiny copy/page cost: %d,%v", small, err)
	}
	actual := htmlmaster.TemplateCommitment{MasterJSON: bytes.Repeat([]byte{1}, 32768), DefaultsJSON: bytes.Repeat([]byte{2}, 8192)}
	larger, err := htmlAuthoringCanonicalCopyResourcesV1(actual, 64, 64)
	if err != nil || larger < int64(len(actual.MasterJSON)+len(actual.DefaultsJSON))+64*32 {
		t.Fatalf("actual defensive copies omitted: %d,%v", larger, err)
	}
	for _, count := range []int{-1, 65, math.MaxInt} {
		if _, err = htmlAuthoringCanonicalCopyResourcesV1(actual, count, 0); err == nil {
			t.Fatalf("invalid existing topology accepted: %d", count)
		}
	}
	var zero ApplicationHTMLAuthoringReaderV1
	if _, err = zero.PreparedRetainedTemplateV1(nil, uuid.New(), 1); err == nil {
		t.Fatal("zero/native-free reader accepted prepared work")
	}
}
