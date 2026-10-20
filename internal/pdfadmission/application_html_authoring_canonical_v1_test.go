// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestHTMLStoredCanonicalRefusesMissingActualNativeOwnerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 1<<30)
	org := uuid.New()
	// A configured factory and actual org alone do not prove a native session.
	h := &ApplicationSessionV1{state: &applicationOwnedSessionV1{factory: f.state, org: org}}
	if owner, err := h.newHTMLCanonicalModelConsumerV1(ctx); owner != nil || !errors.Is(err, ErrHTMLAuthoringReadV1) {
		t.Fatalf("missing native ownership accepted: %p %v", owner, err)
	}
	if p := f.PendingV1(); p.HTMLCanonicalConsumers != 0 || p.WorkSessions != 0 || p.ObserverSessions != 0 {
		t.Fatalf("refusal installed source/SQL debt: %+v", p)
	}
	if s := c.SnapshotV1(org); s.GlobalGrants != 0 {
		t.Fatalf("refusal acquired work: %+v", s)
	}
	if err := f.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestHTMLStoredCanonicalSnapshotsDoNotAdoptCallerMutationV1(t *testing.T) {
	r := &ApplicationHTMLAuthoringReaderV1{}
	r.self = r
	master := []byte("{\"schema_version\":1,\"html\":\"<p>Original</p>\"}")
	defaults := []byte("{}")
	id := uuid.New()
	digest := make([]byte, 32)
	if err := r.rememberCanonicalSourceV1(id, 1, false, master, defaults, digest); err != nil {
		t.Fatal(err)
	}
	old := bytes.Clone(master)
	master[0] = 91
	defaults[0] = 91
	digest[0] = 255
	source := r.canonicalSources[0]
	if !bytes.Equal(source.master, old) || !bytes.Equal(source.defaults, []byte("{}")) || !source.digestValid || source.digest[0] != 0 {
		t.Fatal("mutable DB/caller bytes replaced stored source")
	}
	// This is a pure snapshot assertion, not a body/physical retirement claim.
	copyShell := &ApplicationHTMLAuthoringReaderV1{self: r}
	copyShell.CloseConsumerV1()
	if r.closed {
		t.Fatal("copied identity closed original source consumer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := copyShell.CanonicalCurrentTemplateV1(ctx, id, 1); !errors.Is(err, ErrHTMLAuthoringReadV1) {
		t.Fatalf("copied shell accepted actual source: %v", err)
	}
}
func TestHTMLStoredMaterializationPricesDeclaredTextAndActualAssetURLV1(t *testing.T) {
	small := htmlmaster.Master{HTML: "<p><span data-hash-value=\"name\"></span></p>", Values: []htmlmaster.Value{{Name: "name", MaxChars: 1}}}
	stats := htmlInputCanonicalStatsV1{tokens: 4, cssTokens: 1}
	a, err := htmlStoredTemplateMaterializationResourcesV1(small, stats)
	if err != nil {
		t.Fatal(err)
	}
	large := small
	large.Values = []htmlmaster.Value{{Name: "name", MaxChars: 8192}}
	b, err := htmlStoredTemplateMaterializationResourcesV1(large, stats)
	if err != nil {
		t.Fatal(err)
	}
	stats.maxAssetURL = 1 << 20
	d, err := htmlStoredTemplateMaterializationResourcesV1(large, stats)
	if err != nil {
		t.Fatal(err)
	}
	if a <= 0 || b <= a || d <= b {
		t.Fatalf("declared text/actual URL expansion omitted: %d %d %d", a, b, d)
	}
	large.Values[0].MaxChars = htmlmaster.MaxValueChars + 1
	if _, err := htmlStoredTemplateMaterializationResourcesV1(large, stats); err == nil {
		t.Fatal("invalid declaration was used as allocation authority")
	}
}
