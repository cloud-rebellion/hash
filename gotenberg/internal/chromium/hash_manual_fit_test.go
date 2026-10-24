// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

const validHashCapabilityReport = `{"schema":1,"documentScriptsBlocked":true,"domAccessible":true,"styleApplied":true,"printMedia":true,"fontLoaded":true,"textPreserved":true,"graphemes":8,"advance":70,"inkLeft":-1,"inkRight":72,"inkAscent":20,"inkDescent":4}`

func TestHashFitCapabilityReportRefusesAmbiguousOrIncompleteEvidence(t *testing.T) {
	if _, err := decodeHashFitCapability([]byte(validHashCapabilityReport)); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		strings.Replace(validHashCapabilityReport, `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(validHashCapabilityReport, `"schema":1`, `"schema":null`, 1),
		strings.Replace(validHashCapabilityReport, `"schema":1,`, ``, 1),
		strings.Replace(validHashCapabilityReport, `"schema":1`, `"schema":2`, 1),
		strings.Replace(validHashCapabilityReport, `"schema":1`, `"schema":1,"unknown":1`, 1),
		strings.Replace(validHashCapabilityReport, `"documentScriptsBlocked":true`, `"documentScriptsBlocked":false`, 1),
		strings.Replace(validHashCapabilityReport, `"textPreserved":true`, `"textPreserved":false`, 1),
		strings.Replace(validHashCapabilityReport, `"fontLoaded":true`, `"fontLoaded":false`, 1),
		strings.Replace(validHashCapabilityReport, `"printMedia":true`, `"printMedia":false`, 1),
		strings.Replace(validHashCapabilityReport, `"graphemes":8`, `"graphemes":201`, 1),
		strings.Replace(validHashCapabilityReport, `"graphemes":8`, `"graphemes":0`, 1),
		strings.Replace(validHashCapabilityReport, `"advance":70`, `"advance":1e400`, 1),
		strings.Replace(validHashCapabilityReport, `"advance":70`, `"advance":0`, 1),
		strings.Replace(validHashCapabilityReport, `"advance":70`, `"advance":-1`, 1),
		strings.Replace(validHashCapabilityReport, `"inkRight":72`, `"inkRight":0`, 1),
		validHashCapabilityReport + ` {}`,
		strings.Repeat(" ", 4097),
	}
	for i, raw := range cases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			if _, err := decodeHashFitCapability([]byte(raw)); !errors.Is(err, errHashFitCapability) {
				t.Fatalf("unexpected admission: %v", err)
			}
		})
	}
}

func TestHashManualFitCannotBeArmedByPublicOptions(t *testing.T) {
	var options PdfOptions
	if err := json.Unmarshal([]byte(`{"hashManualFit":{"text":"x","font":"Caveat"},"HashManualFit":{"text":"x","font":"Caveat"}}`), &options); err != nil {
		t.Fatal(err)
	}
	if options.hashManualFit != nil {
		t.Fatal("public JSON armed private hook")
	}
	if err := hashManualSignatureFitAction(nil).Do(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHashManualFitRefusesBeforeNavigationWithoutIsolation(t *testing.T) {
	plan := &hashManualFitPlan{text: "Test", font: "Caveat", capability: &hashFitCapability{Schema: 1}}
	b := &chromiumBrowser{}
	err := b.pdf(context.Background(), slog.New(slog.DiscardHandler), "ignored", "ignored", PdfOptions{hashManualFit: plan}, nil)
	if !errors.Is(err, errHashFitIsolation) || plan.capability != nil {
		t.Fatal("isolation refusal or stale result")
	}
	// No browser exists: this must refuse before attempting any CDP/navigation.
	b.arguments.disableJavaScript = true
	plan.text = strings.Repeat("x", 201)
	err = b.pdf(context.Background(), slog.New(slog.DiscardHandler), "ignored", "ignored", PdfOptions{hashManualFit: plan}, nil)
	if !errors.Is(err, errHashFitCapability) {
		t.Fatal(err)
	}
}

func TestHashFitProbePreservesFullNamePolicy(t *testing.T) {
	for _, name := range []string{strings.Repeat("Å", 200), strings.Repeat("𝔸", 200), "A\u0301 B\u00a0 C\nD", `O'Neill <script> ${name} " backslash\`} {
		if !(&hashManualFitPlan{text: name, font: "Caveat"}).valid() {
			t.Fatal("valid name policy narrowed")
		}
	}
	for _, name := range []string{"", "  ", "\xff", strings.Repeat("x", 201)} {
		if (&hashManualFitPlan{text: name, font: "Caveat"}).valid() {
			t.Fatal("invalid name admitted")
		}
	}
}

func TestHashUnconfirmedCleanupRefusesReuseAndHealth(t *testing.T) {
	b := &chromiumBrowser{}
	b.isStarted.Store(true)
	b.hashCleanupUnconfirmed.Store(true)
	logger := slog.New(slog.DiscardHandler)
	if b.Healthy(logger) {
		t.Fatal("unconfirmed cleanup reported healthy")
	}
	// No browser connection exists: refusal must precede allocation/navigation.
	if err := b.do(context.Background(), logger, "ignored", Options{}, nil, nil); !errors.Is(err, errHashTabCleanup) {
		t.Fatal(err)
	}
}
