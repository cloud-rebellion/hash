//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"github.com/bright-interaction/hash/internal/render"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOwnedProtocolRendererHonorsExactPaperV1E2E(t *testing.T) {
	peer := httptest.NewServer(&ownedA4ProtocolRendererV1{})
	defer peer.Close()
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	renderer := render.NewGotenberg(peer.URL)
	defaultA4, err := renderer.HTMLToPDF(ctx, "<!doctype html><html><body>synthetic default protocol</body></html>", render.PDFOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(defaultA4, ownedA4ProtocolPDFV1()) {
		t.Fatal("default exact-A4 protocol bytes changed")
	}
	letter, err := renderer.HTMLToPDF(ctx, "<!doctype html><html><body>synthetic Letter protocol</body></html>", render.PDFOptions{ExactPaperPoints: [2]float64{612, 792}, PreferCSSPageSize: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(letter, []byte("/MediaBox [0 0 612.000000 792.000000]")) || bytes.Equal(letter, defaultA4) {
		t.Fatal("actual ExactPaperPoints multipart fields were ignored")
	}
}
