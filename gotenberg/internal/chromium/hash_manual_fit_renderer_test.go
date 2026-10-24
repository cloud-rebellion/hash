//go:build renderer_e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/dlclark/regexp2"
)

// Mandatory genuine-engine tests have a separate tag and fail if their exact
// synthetic runtime inputs are absent. They must never silently skip.
func hashNewGenuineBrowser(t *testing.T) *chromiumBrowser {
	t.Helper()
	if os.Getenv("HASH_FIT_RENDERER_TEST") != "1" {
		t.Fatal("mandatory renderer fixture missing")
	}
	b := newChromiumBrowser(browserArguments{
		binPath: "/usr/bin/chromium", hyphenDataDirPath: "/opt/gotenberg/chromium-hyphen-data",
		wsUrlReadTimeout:  10 * time.Second,
		disableJavaScript: true, denyPrivateIPs: true, denyPublicIPs: true,
		denyList:   []*regexp2.Regexp{regexp2.MustCompile(`^https?://.*`, 0)},
		clearCache: true, clearCookies: true, clearStorage: true,
	}).(*chromiumBrowser)
	return b
}

func hashGenuineBrowser(t *testing.T) *chromiumBrowser {
	t.Helper()
	b := hashNewGenuineBrowser(t)
	logger := slog.New(slog.DiscardHandler)
	if err := b.Start(logger); err != nil {
		t.Fatal("start genuine browser: ", err)
	}
	t.Cleanup(func() {
		if err := b.Stop(logger); err != nil {
			t.Error("stop genuine browser: ", err)
		}
	})
	return b
}

func hashBrowserTargets(t *testing.T, b *chromiumBrowser) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(b.ctx, 2*time.Second)
	defer cancel()
	var infos []*target.Info
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		infos, err = target.GetTargets().Do(ctx)
		return err
	}))
	if err != nil {
		t.Fatal("observe browser targets: ", err)
	}
	n := 0
	for _, info := range infos {
		if info.Type == "page" {
			n++
		}
	}
	return n
}

func hashFitFixture(t *testing.T, font, filename, expectedSHA string, missing bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if !missing {
		raw, err := os.ReadFile(filepath.Join("/tmp/hash-fit-inputs", filename))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != expectedSHA {
			t.Fatal("pinned font fixture unavailable")
		}
		if err := os.WriteFile(filepath.Join(dir, filename), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// If any document script executes, it changes shared DOM rather than a
	// main-world global. The trusted isolated-world probe must detect that.
	raw := `<!doctype html><meta charset="utf-8"><style>@font-face{font-family:"` + html.EscapeString(font) + `";src:url("` + filename + `") format("woff2")} @page{size:400pt 200pt;margin:0}</style><div id="hash-fit-capability-target"></div><img src="data:image/png;base64,broken" onerror="document.documentElement.setAttribute('data-hash-event-handler','executed')"><script>document.documentElement.setAttribute("data-hash-page-script","executed");const e=document.createElement("div");e.id="hash-page-script-effect";document.body.appendChild(e);</script>`
	p := filepath.Join(dir, "index.html")
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	return (&url.URL{Scheme: "file", Path: p}).String(), dir
}

func TestHashFitCapabilityGenuineRenderer(t *testing.T) {
	b := hashGenuineBrowser(t)
	initialTargets := hashBrowserTargets(t, b)
	t.Run("pre-attachment-cleanup-preserves-another-target", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(b.ctx, 3*time.Second)
		defer cancel()
		ctx = cdp.WithExecutor(ctx, chromedp.FromContext(b.ctx).Browser)
		owned, err := target.CreateTarget("about:blank").Do(ctx)
		if err != nil {
			t.Fatal("create unattached owned target: ", err)
		}
		defer b.hashWaitForTargetCleanup(owned)
		decoy, err := target.CreateTarget("about:blank").Do(ctx)
		if err != nil {
			t.Fatal("create unattached decoy target: ", err)
		}
		defer b.hashWaitForTargetCleanup(decoy)
		if err := b.hashWaitForTargetCleanup(owned); err != nil {
			t.Fatal(err)
		}
		infos, err := target.GetTargets().Do(ctx)
		if err != nil {
			t.Fatal(err)
		}
		foundDecoy := false
		for _, info := range infos {
			if info.TargetID == owned {
				t.Fatal("unattached owned target remains")
			}
			if info.TargetID == decoy {
				foundDecoy = true
			}
		}
		if !foundDecoy || !b.Healthy(slog.New(slog.DiscardHandler)) {
			t.Fatal("cleanup affected another target or browser health")
		}
		if err := b.hashWaitForTargetCleanup(decoy); err != nil {
			t.Fatal(err)
		}
		if hashBrowserTargets(t, b) != initialTargets {
			t.Fatal("unattached fixture targets remain")
		}
	})
	fonts := []struct{ name, file, sha string }{
		{"Caveat", "Caveat.woff2", "d0b7b931b8980049327e8f8f9ac264617c8200b8422d62e886473d3d9527bad3"},
		{"Dancing Script", "DancingScript.woff2", "570e4265bbcb453353ce2fdf63d179332d8daa92691d567547b8a383f3b46c3b"},
		{"Great Vibes", "GreatVibes.woff2", "c59dc73d29daf142ef2431f455d21464172374aa750d793a79d608735db2d856"},
		{"Sacramento", "Sacramento.woff2", "2fcd867d2812578d001b0eca921848e24de91d01986f26e038be374ec7c5cfd2"},
		{"Homemade Apple", "HomemadeApple.woff2", "bbaa96c741caa479d4647fc567f64e5ddc71eec58ee9849cb9e8a14bee65bc30"},
	}
	for _, font := range fonts {
		for _, fixture := range []struct{ label, name string }{
			{"normal", "Anna Åström"},
			{"full-200-runes", strings.Repeat("Å", 200)},
			{"typed-hostile-punctuation", `O'Neill <script> ${name} " slash\ &`},
		} {
			t.Run(font.file+"/"+fixture.label, func(t *testing.T) {
				u, dir := hashFitFixture(t, font.name, font.file, font.sha, false)
				plan := &hashManualFitPlan{text: fixture.name, font: font.name}
				opts := DefaultPdfOptions()
				opts.EmulatedMediaType = "print"
				opts.AllowedFilePrefixes = []string{dir}
				opts.hashManualFit = plan
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				output := filepath.Join(dir, "must-not-print.pdf")
				err := b.pdf(ctx, slog.New(slog.DiscardHandler), u, output, opts, nil)
				if !errors.Is(err, errHashFitNotReady) || plan.capability == nil {
					t.Fatalf("trusted disabled-script capability not established: %v", err)
				}
				if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("capability probe produced a PDF")
				}
				if hashBrowserTargets(t, b) != initialTargets {
					t.Fatal("conversion target not reaped")
				}
			})
		}
	}
	t.Run("missing-font-refuses-no-pdf", func(t *testing.T) {
		f := fonts[0]
		u, dir := hashFitFixture(t, f.name, f.file, f.sha, true)
		opts := DefaultPdfOptions()
		opts.EmulatedMediaType = "print"
		opts.AllowedFilePrefixes = []string{dir}
		plan := &hashManualFitPlan{text: "Anna Åström", font: f.name, capability: &hashFitCapability{Schema: 1}}
		opts.hashManualFit = plan
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output := filepath.Join(dir, "must-not-print.pdf")
		if err := b.pdf(ctx, slog.New(slog.DiscardHandler), u, output, opts, nil); !errors.Is(err, errHashFitCapability) || plan.capability != nil {
			t.Fatalf("missing font not refused: %v", err)
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refusal produced a PDF")
		}
		if hashBrowserTargets(t, b) != initialTargets {
			t.Fatal("refused target not reaped")
		}
	})
	t.Run("ordinary-pdf-after-refusals", func(t *testing.T) {
		f := fonts[0]
		u, dir := hashFitFixture(t, f.name, f.file, f.sha, false)
		opts := DefaultPdfOptions()
		opts.EmulatedMediaType = "print"
		opts.AllowedFilePrefixes = []string{dir}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output := filepath.Join(dir, "ordinary.pdf")
		if err := b.pdf(ctx, slog.New(slog.DiscardHandler), u, output, opts, nil); err != nil {
			t.Fatal("ordinary conversion: ", err)
		}
		raw, err := os.ReadFile(output)
		if err != nil || !strings.HasPrefix(string(raw), "%PDF-") {
			t.Fatal("ordinary conversion output absent")
		}
		if hashBrowserTargets(t, b) != initialTargets {
			t.Fatal("ordinary target not reaped")
		}
	})
	t.Run("early-caller-cancel-reaps-direct-conversion", func(t *testing.T) {
		f := fonts[0]
		u, dir := hashFitFixture(t, f.name, f.file, f.sha, false)
		opts := DefaultPdfOptions()
		opts.EmulatedMediaType = "print"
		opts.AllowedFilePrefixes = []string{dir}
		opts.WaitForSelector = "#hash-never-visible"
		plan := &hashManualFitPlan{text: "Anna Åström", font: f.name, capability: &hashFitCapability{Schema: 1}}
		opts.hashManualFit = plan
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		output := filepath.Join(dir, "must-not-print.pdf")
		done := make(chan error, 1)
		go func() { done <- b.pdf(ctx, slog.New(slog.DiscardHandler), u, output, opts, nil) }()
		joined := false
		defer func() {
			cancel()
			if !joined {
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("direct conversion did not join")
				}
			}
		}()
		observeUntil := time.Now().Add(3 * time.Second)
		for hashBrowserTargets(t, b) == initialTargets {
			if time.Now().After(observeUntil) {
				t.Fatal("conversion target was not observed")
			}
			select {
			case err := <-done:
				joined = true
				t.Fatalf("conversion ended before cancellation: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
		}
		cancelledAt := time.Now()
		cancel()
		select {
		case err := <-done:
			joined = true
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("caller cancellation result missing: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("early caller cancellation did not stop direct conversion")
		}
		if time.Since(cancelledAt) >= 3*time.Second || plan.capability != nil {
			t.Fatal("late or stale cancellation result")
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("cancelled conversion produced a PDF")
		}
		if hashBrowserTargets(t, b) != initialTargets {
			t.Fatal("cancelled direct conversion target not reaped")
		}
		// This tests b.pdf completion, not upstream supervisor slot ownership.
		opts.WaitForSelector = ""
		opts.hashManualFit = nil
		nextCtx, nextCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer nextCancel()
		nextOutput := filepath.Join(dir, "after-cancel.pdf")
		if err := b.pdf(nextCtx, slog.New(slog.DiscardHandler), u, nextOutput, opts, nil); err != nil {
			t.Fatal("ordinary conversion after cancellation: ", err)
		}
		raw, err := os.ReadFile(nextOutput)
		if err != nil || !strings.HasPrefix(string(raw), "%PDF-") {
			t.Fatal("post-cancel ordinary output absent")
		}
		if hashBrowserTargets(t, b) != initialTargets {
			t.Fatal("post-cancel ordinary target not reaped")
		}
	})
}
