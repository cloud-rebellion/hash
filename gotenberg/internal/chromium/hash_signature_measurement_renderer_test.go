//go:build renderer_e2e

package chromium

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hashMeasureFixture(t *testing.T, p *hashSignatureMeasurePlan, change func(string) string) (string, string) {
	t.Helper()
	f, _ := hashPinnedMeasureFont(p.Font)
	raw, err := os.ReadFile(filepath.Join("/tmp/hash-fit-inputs", f.file))
	if err != nil {
		t.Fatal(err)
	}
	html, err := hashSignatureMeasureHTML(p, raw)
	if err != nil {
		t.Fatal(err)
	}
	if change != nil {
		html = change(html)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "index.html")
	if err = os.WriteFile(path, []byte(html), 0600); err != nil {
		t.Fatal(err)
	}
	return (&url.URL{Scheme: "file", Path: path}).String(), dir
}

func TestHashSignatureMeasurementGenuineRenderer(t *testing.T) {
	b := hashGenuineBrowser(t)
	initial := hashBrowserTargets(t, b)
	run := func(t *testing.T, p *hashSignatureMeasurePlan, change func(string) string, want error) {
		t.Helper()
		u, dir := hashMeasureFixture(t, p, change)
		opts := DefaultPdfOptions()
		opts.EmulatedMediaType = "print"
		opts.AllowedFilePrefixes = []string{dir}
		opts.hashSignatureMeasure = p
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output := filepath.Join(dir, "must-not-print.pdf")
		err := b.pdf(ctx, slog.New(slog.DiscardHandler), u, output, opts, nil)
		if !errors.Is(err, want) {
			t.Fatalf("measurement result: %v; wanted %v", err, want)
		}
		if _, err = os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unsealed measurement printed a PDF")
		}
		if hashBrowserTargets(t, b) != initial {
			t.Fatal("measurement target not reaped")
		}
		if errors.Is(want, errHashFitNotReady) {
			if p.report == nil || p.report.InputSHA256 != p.inputSHA() || len(p.report.DOM.Targets) != len(p.Targets) {
				t.Fatal("complete input-bound measurement absent")
			}
			for _, target := range p.report.DOM.Targets {
				reconstructed := ""
				for _, line := range target.Lines {
					reconstructed += line.Text + line.HardBreak
					if strings.TrimSpace(line.Text) != "" && len(line.Fonts) != 1 {
						t.Fatal("actual font attribution absent")
					}
				}
				if reconstructed != p.Text {
					t.Fatal("full signer name changed")
				}
			}
			encoded, _ := json.Marshal(p.report)
			t.Logf("measurement=%s", encoded)
		} else if p.report != nil {
			t.Fatal("refusal retained stale or partial report")
		}
	}
	for _, font := range []string{"Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple"} {
		for _, fixture := range []struct{ label, text string }{{"normal", "Anna Åström"}, {"full-200-runes", strings.Repeat("Å", 200)}, {"typed-punctuation", `O'Neill <script> ${name} " slash\ &`}, {"hard-break-and-combining", "A\u0301  B\r\nC\nD"}, {"whitespace-and-all-hard-breaks", "  A\u00a0 B \rC\nD\r\n "}} {
			t.Run(font+"/"+fixture.label, func(t *testing.T) {
				p := hashTestMeasurePlan()
				p.Font = font
				p.Text = fixture.text
				if fixture.label == "full-200-runes" {
					p.WidthPoints = "1000"
					p.HeightPoints = "600"
				}
				p.Targets = append(p.Targets, hashMeasureTarget{ID: "22222222-2222-4222-8222-222222222222", X: ".05", Y: ".5", W: ".9", H: ".45"})
				run(t, p, nil, errHashFitNotReady)
			})
		}
	}
	t.Run("every-target-required-tiny-second-refuses", func(t *testing.T) {
		p := hashTestMeasurePlan()
		p.Targets = append(p.Targets, hashMeasureTarget{ID: "22222222-2222-4222-8222-222222222222", X: ".1", Y: ".5", W: ".02", H: ".02"})
		run(t, p, nil, errHashSignatureMeasure)
	})
	for _, font := range []string{"Sacramento", "Homemade Apple"} {
		t.Run(font+"/full-200-runes-small-field-refuses", func(t *testing.T) {
			p := hashTestMeasurePlan()
			p.Font = font
			p.Text = strings.Repeat("Å", 200)
			run(t, p, nil, errHashSignatureMeasure)
		})
	}
	t.Run("mixed-unpinned-fallback-refuses", func(t *testing.T) {
		p := hashTestMeasurePlan()
		p.Text = "Anna 🙂"
		run(t, p, nil, errHashSignatureMeasure)
	})
	t.Run("missing-font-refuses", func(t *testing.T) {
		p := hashTestMeasurePlan()
		run(t, p, func(s string) string {
			return strings.Replace(s, "data:font/woff2;base64,", "data:font/woff2;base64,invalid", 1)
		}, errHashSignatureMeasure)
	})
	t.Run("wrong-custom-font-under-selected-alias-refuses", func(t *testing.T) {
		p := hashTestMeasurePlan()
		f, _ := hashPinnedMeasureFont("Caveat")
		other, _ := hashPinnedMeasureFont("Sacramento")
		original, err := os.ReadFile(filepath.Join("/tmp/hash-fit-inputs", f.file))
		if err != nil {
			t.Fatal(err)
		}
		replacement, err := os.ReadFile(filepath.Join("/tmp/hash-fit-inputs", other.file))
		if err != nil {
			t.Fatal(err)
		}
		run(t, p, func(s string) string {
			return strings.Replace(s, base64.StdEncoding.EncodeToString(original), base64.StdEncoding.EncodeToString(replacement), 1)
		}, errHashSignatureMeasure)
	})
	t.Run("wrong-input-commitment-refuses", func(t *testing.T) {
		p := hashTestMeasurePlan()
		run(t, p, func(s string) string { return strings.Replace(s, p.inputSHA(), strings.Repeat("9", 64), 1) }, errHashSignatureMeasure)
	})
	t.Run("document-script-sentinel-refuses", func(t *testing.T) {
		p := hashTestMeasurePlan()
		run(t, p, func(s string) string {
			return strings.Replace(s, "<html ", `<html data-hash-page-script="executed" `, 1)
		}, errHashSignatureMeasure)
	})
	t.Run("untrusted-body-refuses", func(t *testing.T) {
		p := hashTestMeasurePlan()
		run(t, p, func(s string) string {
			return strings.Replace(s, "<body>", "<body><script>window.escaped=true</script>", 1)
		}, errHashSignatureMeasure)
	})
	t.Run("ordinary-pdf-after-measurement-refusals", func(t *testing.T) {
		p := hashTestMeasurePlan()
		u, dir := hashMeasureFixture(t, p, nil)
		opts := DefaultPdfOptions()
		opts.EmulatedMediaType = "print"
		opts.AllowedFilePrefixes = []string{dir}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output := filepath.Join(dir, "ordinary.pdf")
		if err := b.pdf(ctx, slog.New(slog.DiscardHandler), u, output, opts, nil); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(output)
		if err != nil || !strings.HasPrefix(string(raw), "%PDF-") {
			t.Fatal("ordinary PDF output smoke failed")
		}
		if hashBrowserTargets(t, b) != initial {
			t.Fatal("ordinary target not reaped")
		}
	})
}
