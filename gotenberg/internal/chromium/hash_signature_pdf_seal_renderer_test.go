//go:build renderer_e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

type hashSealTailSupervisor struct {
	gotenberg.ProcessSupervisor
	cancel  context.CancelFunc
	failure error
}

func (s hashSealTailSupervisor) Run(ctx context.Context, logger *slog.Logger, task func() error) error {
	if err := s.ProcessSupervisor.Run(ctx, logger, task); err != nil {
		return err
	}
	if s.cancel != nil {
		s.cancel()
	}
	return s.failure
}

func TestHashSignaturePDFSealGenuineRenderer(t *testing.T) {
	mod, b := hashPublicFixtureModule(t)
	initial := hashBrowserTargets(t, b)
	logger := slog.New(slog.DiscardHandler)
	index := 0
	for _, font := range []string{"Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple"} {
		for _, fixture := range []struct{ label, text string }{{"normal", "Anna Åström"}, {"full-200-runes", "Start" + strings.Repeat("Åb", 95) + "SlutZ"}} {
			t.Run(font+"/"+fixture.label, func(t *testing.T) {
				p := hashTestMeasurePlan()
				p.Font = font
				p.Text = fixture.text
				if fixture.label == "full-200-runes" {
					p.WidthPoints = "1000"
					p.HeightPoints = "600"
				}
				p.Targets = append(p.Targets, hashMeasureTarget{ID: "22222222-2222-4222-8222-222222222222", X: ".05", Y: ".5", W: ".8", H: ".45"})
				hashSealGenuineCase(t, mod, b, logger, p, initial, index)
				index++
			})
		}
	}
	for _, text := range []string{`  Á O'Neill <tag> ${name} " & Å B  `, "Á  B\r\nC\nD\r"} {
		t.Run("source-and-paint-projection-"+string(rune('a'+index-10)), func(t *testing.T) {
			p := hashTestMeasurePlan()
			p.Text = text
			p.Targets = append(p.Targets, hashMeasureTarget{ID: "22222222-2222-4222-8222-222222222222", X: ".05", Y: ".5", W: ".8", H: ".45"})
			hashSealGenuineCase(t, mod, b, logger, p, initial, index)
			index++
		})
	}
	for _, mode := range []string{"tiny-second", "fallback", "wrong-font-bytes", "already-cancelled", "cancel-after-callback", "failure-after-callback"} {
		t.Run(mode, func(t *testing.T) {
			p := hashTestMeasurePlan()
			f, _ := hashPinnedMeasureFont(p.Font)
			font, err := os.ReadFile(filepath.Join("/tmp/hash-fit-inputs", f.file))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			original := mod.supervisor
			defer func() { mod.supervisor = original }()
			switch mode {
			case "tiny-second":
				p.Targets = append(p.Targets, hashMeasureTarget{ID: "22222222-2222-4222-8222-222222222222", X: ".1", Y: ".5", W: ".02", H: ".02"})
			case "fallback":
				p.Text = "Anna 🙂"
			case "wrong-font-bytes":
				font[0] ^= 1
			case "already-cancelled":
				cancel()
			case "cancel-after-callback":
				mod.supervisor = hashSealTailSupervisor{ProcessSupervisor: original, cancel: cancel}
			case "failure-after-callback":
				mod.supervisor = hashSealTailSupervisor{ProcessSupervisor: original, failure: errors.New("synthetic owned tail refusal")}
			}
			pack, err := mod.prepareHashSignaturePDF(ctx, logger, p, font)
			if err == nil || pack != nil {
				t.Fatal("refusal published package")
			}
			if hashBrowserTargets(t, b) != initial {
				t.Fatal("refused target still present")
			}
		})
	}
}

func hashSealGenuineCase(t *testing.T, mod *Chromium, b *chromiumBrowser, logger *slog.Logger, p *hashSignatureMeasurePlan, initial int, index int) {
	t.Helper()
	f, _ := hashPinnedMeasureFont(p.Font)
	font, err := os.ReadFile(filepath.Join("/tmp/hash-fit-inputs", f.file))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pack, err := mod.prepareHashSignaturePDF(ctx, logger, p, font)
	if err != nil {
		t.Fatal(err)
	}
	if hashBrowserTargets(t, b) != initial {
		t.Fatal("sealed target not reaped")
	}
	decoded, err := decodeHashSignaturePDFPackage(pack.Bytes(), p)
	if err != nil {
		t.Fatal(err)
	}
	var r hashSignaturePDFReport
	if json.Unmarshal(decoded.Report(), &r) != nil {
		t.Fatal("report")
	}
	for _, target := range r.Measurement.DOM.Targets {
		text := ""
		for _, l := range target.Lines {
			text += l.Text + l.HardBreak
		}
		if text != p.Text {
			t.Fatal("original name bytes changed")
		}
	}
	stem := "case-" + strconv.Itoa(index)
	// The test runner owns this fixed tmpfs directory and copies exact outputs
	// before deleting its container. This is not application storage acceptance.
	for suffix, raw := range map[string][]byte{".fit": pack.Bytes(), ".pdf": pack.PDF(), ".json": pack.Report()} {
		path := filepath.Join("/tmp/hash-seal-outputs", stem+suffix)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		n, writeErr := file.Write(raw)
		closeErr := file.Close()
		if n != len(raw) || writeErr != nil || closeErr != nil {
			t.Fatal("output capture")
		}
	}
	t.Logf("sealed-package=%s pdfSha256=%s reportSha256=%s", stem, r.PDFSHA256, hashSealSHA(pack.Report()))
}

func TestHashSignaturePDFSealSnapshotGenuineRefusals(t *testing.T) {
	mod, b := hashPublicFixtureModule(t)
	initial := hashBrowserTargets(t, b)
	logger := slog.New(slog.DiscardHandler)
	for _, mode := range []string{"missing-middle-text", "hidden-ink", "clipped-svg", "extra-opaque-paint"} {
		t.Run(mode, func(t *testing.T) {
			p := hashTestMeasurePlan()
			u, dir := hashMeasureFixture(t, p, nil)
			options := DefaultOptions()
			options.AllowedFilePrefixes = []string{dir}
			options.EmulatedMediaType = "print"
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err := mod.supervisor.Run(ctx, logger, func() error {
				return b.do(ctx, logger, u, options, nil, chromedp.Tasks{
					network.Enable(), fetch.Enable(), runtime.Enable(), disableJavaScriptActionFunc(logger, true), navigateActionFunc(logger, u, true, true), emulateMediaTypeActionFunc(logger, "print", nil),
					chromedp.ActionFunc(func(task context.Context) error {
						if err := hashSignatureMeasurementAction(p).Do(task); err != errHashFitNotReady {
							return err
						}
						before, err := hashCaptureSignatureSnapshot(task, p.report)
						if err != nil {
							return err
						}
						frame, err := page.GetFrameTree().Do(task)
						if err != nil {
							return err
						}
						world, err := page.CreateIsolatedWorld(frame.Frame.ID).WithWorldName("hash-seal-test-fault").WithGrantUniveralAccess(false).Do(task)
						if err != nil {
							return err
						}
						arg, _ := json.Marshal(mode)
						_, exception, err := runtime.CallFunctionOn(`function(mode){const n=document.getElementById("hash-measure-line-0-0"),s=document.getElementById("hash-measure-target-0");if(mode==="missing-middle-text")n.textContent=n.textContent.slice(0,3)+n.textContent.slice(4);else if(mode==="hidden-ink")n.style.opacity="0";else if(mode==="clipped-svg")s.style.overflow="hidden";else if(mode==="extra-opaque-paint"){const d=document.createElement("div");d.style="position:absolute;inset:0;background:white";document.body.appendChild(d)}else throw new Error("mode");}`).WithExecutionContextID(world).WithArguments([]*runtime.CallArgument{{Value: arg}}).WithReturnByValue(true).WithSilent(true).Do(task)
						if err != nil || exception != nil {
							return errors.New("fault did not apply")
						}
						after, err := hashCaptureSignatureSnapshot(task, p.report)
						if err != nil || string(after) != string(before) {
							return errHashSignatureSeal
						}
						return errors.New("changed snapshot accepted")
					}), page.Close(),
				})
			})
			if !errors.Is(err, errHashSignatureSeal) {
				t.Fatal(err)
			}
			if hashBrowserTargets(t, b) != initial {
				t.Fatal("fault target still present")
			}
		})
	}
}
