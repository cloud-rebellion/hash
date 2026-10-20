//go:build renderer_e2e

package chromium

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/gotenberg/internal/ordinarypage"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// These mandatory tagged tests use the real private producer, its process
// supervisor, actual CDP measurements/font attribution and native PDF stream.
// Declared source/static pins are fixture metadata: no source PDF inspection,
// SQL authority, storage/retention or complete Sign journey is claimed here.
// The owned runner must supply the pinned font and output tmpfs; never skip or
// replace a failed Chromium/font execution with a synthetic success package.
func hashOrdinaryGenuineFont(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("/tmp/hash-fit-inputs", ordinarypage.FontFileV1))
	if err != nil || len(raw) != ordinarypage.FontBytesV1 || hashOrdinarySHA(raw) != ordinarypage.FontSHA256V1 {
		t.Fatal("mandatory exact Inter font fixture unavailable")
	}
	return raw
}

func hashOrdinarySHA(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func hashOrdinaryField(index int, kind, value, x, y, w, h string) ordinarypage.FieldV1 {
	return ordinarypage.FieldV1{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", index),
		RecipientID: "44444444-4444-4444-4444-444444444444", Type: kind, Required: true,
		XPct: x, YPct: y, WPct: w, HPct: h, ValueValid: true, Value: value}
}

func hashOrdinaryPlan() ordinarypage.PlanV1 {
	pin := hashOrdinarySHA([]byte("declared synthetic source/static fixture; genuine ordinary renderer only"))
	return ordinarypage.PlanV1{Schema: 1, OrgID: "11111111-1111-4111-8111-111111111111",
		DocumentID: "22222222-2222-4222-8222-222222222222", CeremonyEpoch: "2026-10-12T10:00:00.125Z",
		SourceKey: "synthetic/ordinary-source.pdf", SourceVersionID: " opaque-source-version ",
		SourceSHA256: pin, SourceBytes: 123, SourcePages: 1, Page: 1,
		Geometry:    ordinarypage.PageGeometryV1{Boxes: [5][4]float64{{0, 0, 612, 792}, {0, 0, 612, 792}, {0, 0, 612, 792}, {0, 0, 612, 792}, {0, 0, 612, 792}}, UserUnit: 1},
		WidthPoints: "612", HeightPoints: "792", GeometrySHA256: pin, FieldsSHA256: pin,
		StaticBasisSHA256: pin, BrandingContextSHA256: pin, RenderRecipeSHA256: ordinarypage.RecipeSHA256V1(),
		Fields: []ordinarypage.FieldV1{hashOrdinaryField(1, "text", "Original Å Á", "10", "20", "45", "12")}}
}

func hashOrdinaryBindPlan(t *testing.T, p ordinarypage.PlanV1) ordinarypage.PlanV1 {
	t.Helper()
	width, height, err := p.Geometry.ViewportPointsV1()
	if err != nil {
		t.Fatal(err)
	}
	p.WidthPoints, p.HeightPoints = strconv.FormatFloat(width, 'g', -1, 64), strconv.FormatFloat(height, 'g', -1, 64)
	geometry, err := json.Marshal(p.Geometry)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := json.Marshal(p.Fields)
	if err != nil {
		t.Fatal(err)
	}
	p.GeometrySHA256, p.FieldsSHA256 = hashOrdinarySHA(geometry), hashOrdinarySHA(fields)
	if ordinarypage.ValidatePlanV1(p) != nil {
		t.Fatal("invalid genuine renderer fixture plan")
	}
	return p
}

func TestHashOrdinaryPDFGenuineRenderer(t *testing.T) {
	mod, b := hashPublicFixtureModule(t)
	initial := hashBrowserTargets(t, b)
	baseline, err := hashTargetSnapshot(b)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	font := hashOrdinaryGenuineFont(t)
	var written int64
	type fixture struct {
		name         string
		plan         ordinarypage.PlanV1
		wrappedField int
	}
	raw := hashOrdinaryPlan()
	raw.Fields = []ordinarypage.FieldV1{
		hashOrdinaryField(1, "text", "  Á O'Neill <script> ${name} \" & Å B  \r\nNext\nThird\rFourth  ", "10", "5", "80", "18"),
		hashOrdinaryField(2, "text", strings.Repeat("Wrap Å & <b> Á  ", 30), "10", "30", "28", "55"),
	}
	checkbox := hashOrdinaryPlan()
	checkbox.Fields = nil
	values := []string{"true", "1", "yes", "on", "checked", "x", "false", "0", "", "unchecked", "maybe"}
	for i, value := range values {
		checkbox.Fields = append(checkbox.Fields, hashOrdinaryField(i+1, "checkbox", value, "10", strconv.Itoa(5+i*5), "10", "3"))
	}
	missing := hashOrdinaryField(12, "checkbox", "", "10", "60", "10", "3")
	missing.ValueValid = false
	checkbox.Fields = append(checkbox.Fields, missing,
		hashOrdinaryField(13, "text", " \r\n   ", "10", "68", "20", "5"))
	missingText := hashOrdinaryField(14, "text", "", "10", "78", "20", "5")
	missingText.ValueValid = false
	checkbox.Fields = append(checkbox.Fields, missingText)
	ordinaryTypes := hashOrdinaryPlan()
	ordinaryTypes.Fields = []ordinarypage.FieldV1{
		hashOrdinaryField(1, "text", "Reviewed contract text Å", "10", "5", "70", "9"),
		hashOrdinaryField(2, "date", "2026-10-12", "10", "18", "70", "9"),
		hashOrdinaryField(3, "initial", "ÁÅ", "10", "31", "70", "9"),
		hashOrdinaryField(4, "dropdown", "Option <One> & \"Two\"", "10", "44", "70", "9"),
		hashOrdinaryField(5, "text", "", "10", "57", "70", "9"),
	}
	fixtures := []fixture{{"raw-unicode-crlf-literal-html-and-wrap", raw, 1}, {"checkbox-truth-mapping-and-no-ink", checkbox, -1}, {"ordinary-types", ordinaryTypes, -1}}
	for _, geometry := range []struct {
		name     string
		rotation int
		unit     float64
	}{
		{"crop-offset", 0, 1}, {"rotation-90", 90, 1}, {"rotation-180", 180, 1}, {"rotation-270", 270, 1},
		{"negative-rotation", -90, 1}, {"user-unit-half", 0, .5}, {"rotation-and-user-unit-two", 90, 2},
	} {
		p := hashOrdinaryPlan()
		p.SourcePages, p.Page = 3, 2
		p.Geometry = ordinarypage.PageGeometryV1{Boxes: [5][4]float64{{-40, -30, 612, 792}, {10, 20, 600, 780}, {8, 18, 602, 782}, {20, 30, 580, 760}, {30, 40, 570, 750}}, Rotation: geometry.rotation, UserUnit: geometry.unit}
		fixtures = append(fixtures, fixture{geometry.name, p, -1})
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			p := hashOrdinaryBindPlan(t, f.plan)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			pack, err := mod.prepareHashOrdinaryPDF(ctx, logger, p, font)
			if err != nil || pack == nil {
				t.Fatalf("genuine ordinary producer: %v", err)
			}
			hashOrdinaryAssertJoined(t, mod, b, initial, baseline)
			decoded, err := ordinarypage.DecodeWithContextV1(ctx, pack.Bytes(), p)
			if err != nil {
				t.Fatal("complete genuine package: ", err)
			}
			report, err := decoded.Report()
			if err != nil {
				t.Fatal(err)
			}
			hashOrdinaryAssertReport(t, p, decoded, report)
			if f.wrappedField >= 0 && len(report.Measurement.Fields[f.wrappedField].Lines) < 3 {
				t.Fatal("long raw value did not genuinely wrap")
			}
			hashOrdinaryCapture(t, f.name, decoded, &written)
			t.Logf("ordinary-package=%s pdfSha256=%s reportSha256=%s chromium=%s", f.name, report.PDFSHA256, hashOrdinarySHA(decoded.ReportBytes()), report.Chromium.Product)
		})
	}
}

func hashOrdinaryAssertReport(t *testing.T, p ordinarypage.PlanV1, pack *ordinarypage.PackageV1, r ordinarypage.ReportV1) {
	t.Helper()
	input, err := ordinarypage.PlanSHA256V1(p)
	if err != nil || r.InputSHA256 != input || r.RecipeSHA256 != ordinarypage.RecipeSHA256V1() || r.FontSHA256 != ordinarypage.FontSHA256V1 ||
		r.Policy != ordinarypage.PolicyV1 || r.FragmentPage != 1 || r.Plan.Geometry != p.Geometry || r.Plan.SourceVersionID != p.SourceVersionID ||
		r.Plan.WidthPoints != p.WidthPoints || r.Plan.HeightPoints != p.HeightPoints || !strings.Contains(r.Chromium.Product, "Chrome") ||
		!r.Measurement.TextPreserved || !r.Measurement.Unobscured || !r.Measurement.PrintMedia || !r.Measurement.DocumentScriptsBlocked || len(r.Measurement.Fields) != len(p.Fields) {
		t.Fatal("genuine report lost input/recipe/runtime/geometry binding")
	}
	if !strings.Contains(ordinarypage.PrintRecipeV1, "font=11csspx=8.25pt") || !strings.Contains(ordinarypage.PrintRecipeV1, "viewport-csspx=points*96/72") {
		t.Fatal("physical print recipe drift")
	}
	pdf := pack.PDF()
	if len(pdf) < 1024 || len(pdf) > ordinarypage.MaxPDFBytesV1 || !bytes.HasPrefix(pdf, []byte("%PDF-")) || !bytes.HasSuffix(bytes.TrimSpace(pdf), []byte("%%EOF")) ||
		r.PDFBytes != len(pdf) || r.PDFSHA256 != hashOrdinarySHA(pdf) || r.SnapshotSHA256 != hashOrdinarySHA(pack.SnapshotBytes()) {
		t.Fatal("actual native PDF/snapshot commitment missing")
	}
	var snapshot ordinarypage.SnapshotReportV1
	if json.Unmarshal(pack.SnapshotBytes(), &snapshot) != nil || len(snapshot.Fields) != len(p.Fields) || snapshot.InputSHA256 != input || snapshot.RecipeSHA256 != r.RecipeSHA256 {
		t.Fatal("actual canonical snapshot missing")
	}
	width, _ := strconv.ParseFloat(p.WidthPoints, 64)
	height, _ := strconv.ParseFloat(p.HeightPoints, 64)
	var expectedBody strings.Builder
	for i, f := range p.Fields {
		measured := r.Measurement.Fields[i]
		x, _ := strconv.ParseFloat(f.XPct, 64)
		y, _ := strconv.ParseFloat(f.YPct, 64)
		w, _ := strconv.ParseFloat(f.WPct, 64)
		h, _ := strconv.ParseFloat(f.HPct, 64)
		expected := ordinarypage.BBoxV1{X: x * width * 4 / 300, Y: y * height * 4 / 300, Width: w * width * 4 / 300, Height: h * height * 4 / 300}
		actual := measured.ViewportBBox
		if measured.ID != f.ID || measured.Type != f.Type || math.Abs(actual.X-expected.X) > 1.0/32 || math.Abs(actual.Y-expected.Y) > 1.0/32 ||
			math.Abs(actual.Width-expected.Width) > 1.0/32 || math.Abs(actual.Height-expected.Height) > 1.0/32 {
			t.Fatal("actual CSS-pixel geometry lost point conversion")
		}
		checked := f.Type == "checkbox" && f.ValueValid && ordinarypage.CheckedV1(f.Value)
		visible := ""
		if f.Type != "checkbox" && f.ValueValid && strings.TrimSpace(f.Value) != "" {
			visible = f.Value
			expectedBody.WriteString(visible)
		}
		if measured.Checked != checked || measured.NoInk != (!checked && visible == "") {
			t.Fatal("checkbox/blank/missing paint state changed")
		}
		if f.Type == "checkbox" {
			if measured.FontSizePX != 0 || len(measured.Lines) != 0 {
				t.Fatal("checkbox was replaced with text glyph")
			}
			if checked {
				if measured.MarkSizePX != 11 || measured.MarkPath != ordinarypage.CheckboxPathV1 || measured.MarkBBox.Width <= 0 || measured.MarkBBox.Height <= 0 {
					t.Fatal("actual checked path/bounds missing")
				}
			} else if measured.MarkSizePX != 0 || measured.MarkPath != "" || measured.MarkBBox != (ordinarypage.BBoxV1{}) {
				t.Fatal("unchecked checkbox invented ink")
			}
		} else if measured.FontSizePX != 11 {
			t.Fatal("ordinary font changed from 11 CSS px / 8.25 pt")
		}
		var reconstructed strings.Builder
		for _, line := range measured.Lines {
			reconstructed.WriteString(line.Text)
			reconstructed.WriteString(line.HardBreak)
			if strings.TrimSpace(line.Text) == "" {
				if len(line.Fonts) != 0 {
					t.Fatal("blank line invented font attribution")
				}
				continue
			}
			if len(line.Fonts) != 1 {
				t.Fatal("missing or mixed actual platform font attribution")
			}
			observed := line.Fonts[0]
			if !observed.IsCustomFont || observed.FamilyName != ordinarypage.FontFamilyV1 || observed.PostScriptName == "" || observed.GlyphCount <= 0 || math.Trunc(observed.GlyphCount) != observed.GlyphCount {
				t.Fatal("actual pinned custom font not observed")
			}
		}
		if reconstructed.String() != visible {
			t.Fatal("raw whitespace/CRLF/grapheme/literal-HTML bytes changed")
		}
		if measured.NoInk && (len(measured.Lines) != 0 || measured.MarkPath != "") {
			t.Fatal("no-ink field contains painted nodes")
		}
		if snapshot.Fields[i].ID != measured.ID || len(snapshot.Fields[i].Lines) != len(measured.Lines) {
			t.Fatal("post-print snapshot lost measured line membership")
		}
		for j, line := range measured.Lines {
			after := snapshot.Fields[i].Lines[j]
			a, z := after.BBox, line.BBox
			if math.Abs(a.X-z.X) > .001 || math.Abs(a.Y-z.Y) > .001 || math.Abs(a.Width-z.Width) > .001 || math.Abs(a.Height-z.Height) > .001 || !reflect.DeepEqual(after.Fonts, line.Fonts) {
				t.Fatal("post-print snapshot lost measured text boxes/font attribution")
			}
		}
	}
	if snapshot.BodyTextSHA256 != hashOrdinarySHA([]byte(expectedBody.String())) {
		t.Fatal("raw body text snapshot commitment changed")
	}
}

func hashOrdinaryAssertJoined(t *testing.T, mod *Chromium, b *chromiumBrowser, initial int, baseline map[target.ID]string) {
	t.Helper()
	current, err := hashTargetSnapshot(b)
	if err != nil || len(current) != initial || !reflect.DeepEqual(current, baseline) || mod.supervisor.ActiveTasksCount() != 0 || mod.supervisor.ReqQueueSize() != 0 {
		t.Fatalf("ordinary target/supervisor cleanup did not restore baseline: %v", err)
	}
}

func hashOrdinaryCapture(t *testing.T, stem string, pack *ordinarypage.PackageV1, written *int64) {
	t.Helper()
	dir := "/tmp/hash-ordinary-outputs"
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("mandatory owned ordinary output directory missing")
	}
	for _, part := range []struct {
		suffix string
		raw    []byte
		limit  int
	}{
		{".ordinary", pack.Bytes(), ordinarypage.MaxPackageBytesV1}, {".pdf", pack.PDF(), ordinarypage.MaxPDFBytesV1}, {".json", pack.ReportBytes(), ordinarypage.MaxReportBytesV1},
	} {
		if len(part.raw) < 1 || len(part.raw) > part.limit || int64(len(part.raw)) > 64<<20-*written {
			t.Fatal("bounded ordinary output inventory exceeded")
		}
		path := filepath.Join(dir, stem+part.suffix)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		n, writeErr := file.Write(part.raw)
		closeErr := file.Close()
		if n != len(part.raw) || writeErr != nil || closeErr != nil {
			t.Fatal("private ordinary output capture failed")
		}
		*written += int64(n)
	}
}

// Tail faults apply only AFTER a successfully completed real production
// callback. A browser/measurement failure cannot impersonate the tail witness.
type hashOrdinaryTailSupervisor struct {
	hashSealTailSupervisor
	completed   atomic.Bool
	tailReached atomic.Bool
}

func (s *hashOrdinaryTailSupervisor) Run(ctx context.Context, logger *slog.Logger, task func() error) error {
	err := s.ProcessSupervisor.Run(ctx, logger, func() error {
		result := task()
		if result == nil {
			s.completed.Store(true)
		}
		return result
	})
	if err != nil {
		return err
	}
	if !s.completed.Load() {
		return ordinarypage.ErrUnavailableV1
	}
	s.tailReached.Store(true)
	if s.cancel != nil {
		s.cancel()
	}
	return s.failure
}

func TestHashOrdinaryPDFGenuineRefusals(t *testing.T) {
	mod, b := hashPublicFixtureModule(t)
	initial := hashBrowserTargets(t, b)
	baseline, err := hashTargetSnapshot(b)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	font := hashOrdinaryGenuineFont(t)
	for _, mode := range []string{"narrow-overflow", "short-height", "overlapping-ink", "fallback-script", "wrong-font-bytes", "javascript-settings", "already-cancelled", "no-deadline", "cancel-after-callback", "failure-after-callback"} {
		t.Run(mode, func(t *testing.T) {
			p := hashOrdinaryPlan()
			ownFont := bytes.Clone(font)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			originalSupervisor := mod.supervisor
			var tail *hashOrdinaryTailSupervisor
			originalDisableJS := b.arguments.disableJavaScript
			defer func() { mod.supervisor = originalSupervisor; b.arguments.disableJavaScript = originalDisableJS }()
			switch mode {
			case "narrow-overflow":
				p.Fields[0].WPct = ".1"
				p.Fields[0].Value = "W"
			case "short-height":
				p.Fields[0].HPct = ".5"
			case "overlapping-ink":
				p.Fields = append(p.Fields, hashOrdinaryField(2, "text", p.Fields[0].Value, "10", "20", "45", "12"))
			case "fallback-script":
				p.Fields[0].Value = "Inter 🙂 漢"
			case "wrong-font-bytes":
				ownFont[0] ^= 1
			case "javascript-settings":
				b.arguments.disableJavaScript = false
			case "already-cancelled":
				cancel()
			case "no-deadline":
				ctx = context.Background()
			case "cancel-after-callback":
				tail = &hashOrdinaryTailSupervisor{hashSealTailSupervisor: hashSealTailSupervisor{ProcessSupervisor: originalSupervisor, cancel: cancel}}
				mod.supervisor = tail
			case "failure-after-callback":
				tail = &hashOrdinaryTailSupervisor{hashSealTailSupervisor: hashSealTailSupervisor{ProcessSupervisor: originalSupervisor, failure: errors.New("owned ordinary supervisor tail refusal")}}
				mod.supervisor = tail
			}
			p = hashOrdinaryBindPlan(t, p)
			pack, err := mod.prepareHashOrdinaryPDF(ctx, logger, p, ownFont)
			if err == nil || pack != nil {
				t.Fatal("ordinary refusal published a candidate")
			}
			if tail != nil && (!tail.completed.Load() || !tail.tailReached.Load()) {
				t.Fatal("genuine producer did not complete before owned supervisor tail fault")
			}
			if (mode == "already-cancelled" || mode == "cancel-after-callback") && !errors.Is(err, context.Canceled) {
				t.Fatal("ordinary cancellation sentinel lost")
			}
			hashOrdinaryAssertJoined(t, mod, b, initial, baseline)
		})
	}
}

func TestHashOrdinaryPDFSnapshotGenuineMutations(t *testing.T) {
	mod, b := hashPublicFixtureModule(t)
	initial := hashBrowserTargets(t, b)
	baseline, err := hashTargetSnapshot(b)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	font := hashOrdinaryGenuineFont(t)
	for _, mode := range []string{"missing-middle-text", "hidden-ink", "clipped-svg", "extra-opaque-paint", "checkbox-path"} {
		t.Run(mode, func(t *testing.T) {
			p := hashOrdinaryPlan()
			if mode == "checkbox-path" {
				p.Fields[0].Type = "checkbox"
				p.Fields[0].Value = "true"
			}
			p = hashOrdinaryBindPlan(t, p)
			seal, err := ordinarypage.NewSealV1(p, font)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "index.html")
			html := seal.HTML()
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			n, writeErr := file.Write(html)
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil || n != len(html) {
				t.Fatal("owned private fault fixture write")
			}
			u := (&url.URL{Scheme: "file", Path: path}).String()
			options := DefaultOptions()
			options.AllowedFilePrefixes = []string{dir}
			options.EmulatedMediaType = "print"
			options.OmitBackground = true
			options.FailOnResourceLoadingFailed = true
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			measured, printed, mutated := false, false, false
			err = mod.supervisor.Run(ctx, logger, func() error {
				return b.do(ctx, logger, u, options, nil, chromedp.Tasks{
					network.Enable(), fetch.Enable(), runtime.Enable(), disableJavaScriptActionFunc(logger, true), navigateActionFunc(logger, u, true, true),
					hideDefaultWhiteBackgroundActionFunc(logger, true, true), emulateMediaTypeActionFunc(logger, "print", nil),
					chromedp.ActionFunc(func(task context.Context) error {
						if err := ordinarypage.MeasureV1(task, seal); err != nil {
							return err
						}
						if _, err := ordinarypage.SnapshotV1(task, seal); err != nil {
							return err
						}
						measured = true
						if err := hashNavigationBarrierAction().Do(task); err != nil {
							return err
						}
						width, height, _ := p.Geometry.ViewportPointsV1()
						pdf, err := b.hashPrintSignaturePDF(task, width, height)
						if err != nil {
							return err
						}
						if len(pdf) < 1024 || !bytes.HasPrefix(pdf, []byte("%PDF-")) {
							return errors.New("native fault-fixture print failed")
						}
						printed = true
						if err := hashNavigationBarrierAction().Do(task); err != nil {
							return err
						}
						frame, err := page.GetFrameTree().Do(task)
						if err != nil || frame == nil || frame.Frame == nil {
							return errors.New("fault frame unavailable")
						}
						world, err := page.CreateIsolatedWorld(frame.Frame.ID).WithWorldName("hash-ordinary-test-fault").WithGrantUniveralAccess(false).Do(task)
						if err != nil {
							return err
						}
						arg, _ := json.Marshal(mode)
						_, exception, err := runtime.CallFunctionOn("function(mode){const s=document.getElementById('ordinary-field-0'),n=document.getElementById('ordinary-line-0-0');if(mode==='missing-middle-text')n.textContent=n.textContent.slice(0,5)+n.textContent.slice(6);else if(mode==='hidden-ink')n.style.opacity='0';else if(mode==='clipped-svg')s.style.overflow='hidden';else if(mode==='extra-opaque-paint'){const d=document.createElement('div');d.style='position:absolute;inset:0;background:white';document.body.appendChild(d)}else if(mode==='checkbox-path')s.querySelector('path').setAttribute('d','M1 1 L10 10');else throw new Error('mode');}").WithExecutionContextID(world).WithArguments([]*runtime.CallArgument{{Value: arg}}).WithReturnByValue(true).WithSilent(true).Do(task)
						if err != nil || exception != nil {
							return errors.New("owned snapshot fault was not applied")
						}
						mutated = true
						if _, err := ordinarypage.SnapshotV1(task, seal); err != nil {
							return err
						}
						return errors.New("changed ordinary snapshot accepted")
					}), page.Close(),
				})
			})
			if !measured || !printed || !mutated {
				t.Fatalf("genuine mutation witness did not reach measured/printed/mutated checkpoints: %v", err)
			}
			if !errors.Is(err, ordinarypage.ErrUnavailableV1) {
				t.Fatalf("ordinary snapshot mutation was not refused: %v", err)
			}
			hashOrdinaryAssertJoined(t, mod, b, initial, baseline)
		})
	}
}
