package chromium

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

var (
	errHashFitIsolation  = errors.New("hash signature fit requires disabled page scripts")
	errHashFitCapability = errors.New("hash signature fit capability unavailable")
	errHashFitNotReady   = errors.New("hash signature fitting not activated")
)

// This private seam is deliberately not activated by an HTTP route or by an
// exported API. Capability observations are not signature admission. Until
// measured fitting, font attribution, PDF binding and retained recovery recipes
// are implemented, even a successful probe refuses before PrintToPDF.
type hashManualFitPlan struct {
	text       string
	font       string
	capability *hashFitCapability
}

type hashFitCapability struct {
	Schema                 int     `json:"schema"`
	DocumentScriptsBlocked bool    `json:"documentScriptsBlocked"`
	DOMAccessible          bool    `json:"domAccessible"`
	StyleApplied           bool    `json:"styleApplied"`
	PrintMedia             bool    `json:"printMedia"`
	FontLoaded             bool    `json:"fontLoaded"`
	TextPreserved          bool    `json:"textPreserved"`
	Graphemes              int     `json:"graphemes"`
	Advance                float64 `json:"advance"`
	InkLeft                float64 `json:"inkLeft"`
	InkRight               float64 `json:"inkRight"`
	InkAscent              float64 `json:"inkAscent"`
	InkDescent             float64 `json:"inkDescent"`
}

// No interpolation: names and font selection travel as typed JSON arguments.
// The DOM sentinel checks are intentional: main-world globals are invisible to
// an isolated world and would give false evidence of disabled page scripts.
const hashFitCapabilityFunction = `async function(input) {
  "use strict";
  const before = performance.now();
  const alive = () => { if (performance.now() - before > 1000) throw new Error("deadline"); };
  const sentinel = () => document.documentElement.getAttribute("data-hash-page-script") === null
    && document.documentElement.getAttribute("data-hash-event-handler") === null
    && document.getElementById("hash-page-script-effect") === null;
  const root = document.getElementById("hash-fit-capability-target");
  if (!root || !sentinel() || typeof Intl.Segmenter !== "function") throw new Error("capability");
  const loaded = await document.fonts.load('24px "' + input.font + '"', input.text);
  await document.fonts.ready;
  alive();
  if (loaded.length !== 1 || loaded[0].status !== "loaded") throw new Error("font");
  root.textContent = input.text;
  root.style.fontFamily = '"' + input.font + '"';
  root.style.fontSize = "24px";
  root.style.whiteSpace = "pre";
  root.style.color = "rgb(1, 2, 3)";
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("canvas");
  ctx.font = '24px "' + input.font + '"';
  ctx.textAlign = "left";
  ctx.textBaseline = "alphabetic";
  ctx.direction = "ltr";
  const metrics = ctx.measureText(input.text);
  const result = {
    schema: 1,
    documentScriptsBlocked: sentinel(),
    domAccessible: root.isConnected,
    styleApplied: getComputedStyle(root).color === "rgb(1, 2, 3)" && getComputedStyle(root).fontSize === "24px",
    printMedia: matchMedia("print").matches,
    fontLoaded: document.fonts.check('24px "' + input.font + '"', input.text),
    textPreserved: root.textContent === input.text,
    graphemes: Array.from(new Intl.Segmenter("und", {granularity: "grapheme"}).segment(input.text)).length,
    advance: metrics.width,
    inkLeft: metrics.actualBoundingBoxLeft,
    inkRight: metrics.actualBoundingBoxRight,
    inkAscent: metrics.actualBoundingBoxAscent,
    inkDescent: metrics.actualBoundingBoxDescent
  };
  alive();
  return result;
}`

func (p *hashManualFitPlan) valid() bool {
	if p == nil || !utf8.ValidString(p.text) || len(p.text) > 800 || utf8.RuneCountInString(p.text) > 200 || strings.TrimSpace(p.text) == "" {
		return false
	}
	switch p.font {
	case "Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple":
		return true
	default:
		return false
	}
}

func decodeHashFitCapability(raw []byte) (*hashFitCapability, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, errHashFitCapability
	}
	// Require every closed report key exactly once; encoding/json alone accepts
	// duplicate keys, missing values and nulls for scalar fields.
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errHashFitCapability
	}
	seen := make(map[string]bool)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return nil, errHashFitCapability
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errHashFitCapability
		}
	}
	if _, err = d.Token(); err != nil {
		return nil, errHashFitCapability
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errHashFitCapability
	}
	keys := []string{"schema", "documentScriptsBlocked", "domAccessible", "styleApplied", "printMedia", "fontLoaded", "textPreserved", "graphemes", "advance", "inkLeft", "inkRight", "inkAscent", "inkDescent"}
	if len(seen) != len(keys) {
		return nil, errHashFitCapability
	}
	for _, key := range keys {
		if !seen[key] {
			return nil, errHashFitCapability
		}
	}
	var report hashFitCapability
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&report) != nil || report.Schema != 1 || !report.DocumentScriptsBlocked || !report.DOMAccessible || !report.StyleApplied || !report.PrintMedia || !report.FontLoaded || !report.TextPreserved || report.Graphemes < 1 || report.Graphemes > 200 {
		return nil, errHashFitCapability
	}
	for _, v := range []float64{report.Advance, report.InkLeft, report.InkRight, report.InkAscent, report.InkDescent} {
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 100000 {
			return nil, errHashFitCapability
		}
	}
	if report.Advance <= 0 || report.InkAscent < 0 || report.InkDescent < 0 || report.InkLeft+report.InkRight <= 0 {
		return nil, errHashFitCapability
	}
	return &report, nil
}

func hashManualSignatureFitAction(plan *hashManualFitPlan) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if plan == nil {
			return nil
		}
		plan.capability = nil
		if !plan.valid() {
			return errHashFitCapability
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		// Keep the original conversion's executor/session and deadline. No
		// goroutine, new browser, universal access or script-enable toggle.
		frame, err := page.GetFrameTree().Do(callCtx)
		if err != nil || frame == nil || frame.Frame == nil {
			return errHashFitCapability
		}
		world, err := page.CreateIsolatedWorld(frame.Frame.ID).WithWorldName("hash-fit-capability-v1").WithGrantUniveralAccess(false).Do(callCtx)
		if err != nil || world == 0 {
			return errHashFitCapability
		}
		arg, err := json.Marshal(struct {
			Text string `json:"text"`
			Font string `json:"font"`
		}{plan.text, plan.font})
		if err != nil {
			return errHashFitCapability
		}
		value, exception, err := runtime.CallFunctionOn(hashFitCapabilityFunction).
			WithExecutionContextID(world).
			WithArguments([]*runtime.CallArgument{{Value: arg}}).
			WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true).WithUserGesture(false).Do(callCtx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if callCtx.Err() != nil {
			return errHashFitCapability
		}
		if err != nil || exception != nil || value == nil || value.Type != runtime.TypeObject {
			return errHashFitCapability
		}
		report, err := decodeHashFitCapability(value.Value)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if callCtx.Err() != nil {
			return errHashFitCapability
		}
		plan.capability = report
		return errHashFitNotReady
	})
}
