package chromium

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/css"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

const hashMeasurePolicy = "hash-manual-signature-measurement-v1"

var errHashSignatureMeasure = errors.New("hash signature measurement unavailable")
var hashMeasureDecimalPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,2})?$`)

// This is a measurement-only private seam. Neither public options nor an HTTP
// route can activate it. Successful measurements still refuse PrintToPDF until
// exact PDF sealing, immutable retention and recovery are integrated.
// Source/geometry/span digests here are declarations bound into the report;
// the application must verify those objects and rebind all targets under lock.
type hashSignatureMeasurePlan struct {
	Text           string              `json:"text"`
	Font           string              `json:"font"`
	SourceSHA256   string              `json:"sourceSha256"`
	GeometrySHA256 string              `json:"geometrySha256"`
	SpanSHA256     string              `json:"spanSha256"`
	Page           int                 `json:"page"`
	WidthPoints    string              `json:"widthPoints"`
	HeightPoints   string              `json:"heightPoints"`
	Targets        []hashMeasureTarget `json:"targets"`
	report         *hashSignatureMeasurement
}

type hashMeasureTarget struct {
	ID string `json:"id"`
	X  string `json:"x"`
	Y  string `json:"y"`
	W  string `json:"w"`
	H  string `json:"h"`
}

type hashMeasureFont struct{ file, sha, family, postscript string }

func hashPinnedMeasureFont(name string) (hashMeasureFont, bool) {
	fonts := map[string]hashMeasureFont{
		"Caveat":         {"Caveat.woff2", "d0b7b931b8980049327e8f8f9ac264617c8200b8422d62e886473d3d9527bad3", "Caveat", "Caveat-Regular"},
		"Dancing Script": {"DancingScript.woff2", "570e4265bbcb453353ce2fdf63d179332d8daa92691d567547b8a383f3b46c3b", "Dancing Script", "DancingScript-Regular"},
		"Great Vibes":    {"GreatVibes.woff2", "c59dc73d29daf142ef2431f455d21464172374aa750d793a79d608735db2d856", "Great Vibes", "GreatVibes-Regular"},
		"Sacramento":     {"Sacramento.woff2", "2fcd867d2812578d001b0eca921848e24de91d01986f26e038be374ec7c5cfd2", "Sacramento", "Sacramento-Regular"},
		"Homemade Apple": {"HomemadeApple.woff2", "bbaa96c741caa479d4647fc567f64e5ddc71eec58ee9849cb9e8a14bee65bc30", "Homemade Apple", "HomemadeApple-Regular"},
	}
	f, ok := fonts[name]
	return f, ok
}

func hashMeasureDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s && s != strings.Repeat("0", 64)
}

func hashMeasureID(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Preserve the exact decimal strings in the commitment; only the closed
// renderer argument uses a float. Reject overflow and out-of-page rectangles
// with rational arithmetic before any browser work.
func hashMeasureDecimal(s string) (*big.Rat, float64, bool) {
	if len(s) == 0 || len(s) > 128 || !hashMeasureDecimalPattern.MatchString(s) {
		return nil, 0, false
	}
	if at := strings.IndexAny(s, "eE"); at >= 0 {
		exponent, err := strconv.Atoi(s[at+1:])
		if err != nil || exponent < -32 || exponent > 32 {
			return nil, 0, false
		}
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Num().BitLen() > 1024 || r.Denom().BitLen() > 1024 {
		return nil, 0, false
	}
	v, _ := r.Float64()
	return r, v, !math.IsInf(v, 0) && !math.IsNaN(v)
}

func (p *hashSignatureMeasurePlan) valid() bool {
	if p == nil || !(&hashManualFitPlan{text: p.Text, font: p.Font}).valid() || !hashMeasureDigest(p.SourceSHA256) || !hashMeasureDigest(p.GeometrySHA256) || !hashMeasureDigest(p.SpanSHA256) || p.Page < 1 || p.Page > 500 || len(p.Targets) < 1 || len(p.Targets) > 128 {
		return false
	}
	_, width, okW := hashMeasureDecimal(p.WidthPoints)
	_, height, okH := hashMeasureDecimal(p.HeightPoints)
	if !okW || !okH || width <= 0 || height <= 0 || width > 14400 || height > 14400 {
		return false
	}
	previous := ""
	zero, one := new(big.Rat), big.NewRat(1, 1)
	for _, t := range p.Targets {
		if !hashMeasureID(t.ID) || t.ID <= previous {
			return false
		}
		previous = t.ID
		x, _, okX := hashMeasureDecimal(t.X)
		y, _, okY := hashMeasureDecimal(t.Y)
		w, _, okW := hashMeasureDecimal(t.W)
		h, _, okH := hashMeasureDecimal(t.H)
		if !okX || !okY || !okW || !okH || x.Cmp(zero) < 0 || y.Cmp(zero) < 0 || w.Cmp(zero) <= 0 || h.Cmp(zero) <= 0 || new(big.Rat).Add(x, w).Cmp(one) > 0 || new(big.Rat).Add(y, h).Cmp(one) > 0 {
			return false
		}
	}
	return true
}

func (p *hashSignatureMeasurePlan) inputSHA() string {
	b, _ := json.Marshal(p) // report is private and cannot participate.
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// Only this generated inert document is permitted for measurement. Callers
// provide no HTML, script, CSS, URL, alias, fallback or arbitrary font asset.
func hashSignatureMeasureHTML(p *hashSignatureMeasurePlan, font []byte) (string, error) {
	if !p.valid() {
		return "", errHashSignatureMeasure
	}
	f, ok := hashPinnedMeasureFont(p.Font)
	if !p.valid() || !ok || fmt.Sprintf("%x", sha256.Sum256(font)) != f.sha {
		return "", errHashSignatureMeasure
	}
	_, width, _ := hashMeasureDecimal(p.WidthPoints)
	_, height, _ := hashMeasureDecimal(p.HeightPoints)
	return fmt.Sprintf(hashSignatureMeasureHTMLRecipe, hashMeasurePolicy, p.inputSHA(), f.family, base64.StdEncoding.EncodeToString(font), strconv.FormatFloat(width, 'g', -1, 64), strconv.FormatFloat(height, 'g', -1, 64), strconv.FormatFloat(width, 'g', -1, 64), strconv.FormatFloat(height, 'g', -1, 64)), nil
}

// Versioned inert document recipe; include these exact bytes in seal identity.
const hashSignatureMeasureHTMLRecipe = `<!doctype html><html data-hash-measure-policy="%s" data-hash-measure-input="%s"><meta charset="utf-8"><style>@font-face{font-family:"%s";src:url("data:font/woff2;base64,%s") format("woff2");font-weight:400;font-style:normal;font-display:block} @page{size:%spt %spt;margin:0}html,body{margin:0;padding:0;width:%spt;height:%spt;background:transparent}svg{position:absolute;overflow:visible}text{white-space:pre;font-kerning:normal;font-variant-ligatures:normal;font-variant-caps:normal;letter-spacing:0;word-spacing:0;direction:ltr;unicode-bidi:isolate;fill:#111827}</style><body></body></html>`

type hashMeasureBBox struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}
type hashMeasureLine struct {
	Text        string                   `json:"text"`
	HardBreak   string                   `json:"hardBreak"`
	X           float64                  `json:"x"`
	Y           float64                  `json:"y"`
	Advance     float64                  `json:"advance"`
	InkLeft     float64                  `json:"inkLeft"`
	InkRight    float64                  `json:"inkRight"`
	InkAscent   float64                  `json:"inkAscent"`
	InkDescent  float64                  `json:"inkDescent"`
	FontAscent  float64                  `json:"fontAscent"`
	FontDescent float64                  `json:"fontDescent"`
	BBox        hashMeasureBBox          `json:"bbox"`
	Fonts       []*css.PlatformFontUsage `json:"fonts,omitempty"`
}
type hashMeasuredTarget struct {
	ID             string            `json:"id"`
	FontSizePoints float64           `json:"fontSizePoints"`
	WidthPX        float64           `json:"widthPx"`
	HeightPX       float64           `json:"heightPx"`
	ViewportBBox   hashMeasureBBox   `json:"viewportBBox"`
	Lines          []hashMeasureLine `json:"lines"`
}
type hashMeasureDOMReport struct {
	Schema                 int                  `json:"schema"`
	TextPreserved          bool                 `json:"textPreserved"`
	PrintMedia             bool                 `json:"printMedia"`
	DocumentScriptsBlocked bool                 `json:"documentScriptsBlocked"`
	Targets                []hashMeasuredTarget `json:"targets"`
}
type hashSignatureMeasurement struct {
	Policy      string               `json:"policy"`
	InputSHA256 string               `json:"inputSha256"`
	FontSHA256  string               `json:"fontSha256"`
	DOM         hashMeasureDOMReport `json:"dom"`
}

// A fixed twelve-size policy, four lines, 2pt padding, 1pt interline gap and
// 100000 shared Canvas measurements. Soft breaks insert no text. CRLF/CR/LF
// hard-break bytes remain separate text nodes. No normalization or truncation.
// Canvas ink metrics guide fitting; SVG getBBox verifies laid-out text-cell
// geometry. These observations do NOT prove glyph coverage or PDF paint.
const hashSignatureMeasureFunction = `async function(input) {
  "use strict";
  const start = performance.now(); let work = 0;
  const alive = () => { if (++work > 100000 || performance.now()-start > 2000) throw new Error("budget"); };
  const sentinel = () => !document.documentElement.hasAttribute("data-hash-page-script") && !document.documentElement.hasAttribute("data-hash-event-handler") && !document.getElementById("hash-page-script-effect");
  if (document.documentElement.getAttribute("data-hash-measure-policy") !== input.policy || document.documentElement.getAttribute("data-hash-measure-input") !== input.inputSha || document.body.childNodes.length !== 0 || !sentinel() || !matchMedia("print").matches || typeof Intl.Segmenter !== "function") throw new Error("document");
  const loaded = await document.fonts.load('24px "'+input.font+'"', input.text); await document.fonts.ready; alive();
  if (loaded.length !== 1 || loaded[0].status !== "loaded") throw new Error("font");
  const canvas = document.createElement("canvas"), ctx = canvas.getContext("2d"); if (!ctx) throw new Error("canvas");
  const segmenter = new Intl.Segmenter("und",{granularity:"grapheme"}), padding=8/3, gap=4/3;
  const cache = new Map(); let sizePX=0;
  const metric = text => {
    const key=sizePX+"/"+text; if(cache.has(key)) return cache.get(key);
    alive(); ctx.font=sizePX+'px "'+input.font+'"'; ctx.textAlign="left";ctx.textBaseline="alphabetic";ctx.direction="ltr";ctx.fontKerning="normal";ctx.fontVariantCaps="normal";
    const m=ctx.measureText(text), v={advance:m.width,left:m.actualBoundingBoxLeft,right:m.actualBoundingBoxRight,ascent:m.actualBoundingBoxAscent,descent:m.actualBoundingBoxDescent,fontAscent:m.fontBoundingBoxAscent,fontDescent:m.fontBoundingBoxDescent};
    if(Object.values(v).some(x=>!Number.isFinite(x)||Math.abs(x)>100000)) throw new Error("metrics"); cache.set(key,v);return v;
  };
  const extent=m=>Math.max(m.advance,m.right)-Math.min(0,-m.left);
  const chunks=Array.from(segmenter.segment(input.text), s=>s.segment);
  const results=[];
  for(let i=0;i<input.targets.length;i++) {
    alive(); const target=input.targets[i], innerW=target.widthPx-2*padding,innerH=target.heightPx-2*padding;
    let accepted=null;
    for(const points of [48,44,40,36,32,28,24,20,18,16,14,12]) {
      alive();sizePX=points*4/3;let lines=[],text="",hard="",bad=innerW<=0||innerH<=0;
      const append=()=>{lines.push({text,hardBreak:hard,m:metric(text)});text="";hard="";if(lines.length>4) bad=true;};
      for(const chunk of chunks) {
        if(bad) break;
        if(chunk==="\n"||chunk==="\r"||chunk==="\r\n") {hard=chunk;append();continue;}
        if(extent(metric(text+chunk))<=innerW) {text+=chunk;continue;}
        if(text==="") {bad=true;break;} append();
        if(extent(metric(chunk))>innerW) {bad=true;break;} text=chunk;
      }
      if(bad) continue; append(); if(bad) continue;
      // Empty hard-break lines consume readable vertical space too.
      let total=0;
      for(const line of lines) {line.height=Math.max(sizePX,Math.max(0,line.m.ascent,line.m.fontAscent)+Math.max(0,line.m.descent,line.m.fontDescent));total+=line.height;}
      total+=gap*(lines.length-1);if(total>innerH) continue;
      const ns="http://www.w3.org/2000/svg",svg=document.createElementNS(ns,"svg");
      svg.id="hash-measure-target-"+i;svg.setAttribute("width",target.widthPx);svg.setAttribute("height",target.heightPx);svg.setAttribute("viewBox","0 0 "+target.widthPx+" "+target.heightPx);
      svg.style.left=target.leftPx+"px";svg.style.top=target.topPx+"px";document.body.appendChild(svg);
      let top=padding; const observed=[];
      for(let j=0;j<lines.length;j++) {
        const line=lines[j],m=line.m,node=document.createElementNS(ns,"text"),x=padding-Math.min(0,-m.left),y=top+Math.max(0,m.ascent,m.fontAscent);
        node.id="hash-measure-line-"+i+"-"+j;node.setAttribute("x",x);node.setAttribute("y",y);node.setAttribute("font-family",input.font);node.setAttribute("font-size",sizePX);node.setAttribute("font-weight","400");node.textContent=line.text;svg.appendChild(node);
        if(line.hardBreak) svg.appendChild(document.createTextNode(line.hardBreak));
        const b=node.getBBox(),bbox={x:b.x,y:b.y,width:b.width,height:b.height};
        const style=getComputedStyle(node);
        const empty=line.text==="";
        if(!node.isConnected || node.textContent!==line.text || Math.abs(parseFloat(style.fontSize)-sizePX)>0.001 || Object.values(bbox).some(v=>!Number.isFinite(v)) || b.width<0 || b.height<0 || (!empty && (b.x<padding-0.25 || b.y<padding-0.25 || b.x+b.width>target.widthPx-padding+0.25 || b.y+b.height>target.heightPx-padding+0.25)) || x-m.left<padding-0.25 || x+m.right>target.widthPx-padding+0.25 || y-m.ascent<padding-0.25 || y+m.descent>target.heightPx-padding+0.25) {bad=true;break;}
        observed.push({text:line.text,hardBreak:line.hardBreak,x,y,advance:m.advance,inkLeft:m.left,inkRight:m.right,inkAscent:m.ascent,inkDescent:m.descent,fontAscent:m.fontAscent,fontDescent:m.fontDescent,bbox});top+=line.height+gap;
      }
      if(bad || svg.textContent!==input.text) {svg.remove();continue;}
      const placed=svg.getBoundingClientRect(),viewportBBox={x:placed.x,y:placed.y,width:placed.width,height:placed.height};
      if(Math.abs(placed.x-target.leftPx)>1/32 || Math.abs(placed.y-target.topPx)>1/32 || Math.abs(placed.width-target.widthPx)>1/32 || Math.abs(placed.height-target.heightPx)>1/32) {svg.remove();continue;}
      accepted={id:target.id,fontSizePoints:points,widthPx:target.widthPx,heightPx:target.heightPx,viewportBBox,lines:observed};break;
    }
    if(!accepted) throw new Error("unreadable");results.push(accepted);
  }
  alive();return {schema:1,textPreserved:document.body.textContent===input.text.repeat(input.targets.length),printMedia:matchMedia("print").matches,documentScriptsBlocked:sentinel(),targets:results};
}`

// Reject duplicate keys and nulls recursively; DisallowUnknownFields alone
// accepts duplicate/missing scalar keys and null. Validation below requires
// every target, exact text, sizes, geometry and valid ink/BBox observations.
func hashMeasureJSONToken(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errHashSignatureMeasure
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return errHashSignatureMeasure
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			s, ok := key.(string)
			if err != nil || !ok || seen[s] {
				return errHashSignatureMeasure
			}
			seen[s] = true
			if err = hashMeasureJSONToken(d, depth+1); err != nil {
				return err
			}
		}
		if t, err = d.Token(); err != nil || t != json.Delim('}') {
			return errHashSignatureMeasure
		}
	case json.Delim('['):
		for d.More() {
			if err = hashMeasureJSONToken(d, depth+1); err != nil {
				return err
			}
		}
		if t, err = d.Token(); err != nil || t != json.Delim(']') {
			return errHashSignatureMeasure
		}
	}
	return nil
}

func hashMeasureClose(a, b float64) bool { return math.Abs(a-b) <= 0.001 }
func hashMeasureClosedKeys(raw []byte, keys ...string) bool {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := values[key]; !ok {
			return false
		}
	}
	return true
}
func decodeHashMeasurement(raw []byte, p *hashSignatureMeasurePlan) (*hashMeasureDOMReport, error) {
	if !p.valid() || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errHashSignatureMeasure
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if hashMeasureJSONToken(d, 0) != nil {
		return nil, errHashSignatureMeasure
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errHashSignatureMeasure
	}
	if !hashMeasureClosedKeys(raw, "schema", "textPreserved", "printMedia", "documentScriptsBlocked", "targets") {
		return nil, errHashSignatureMeasure
	}
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	var targets []json.RawMessage
	_ = json.Unmarshal(top["targets"], &targets)
	for _, target := range targets {
		if !hashMeasureClosedKeys(target, "id", "fontSizePoints", "widthPx", "heightPx", "viewportBBox", "lines") {
			return nil, errHashSignatureMeasure
		}
		var t map[string]json.RawMessage
		_ = json.Unmarshal(target, &t)
		if !hashMeasureClosedKeys(t["viewportBBox"], "x", "y", "width", "height") {
			return nil, errHashSignatureMeasure
		}
		var lines []json.RawMessage
		_ = json.Unmarshal(t["lines"], &lines)
		for _, line := range lines {
			if !hashMeasureClosedKeys(line, "text", "hardBreak", "x", "y", "advance", "inkLeft", "inkRight", "inkAscent", "inkDescent", "fontAscent", "fontDescent", "bbox") {
				return nil, errHashSignatureMeasure
			}
			var l map[string]json.RawMessage
			_ = json.Unmarshal(line, &l)
			if !hashMeasureClosedKeys(l["bbox"], "x", "y", "width", "height") {
				return nil, errHashSignatureMeasure
			}
		}
	}
	var r hashMeasureDOMReport
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || r.Schema != 1 || !r.TextPreserved || !r.PrintMedia || !r.DocumentScriptsBlocked || len(r.Targets) != len(p.Targets) {
		return nil, errHashSignatureMeasure
	}
	_, pw, _ := hashMeasureDecimal(p.WidthPoints)
	_, ph, _ := hashMeasureDecimal(p.HeightPoints)
	for i, t := range r.Targets {
		_, x, _ := hashMeasureDecimal(p.Targets[i].X)
		_, y, _ := hashMeasureDecimal(p.Targets[i].Y)
		_, w, _ := hashMeasureDecimal(p.Targets[i].W)
		_, h, _ := hashMeasureDecimal(p.Targets[i].H)
		if t.ID != p.Targets[i].ID || !hashMeasureClose(t.WidthPX, w*pw*4/3) || !hashMeasureClose(t.HeightPX, h*ph*4/3) || len(t.Lines) < 1 || len(t.Lines) > 4 {
			return nil, errHashSignatureMeasure
		}
		for _, pair := range [][2]float64{{t.ViewportBBox.X, x * pw * 4 / 3}, {t.ViewportBBox.Y, y * ph * 4 / 3}, {t.ViewportBBox.Width, w * pw * 4 / 3}, {t.ViewportBBox.Height, h * ph * 4 / 3}} {
			if math.IsNaN(pair[0]) || math.IsInf(pair[0], 0) || math.Abs(pair[0]-pair[1]) > 1.0/32 {
				return nil, errHashSignatureMeasure
			}
		}
		validSize := false
		for _, s := range []float64{48, 44, 40, 36, 32, 28, 24, 20, 18, 16, 14, 12} {
			if t.FontSizePoints == s {
				validSize = true
			}
		}
		if !validSize {
			return nil, errHashSignatureMeasure
		}
		text := ""
		for _, line := range t.Lines {
			if line.Fonts != nil || !(line.HardBreak == "" || line.HardBreak == "\r" || line.HardBreak == "\n" || line.HardBreak == "\r\n") {
				return nil, errHashSignatureMeasure
			}
			text += line.Text + line.HardBreak
			for _, v := range []float64{line.X, line.Y, line.Advance, line.InkLeft, line.InkRight, line.InkAscent, line.InkDescent, line.FontAscent, line.FontDescent, line.BBox.X, line.BBox.Y, line.BBox.Width, line.BBox.Height} {
				if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 100000 {
					return nil, errHashSignatureMeasure
				}
			}
			if line.Advance < 0 || line.FontAscent < 0 || line.FontDescent < 0 || line.BBox.Width < 0 || line.BBox.Height < 0 || line.X-line.InkLeft < 8.0/3-0.25 || line.X+line.InkRight > t.WidthPX-8.0/3+0.25 || line.Y-line.InkAscent < 8.0/3-0.25 || line.Y+line.InkDescent > t.HeightPX-8.0/3+0.25 {
				return nil, errHashSignatureMeasure
			}
			if line.Text != "" && (line.BBox.X < 8.0/3-0.25 || line.BBox.Y < 8.0/3-0.25 || line.BBox.X+line.BBox.Width > t.WidthPX-8.0/3+0.25 || line.BBox.Y+line.BBox.Height > t.HeightPX-8.0/3+0.25) {
				return nil, errHashSignatureMeasure
			}
		}
		if text != p.Text {
			return nil, errHashSignatureMeasure
		}
	}
	return &r, nil
}

func hashSignatureMeasurementAction(p *hashSignatureMeasurePlan) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if p == nil {
			return nil
		}
		p.report = nil
		if !p.valid() {
			return errHashSignatureMeasure
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		f, _ := hashPinnedMeasureFont(p.Font)
		_, pw, _ := hashMeasureDecimal(p.WidthPoints)
		_, ph, _ := hashMeasureDecimal(p.HeightPoints)
		type targetArg struct {
			ID       string  `json:"id"`
			LeftPX   float64 `json:"leftPx"`
			TopPX    float64 `json:"topPx"`
			WidthPX  float64 `json:"widthPx"`
			HeightPX float64 `json:"heightPx"`
		}
		args := struct {
			Policy   string      `json:"policy"`
			InputSHA string      `json:"inputSha"`
			Text     string      `json:"text"`
			Font     string      `json:"font"`
			Targets  []targetArg `json:"targets"`
		}{Policy: hashMeasurePolicy, InputSHA: p.inputSHA(), Text: p.Text, Font: p.Font}
		for _, t := range p.Targets {
			_, x, _ := hashMeasureDecimal(t.X)
			_, y, _ := hashMeasureDecimal(t.Y)
			_, w, _ := hashMeasureDecimal(t.W)
			_, h, _ := hashMeasureDecimal(t.H)
			args.Targets = append(args.Targets, targetArg{t.ID, x * pw * 4 / 3, y * ph * 4 / 3, w * pw * 4 / 3, h * ph * 4 / 3})
		}
		arg, _ := json.Marshal(args)
		frame, err := page.GetFrameTree().Do(callCtx)
		if err != nil || frame == nil || frame.Frame == nil {
			return errHashSignatureMeasure
		}
		world, err := page.CreateIsolatedWorld(frame.Frame.ID).WithWorldName(hashMeasurePolicy).WithGrantUniveralAccess(false).Do(callCtx)
		if err != nil || world == 0 {
			return errHashSignatureMeasure
		}
		value, exception, err := runtime.CallFunctionOn(hashSignatureMeasureFunction).WithExecutionContextID(world).WithArguments([]*runtime.CallArgument{{Value: arg}}).WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true).WithUserGesture(false).Do(callCtx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if exception != nil && exception.Exception != nil {
			for _, reason := range []string{"budget", "document", "font", "canvas", "metrics", "unreadable"} {
				if strings.HasPrefix(exception.Exception.Description, "Error: "+reason+"\n") || exception.Exception.Description == "Error: "+reason {
					return fmt.Errorf("%w: %s", errHashSignatureMeasure, reason)
				}
			}
		}
		if callCtx.Err() != nil || err != nil || exception != nil || value == nil || value.Type != runtime.TypeObject {
			return errHashSignatureMeasure
		}
		r, err := decodeHashMeasurement(value.Value, p)
		if err != nil {
			return err
		}
		// The target attachment already enabled CSS before navigation. Avoid the
		// redundant resource preload while preserving the enabled font inspector.
		if dom.Enable().Do(callCtx) != nil {
			return errHashSignatureMeasure
		}
		root, err := dom.GetDocument().Do(callCtx)
		if err != nil || root == nil {
			return errHashSignatureMeasure
		}
		for i := range r.Targets {
			for j := range r.Targets[i].Lines {
				line := &r.Targets[i].Lines[j]
				if strings.TrimSpace(line.Text) == "" {
					continue
				}
				node, err := dom.QuerySelector(root.NodeID, fmt.Sprintf("#hash-measure-line-%d-%d", i, j)).Do(callCtx)
				if err != nil || node == 0 {
					return errHashSignatureMeasure
				}
				fonts, err := css.GetPlatformFontsForNode(node).Do(callCtx)
				if err != nil || len(fonts) != 1 || fonts[0] == nil {
					return errHashSignatureMeasure
				}
				observed := fonts[0]
				if !observed.IsCustomFont || observed.FamilyName != f.family || observed.PostScriptName != f.postscript || observed.GlyphCount <= 0 || observed.GlyphCount > 800 || math.IsInf(observed.GlyphCount, 0) || math.IsNaN(observed.GlyphCount) {
					return errHashSignatureMeasure
				}
				line.Fonts = fonts
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if callCtx.Err() != nil {
			return errHashSignatureMeasure
		}
		p.report = &hashSignatureMeasurement{Policy: hashMeasurePolicy, InputSHA256: p.inputSHA(), FontSHA256: f.sha, DOM: *r}
		return errHashFitNotReady
	})
}
