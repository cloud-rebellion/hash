package chromium

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/css"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

const (
	hashSignatureSealPolicy    = "hash-manual-signature-pdf-seal-v1"
	hashSignaturePDFLimit      = 8 << 20
	hashSignatureReportLimit   = 1 << 20
	hashSignatureHTMLLimit     = 2 << 20
	hashSignatureFontLimit     = 1 << 20
	hashSignatureSnapshotLimit = 4 << 20
	hashSignaturePackageHeader = 60 // magic, five uint32 lengths, report SHA256
	hashSignaturePrintRecipe   = "all-pages;scale=1;zero-margins;css-page-size;transparent;background;no-headers;no-tags;no-outline"
	hashSignatureSealCSS       = "html{-webkit-print-color-adjust:exact;print-color-adjust:exact}"
)

var errHashSignatureSeal = errors.New("hash signature PDF package unavailable")

// This capability and its only factory are private. The closed authenticated
// route calls this factory; there is no public PdfOptions switch, caller
// HTML/path/options or application signing fallback.
// Source digests are declarations; the application must verify exact objects,
// all source pages/targets and locked state before retaining or consuming this.
type hashSignatureSeal struct {
	plan                              hashSignatureMeasurePlan
	font, html, measurement, snapshot []byte
	inputSHA                          string
}

type hashSignaturePDFReport struct {
	Schema           int                      `json:"schema"`
	Policy           string                   `json:"policy"`
	Plan             hashSignatureMeasurePlan `json:"plan"`
	InputSHA256      string                   `json:"inputSha256"`
	RecipeSHA256     string                   `json:"recipeSha256"`
	HTMLSHA256       string                   `json:"htmlSha256"`
	FontFile         string                   `json:"fontFile"`
	FontSHA256       string                   `json:"fontSha256"`
	PDFSHA256        string                   `json:"pdfSha256"`
	PDFBytes         int                      `json:"pdfBytes"`
	FragmentPage     int                      `json:"fragmentPage"` // expected mapping, not parsed PDF proof
	SnapshotSHA256   string                   `json:"snapshotSha256"`
	ChromiumProduct  string                   `json:"chromiumProduct"`
	ChromiumRevision string                   `json:"chromiumRevision"`
	ChromiumProtocol string                   `json:"chromiumProtocol"`
	Measurement      hashSignatureMeasurement `json:"measurement"`
}

// Raw canonical report, PDF, generated source and pinned full font survive
// together. The report binds the other bytes; its external digest avoids a
// self-hash cycle. Accessors return copies, never mutable internal buffers.
type hashSignaturePDFPackage struct{ report, pdf, html, font, snapshot []byte }

func (p *hashSignaturePDFPackage) PDF() []byte    { return bytes.Clone(p.pdf) }
func (p *hashSignaturePDFPackage) Report() []byte { return bytes.Clone(p.report) }
func (p *hashSignaturePDFPackage) Bytes() []byte {
	r := make([]byte, hashSignaturePackageHeader, hashSignaturePackageHeader+len(p.report)+len(p.pdf)+len(p.html)+len(p.font)+len(p.snapshot))
	copy(r, "HSHFIT01")
	for i, b := range [][]byte{p.report, p.pdf, p.html, p.font, p.snapshot} {
		binary.BigEndian.PutUint32(r[8+i*4:], uint32(len(b)))
	}
	h := sha256.Sum256(p.report)
	copy(r[28:], h[:])
	for _, b := range [][]byte{p.report, p.pdf, p.html, p.font, p.snapshot} {
		r = append(r, b...)
	}
	return r
}

func hashSealSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hashSignatureRecipeSHA() string {
	return hashSealSHA([]byte(hashSignatureSealPolicy + "\x00" + hashSignaturePrintRecipe + "\x00" + hashSignatureMeasureHTMLRecipe + "\x00" + hashSignatureSealCSS + "\x00" + hashSignatureMeasureFunction + "\x00" + hashSignatureSnapshotFunction))
}
func hashSignatureSealHTML(p *hashSignatureMeasurePlan, font []byte) ([]byte, error) {
	s, err := hashSignatureMeasureHTML(p, font)
	if err != nil {
		return nil, errHashSignatureSeal
	}
	s = strings.Replace(s, "<style>", "<style>"+hashSignatureSealCSS, 1)
	if len(s) > hashSignatureHTMLLimit {
		return nil, errHashSignatureSeal
	}
	return []byte(s), nil
}
func newHashSignatureSeal(p *hashSignatureMeasurePlan, font []byte) (*hashSignatureSeal, error) {
	if p == nil || !p.valid() || len(font) == 0 || len(font) > hashSignatureFontLimit {
		return nil, errHashSignatureSeal
	}
	r := &hashSignatureSeal{plan: *p, font: bytes.Clone(font)}
	r.plan.Targets = append([]hashMeasureTarget(nil), p.Targets...)
	r.plan.report = nil
	r.inputSHA = r.plan.inputSHA()
	var err error
	r.html, err = hashSignatureSealHTML(&r.plan, r.font)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func hashValidSealedMeasurement(p *hashSignatureMeasurePlan, m *hashSignatureMeasurement) bool {
	if p == nil || !p.valid() {
		return false
	}
	f, ok := hashPinnedMeasureFont(p.Font)
	if !ok || m == nil || m.Policy != hashMeasurePolicy || m.InputSHA256 != p.inputSHA() || m.FontSHA256 != f.sha {
		return false
	}
	raw, err := json.Marshal(m.DOM)
	if err != nil {
		return false
	}
	var observed hashMeasureDOMReport
	if json.Unmarshal(raw, &observed) != nil {
		return false
	}
	for i := range observed.Targets {
		for j := range observed.Targets[i].Lines {
			l := &observed.Targets[i].Lines[j]
			if strings.TrimSpace(l.Text) == "" {
				if len(l.Fonts) != 0 {
					return false
				}
			} else {
				if len(l.Fonts) != 1 || l.Fonts[0] == nil {
					return false
				}
				v := l.Fonts[0]
				if !v.IsCustomFont || v.FamilyName != f.family || v.PostScriptName != f.postscript || v.GlyphCount <= 0 || v.GlyphCount > 800 || math.Trunc(v.GlyphCount) != v.GlyphCount {
					return false
				}
			}
			l.Fonts = nil
		}
	}
	raw, err = json.Marshal(observed)
	if err != nil {
		return false
	}
	_, err = decodeHashMeasurement(raw, p)
	return err == nil
}

func decodeHashSignaturePDFPackage(raw []byte, expected *hashSignatureMeasurePlan) (*hashSignaturePDFPackage, error) {
	if expected == nil || !expected.valid() || len(raw) < hashSignaturePackageHeader || len(raw) > hashSignaturePackageHeader+hashSignatureReportLimit+hashSignaturePDFLimit+hashSignatureHTMLLimit+hashSignatureFontLimit+hashSignatureSnapshotLimit || string(raw[:8]) != "HSHFIT01" {
		return nil, errHashSignatureSeal
	}
	limits := []int{hashSignatureReportLimit, hashSignaturePDFLimit, hashSignatureHTMLLimit, hashSignatureFontLimit, hashSignatureSnapshotLimit}
	parts := make([][]byte, 5)
	offset := hashSignaturePackageHeader
	for i, limit := range limits {
		n := uint64(binary.BigEndian.Uint32(raw[8+i*4:]))
		if n == 0 || n > uint64(limit) || n > uint64(len(raw)-offset) {
			return nil, errHashSignatureSeal
		}
		parts[i] = raw[offset : offset+int(n)]
		offset += int(n)
	}
	if offset != len(raw) {
		return nil, errHashSignatureSeal
	}
	h := sha256.Sum256(parts[0])
	if !bytes.Equal(h[:], raw[28:60]) {
		return nil, errHashSignatureSeal
	}
	var r hashSignaturePDFReport
	d := json.NewDecoder(bytes.NewReader(parts[0]))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return nil, errHashSignatureSeal
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, parts[0]) {
		return nil, errHashSignatureSeal
	}
	f, ok := hashPinnedMeasureFont(expected.Font)
	if !ok || r.Schema != 1 || r.Policy != hashSignatureSealPolicy || !r.Plan.valid() || r.Plan.inputSHA() != expected.inputSHA() || r.InputSHA256 != expected.inputSHA() || r.RecipeSHA256 != hashSignatureRecipeSHA() || r.HTMLSHA256 != hashSealSHA(parts[2]) || r.FontFile != f.file || r.FontSHA256 != f.sha || r.FontSHA256 != hashSealSHA(parts[3]) || r.PDFSHA256 != hashSealSHA(parts[1]) || r.PDFBytes != len(parts[1]) || r.FragmentPage != 1 || !hashMeasureDigest(r.SnapshotSHA256) || len(r.ChromiumProduct) == 0 || len(r.ChromiumProduct) > 256 || len(r.ChromiumRevision) == 0 || len(r.ChromiumRevision) > 256 || len(r.ChromiumProtocol) == 0 || len(r.ChromiumProtocol) > 32 || !bytes.HasPrefix(parts[1], []byte("%PDF-")) || !hashValidSealedMeasurement(&r.Plan, &r.Measurement) {
		return nil, errHashSignatureSeal
	}
	html, err := hashSignatureSealHTML(&r.Plan, parts[3])
	if err != nil || !bytes.Equal(html, parts[2]) {
		return nil, errHashSignatureSeal
	}
	if r.SnapshotSHA256 != hashSealSHA(parts[4]) || !json.Valid(parts[4]) {
		return nil, errHashSignatureSeal
	}
	return &hashSignaturePDFPackage{bytes.Clone(parts[0]), bytes.Clone(parts[1]), bytes.Clone(parts[2]), bytes.Clone(parts[3]), bytes.Clone(parts[4])}, nil
}

// Measure and observe only existing generated nodes. This observer never
// regenerates text or refits, and runs in an isolated world with scripts blocked.
const hashSignatureSnapshotFunction = `function(r) {
 "use strict";
 if(!matchMedia("print").matches || document.documentElement.hasAttribute("data-hash-page-script") || document.documentElement.hasAttribute("data-hash-event-handler") || document.getElementById("hash-page-script-effect") || document.fonts.status!=="loaded" || document.body.childNodes.length!==r.targets.length) throw new Error("document");
 const near=(a,b)=>Number.isFinite(a)&&Math.abs(a-b)<=0.001;
 const box=n=>{const b=n.getBoundingClientRect();return [b.x,b.y,b.width,b.height];};
 const styles=n=>{const s=getComputedStyle(n);return ["display","visibility","opacity","fill","fill-opacity","stroke","stroke-opacity","stroke-width","font-family","font-size","font-weight","font-style","font-stretch","font-kerning","font-variant-ligatures","font-variant-caps","font-feature-settings","font-variation-settings","letter-spacing","word-spacing","white-space","direction","unicode-bidi","text-anchor","text-rendering","transform","transform-origin","clip-path","clip","mask","filter","overflow","mix-blend-mode","position","left","top","width","height"].map(k=>[k,s.getPropertyValue(k)]);};
 let observed=[];
 for(let i=0;i<r.targets.length;i++) {
  const t=r.targets[i],svg=document.body.childNodes[i];
  if(svg.nodeName!=="svg" || svg.namespaceURI!=="http://www.w3.org/2000/svg" || svg.id!=="hash-measure-target-"+i || svg.getAttribute("viewBox")!=="0 0 "+t.widthPx+" "+t.heightPx || !near(+svg.getAttribute("width"),t.widthPx) || !near(+svg.getAttribute("height"),t.heightPx)) throw new Error("target");
  const b=box(svg),expected=[t.viewportBBox.x,t.viewportBBox.y,t.viewportBBox.width,t.viewportBBox.height];if(!b.every((v,j)=>near(v,expected[j]))) throw new Error("geometry");
  let at=0,lines=[];
  for(let j=0;j<t.lines.length;j++) {
   const l=t.lines[j],n=svg.childNodes[at++];if(!n || n.nodeName!=="text" || n.namespaceURI!==svg.namespaceURI || n.id!=="hash-measure-line-"+i+"-"+j || n.textContent!==l.text || !near(+n.getAttribute("x"),l.x) || !near(+n.getAttribute("y"),l.y) || !near(+n.getAttribute("font-size"),t.fontSizePoints*4/3) || n.getAttribute("font-weight")!=="400") throw new Error("line");
   const bb=n.getBBox(),a=[bb.x,bb.y,bb.width,bb.height],e=[l.bbox.x,l.bbox.y,l.bbox.width,l.bbox.height];if(!a.every((v,k)=>near(v,e[k]))) throw new Error("bbox");
   if(l.hardBreak) {const hard=svg.childNodes[at++];if(!hard || hard.nodeType!==3 || hard.textContent!==l.hardBreak) throw new Error("break");}
   lines.push([a,box(n),styles(n)]);
  }
  if(at!==svg.childNodes.length) throw new Error("extra");observed.push([b,styles(svg),lines]);
 }
 return {html:document.documentElement.outerHTML,bodyText:document.body.textContent,rootStyles:styles(document.documentElement),bodyStyles:styles(document.body),targets:observed};
}`

func hashCaptureSignatureSnapshot(ctx context.Context, r *hashSignatureMeasurement) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	frame, err := page.GetFrameTree().Do(call)
	if err != nil || frame == nil || frame.Frame == nil {
		return nil, errHashSignatureSeal
	}
	world, err := page.CreateIsolatedWorld(frame.Frame.ID).WithWorldName(hashSignatureSealPolicy).WithGrantUniveralAccess(false).Do(call)
	if err != nil || world == 0 {
		return nil, errHashSignatureSeal
	}
	arg, err := json.Marshal(r.DOM)
	if err != nil {
		return nil, errHashSignatureSeal
	}
	v, exception, err := runtime.CallFunctionOn(hashSignatureSnapshotFunction).WithExecutionContextID(world).WithArguments([]*runtime.CallArgument{{Value: arg}}).WithReturnByValue(true).WithSilent(true).WithUserGesture(false).Do(call)
	if err != nil || exception != nil || v == nil || v.Type != runtime.TypeObject || len(v.Value) == 0 || len(v.Value) > hashSignatureSnapshotLimit {
		return nil, errHashSignatureSeal
	}
	root, err := dom.GetDocument().Do(call)
	if err != nil || root == nil {
		return nil, errHashSignatureSeal
	}
	for i, t := range r.DOM.Targets {
		for j, l := range t.Lines {
			if strings.TrimSpace(l.Text) == "" {
				continue
			}
			node, err := dom.QuerySelector(root.NodeID, hashMeasureLineSelector(i, j)).Do(call)
			if err != nil || node == 0 {
				return nil, errHashSignatureSeal
			}
			fonts, err := css.GetPlatformFontsForNode(node).Do(call)
			if err != nil {
				return nil, errHashSignatureSeal
			}
			a, err := json.Marshal(fonts)
			if err != nil {
				return nil, errHashSignatureSeal
			}
			b, err := json.Marshal(l.Fonts)
			if err != nil || !bytes.Equal(a, b) {
				return nil, errHashSignatureSeal
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if call.Err() != nil {
		return nil, errHashSignatureSeal
	}
	return bytes.Clone(v.Value), nil
}

func hashMeasureLineSelector(i, j int) string {
	return "#hash-measure-line-" + strconv.Itoa(i) + "-" + strconv.Itoa(j)
}

// Every read is bounded; exactly one explicit close is required even on refusal.
// A close failure taints the browser so health recovery drains that generation.
func hashReadSignaturePDF(ctx context.Context, reader io.ReadCloser) (pdf []byte, result error, closed bool) {
	defer func() {
		err := reader.Close()
		closed = err == nil
		if err != nil {
			result = errors.Join(result, errHashSignatureSeal)
		}
		if ctx.Err() != nil {
			result = errors.Join(result, ctx.Err())
		}
		if result != nil {
			pdf = nil
		}
	}()
	var b bytes.Buffer
	buf := make([]byte, 64<<10)
	empty := 0
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err(), false
		}
		remain := hashSignaturePDFLimit + 1 - b.Len()
		if remain <= 0 {
			return nil, errHashSignatureSeal, false
		}
		n, err := reader.Read(buf[:min(len(buf), remain)])
		if ctx.Err() != nil {
			return nil, ctx.Err(), false
		}
		if n < 0 || n > min(len(buf), remain) {
			return nil, errHashSignatureSeal, false
		}
		if n > 0 {
			b.Write(buf[:n])
			empty = 0
		} else {
			empty++
			if empty > 8 {
				return nil, errHashSignatureSeal, false
			}
		}
		if b.Len() > hashSignaturePDFLimit {
			return nil, errHashSignatureSeal, false
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errHashSignatureSeal, false
		}
	}
	if !bytes.HasPrefix(b.Bytes(), []byte("%PDF-")) {
		return nil, errHashSignatureSeal, false
	}
	return b.Bytes(), nil, false
}

func (b *chromiumBrowser) hashPrintSignaturePDF(task context.Context, widthPoints, heightPoints float64) ([]byte, error) {
	if task.Err() != nil {
		return nil, task.Err()
	}
	_, handle, err := page.PrintToPDF().WithLandscape(false).WithDisplayHeaderFooter(false).WithPrintBackground(true).WithScale(1).WithPaperWidth(widthPoints / 72).WithPaperHeight(heightPoints / 72).WithMarginTop(0).WithMarginBottom(0).WithMarginLeft(0).WithMarginRight(0).WithPreferCSSPageSize(true).WithGenerateTaggedPDF(false).WithGenerateDocumentOutline(false).WithTransferMode(page.PrintToPDFTransferModeReturnAsStream).Do(task)
	if err != nil || handle == "" {
		// A failed CDP reply can have an unknown stream-creation outcome.
		// Tab cleanup alone does not prove IO backing-storage disposal.
		b.hashCleanupUnconfirmed.Store(true)
		return nil, errHashSignatureSeal
	}
	pdf, err, closed := hashReadSignaturePDF(task, &streamReader{ctx: task, handle: handle})
	if !closed {
		b.hashCleanupUnconfirmed.Store(true)
	}
	return pdf, err
}

func (b *chromiumBrowser) hashPrepareSignaturePDF(ctx context.Context, logger *slog.Logger, u, dir string, s *hashSignatureSeal) (*hashSignaturePDFPackage, error) {
	if !b.arguments.disableJavaScript {
		return nil, errHashFitIsolation
	}
	var candidate *hashSignaturePDFPackage
	options := DefaultOptions()
	options.AllowedFilePrefixes = []string{dir}
	options.EmulatedMediaType = "print"
	options.OmitBackground = true
	options.FailOnResourceLoadingFailed = true
	err := b.do(ctx, logger, u, options, nil, chromedp.Tasks{
		network.Enable(), fetch.Enable(), runtime.Enable(),
		clearCacheActionFunc(logger, b.arguments.clearCache), clearCookiesActionFunc(logger, b.arguments.clearCookies), clearStorageActionFunc(logger, b.arguments.clearStorage, u),
		disableJavaScriptActionFunc(logger, true), navigateActionFunc(logger, u, true, true),
		hideDefaultWhiteBackgroundActionFunc(logger, true, true), emulateMediaTypeActionFunc(logger, "print", nil),
		chromedp.ActionFunc(func(task context.Context) error {
			if err := hashSignatureMeasurementAction(&s.plan).Do(task); err != errHashFitNotReady || !hashValidSealedMeasurement(&s.plan, s.plan.report) {
				return errHashSignatureSeal
			}
			var err error
			s.measurement, err = json.Marshal(s.plan.report)
			if err != nil || len(s.measurement) > hashSignatureReportLimit {
				return errHashSignatureSeal
			}
			s.snapshot, err = hashCaptureSignatureSnapshot(task, s.plan.report)
			return err
		}),
		chromedp.ActionFunc(func(task context.Context) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := hashNavigationBarrierAction().Do(task); err != nil {
				return err
			}
			_, w, _ := hashMeasureDecimal(s.plan.WidthPoints)
			_, h, _ := hashMeasureDecimal(s.plan.HeightPoints)
			pdf, err := b.hashPrintSignaturePDF(task, w, h)
			if err != nil {
				return err
			}
			if err := hashNavigationBarrierAction().Do(task); err != nil {
				return err
			}
			var m hashSignatureMeasurement
			if json.Unmarshal(s.measurement, &m) != nil {
				return errHashSignatureSeal
			}
			after, err := hashCaptureSignatureSnapshot(task, &m)
			if err != nil || !bytes.Equal(after, s.snapshot) {
				return errHashSignatureSeal
			}
			protocol, product, revision, _, _, err := cdpbrowser.GetVersion().Do(task)
			if err != nil {
				return errHashSignatureSeal
			}
			f, _ := hashPinnedMeasureFont(s.plan.Font)
			r := hashSignaturePDFReport{Schema: 1, Policy: hashSignatureSealPolicy, Plan: s.plan, InputSHA256: s.inputSHA, RecipeSHA256: hashSignatureRecipeSHA(), HTMLSHA256: hashSealSHA(s.html), FontFile: f.file, FontSHA256: f.sha, PDFSHA256: hashSealSHA(pdf), PDFBytes: len(pdf), FragmentPage: 1, SnapshotSHA256: hashSealSHA(s.snapshot), ChromiumProduct: product, ChromiumRevision: revision, ChromiumProtocol: protocol, Measurement: m}
			report, err := json.Marshal(r)
			if err != nil || len(report) > hashSignatureReportLimit {
				return errHashSignatureSeal
			}
			candidate = &hashSignaturePDFPackage{report, pdf, bytes.Clone(s.html), bytes.Clone(s.font), bytes.Clone(s.snapshot)}
			candidate, err = decodeHashSignaturePDFPackage(candidate.Bytes(), &s.plan)
			return err
		}), page.Close(),
	})
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	if candidate == nil {
		return nil, errHashSignatureSeal
	}
	return candidate, nil
}

// Publication happens only after synchronous owned callback/target/source
// cleanup and supervisor post-cancellation checks. No deterministic-PDF or
// storage durability claim is made by this renderer-only package.
func (mod *Chromium) prepareHashSignaturePDF(ctx context.Context, logger *slog.Logger, p *hashSignatureMeasurePlan, font []byte) (*hashSignaturePDFPackage, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errHashSignatureSeal
	}
	b, ok := mod.browser.(*chromiumBrowser)
	if !ok || mod.supervisor == nil {
		return nil, errHashSignatureSeal
	}
	if !b.arguments.disableJavaScript {
		return nil, errHashFitIsolation
	}
	s, err := newHashSignatureSeal(p, font)
	if err != nil {
		return nil, err
	}
	var candidate *hashSignaturePDFPackage
	err = mod.supervisor.Run(ctx, logger, func() (result error) {
		dir, err := os.MkdirTemp("", "hash-signature-seal-")
		if err != nil {
			return errHashSignatureSeal
		}
		defer func() {
			if os.RemoveAll(dir) != nil {
				result = errors.Join(result, errHashSignatureSeal)
			}
		}()
		path := filepath.Join(dir, "index.html")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errHashSignatureSeal
		}
		n, writeErr := file.Write(s.html)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil || n != len(s.html) {
			return errHashSignatureSeal
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		candidate, err = b.hashPrepareSignaturePDF(ctx, logger, (&url.URL{Scheme: "file", Path: path}).String(), dir, s)
		return err
	})
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	if candidate == nil {
		return nil, errHashSignatureSeal
	}
	return candidate, nil
}
