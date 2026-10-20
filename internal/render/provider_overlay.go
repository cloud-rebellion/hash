// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"regexp"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/sourcejson"
)

const ProviderOverlayRecipeV1 = "hash-provider-overlay-fragments-v1"
const ProviderOverlayRecipeV2 = "hash-provider-overlay-fragments-v2"
const ProviderOverlayRecipeV3 = "hash-provider-overlay-fragments-v3"
const ProviderOverlaySignatureWidth = 471.967968
const ProviderOverlaySignatureHeight = 54.9343986
const ProviderOverlayDisclosureWidth = 475.967968
const ProviderOverlayDisclosureHeight = 25.2575994

var ErrProviderOverlay = errors.New("render: invalid provider overlay input")
var providerOverlayColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// ProviderOverlayInput is app-controlled material, not arbitrary HTML or CSS.
// The original approved page already carries identities and branding. These
// fragments add only the exact signature span and approved disclosure text.
type ProviderOverlayInput struct {
	Name              string `json:"name"`
	Font              string `json:"font"`
	FontSHA256        string `json:"font_sha256"`
	InterSHA256       string `json:"inter_sha256"`
	TextColor         string `json:"text_color"`
	DisclosureColor   string `json:"disclosure_color"`
	DisclosureText    string `json:"disclosure_text"`
	DisclosureVersion int64  `json:"disclosure_version"`
	DisclosureSHA256  string `json:"disclosure_sha256"`
}

type ProviderOverlayHTML struct {
	SignatureHTML  string
	DisclosureHTML string
	SignatureSpan  []byte
	SignatureFont  FontAsset
	InterFont      FontAsset
	RecipeJSON     []byte
	RecipeSHA256   string
}

func providerSHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func providerDisclosureSHA(text string) string {
	return providerSHA(append([]byte("hash:presign-disclosure:v1\x00"), []byte(text)...))
}

// ProviderOverlayRecipe is deterministic and timestamp-free. The exact input,
// font names, geometry, fitting policy, HTML and script all enter this recipe.
func ProviderOverlayRecipe(in ProviderOverlayInput) (ProviderOverlayHTML, error) {
	sf, ok := providerFontAsset(in.Font)
	if !ok {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	return ProviderOverlayRecipeWithAssets(in, sf, FontAsset{Filename: "Inter.woff2", Bytes: bytes.Clone(fontInter)})
}

// ProviderOverlayRecipeWithAssets reconstructs a v1 recipe from the recorded
// archive, never from today's bundled font on recovery. The historical v1 cmap
// and face digests remain explicit; a changed font needs a new recipe version.
func ProviderOverlayRecipeWithAssets(in ProviderOverlayInput, sf, inter FontAsset) (ProviderOverlayHTML, error) {
	if ValidateSignatureName(in.Name) != nil || !utf8.ValidString(in.Name) || utf8.RuneCountInString(in.Name) > 80 || !IsValidFont(in.Font) || !providerOverlayColor.MatchString(in.TextColor) || !providerOverlayColor.MatchString(in.DisclosureColor) || in.DisclosureVersion != 1 || len(in.DisclosureText) < 1 || len(in.DisclosureText) > 512 || !validProviderSHA(in.DisclosureSHA256) || providerDisclosureSHA(in.DisclosureText) != in.DisclosureSHA256 {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	for _, r := range in.Name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !providerFontSupports(in.Font, r) {
			return ProviderOverlayHTML{}, fmt.Errorf("%w: unsupported signature name character", ErrProviderOverlay)
		}
	}
	for _, r := range in.DisclosureText {
		if r < 0x20 || r > 0x7e {
			return ProviderOverlayHTML{}, ErrProviderOverlay
		}
	}
	if sf.Filename != providerFontFilename(in.Font) || providerSHA(sf.Bytes) != in.FontSHA256 || providerFontPinnedSHA[in.Font] != in.FontSHA256 {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	if inter.Filename != "Inter.woff2" || providerSHA(inter.Bytes) != in.InterSHA256 || in.InterSHA256 != "3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62" {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	span, err := RenderSignatureSpan(in.Name, in.Font)
	if err != nil {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	// No fallback families, hidden overflow, dynamic text or remote assets. The
	// bounded script waits for the actual uploaded face and measures each size.
	// Failure leaves ready=false and the renderer refuses the conversion.
	signature := providerFragmentHTML(ProviderOverlaySignatureWidth, ProviderOverlaySignatureHeight, in.TextColor,
		fmt.Sprintf(`@font-face{font-family:'HashProvider';font-style:normal;font-weight:400;src:url('./%s') format('woff2')}#ink{font-family:'HashProvider';font-size:27pt;line-height:1.15;overflow-wrap:anywhere;white-space:normal}`, sf.Filename), span,
		`document.fonts.load('27pt HashProvider',document.getElementById('ink').textContent).then(async()=>{await document.fonts.ready;const e=document.getElementById('ink');for(let s=27;s>=12;s-=0.5){e.style.fontSize=s+'pt';await new Promise(requestAnimationFrame);const r=e.getBoundingClientRect();const lh=s*96/72*1.15;if(document.fonts.check(s+'pt HashProvider',e.textContent)&&e.scrollWidth<=e.clientWidth&&e.scrollHeight<=e.clientHeight&&r.height<=3*lh+0.5&&r.height<=document.documentElement.clientHeight){window.hashProviderReady=true;return}}}).catch(()=>{})`)
	disclosure := providerFragmentHTML(ProviderOverlayDisclosureWidth, ProviderOverlayDisclosureHeight, in.DisclosureColor,
		`@font-face{font-family:'HashDisclosure';font-style:normal;font-weight:400;src:url('./Inter.woff2') format('woff2')}#ink{font-family:'HashDisclosure';font-size:7.5pt;line-height:10pt;overflow-wrap:anywhere;white-space:normal}`,
		`<span>`+html.EscapeString(in.DisclosureText)+`</span>`,
		`document.fonts.load('7.5pt HashDisclosure',document.getElementById('ink').textContent).then(async()=>{await document.fonts.ready;await new Promise(requestAnimationFrame);const e=document.getElementById('ink');const r=e.getBoundingClientRect();window.hashProviderReady=document.fonts.check('7.5pt HashDisclosure',e.textContent)&&e.scrollWidth<=e.clientWidth&&e.scrollHeight<=e.clientHeight&&r.height<=40.5&&r.height<=document.documentElement.clientHeight}).catch(()=>{})`)
	recipe := struct {
		Version        int                  `json:"version"`
		Policy         string               `json:"policy"`
		Input          ProviderOverlayInput `json:"input"`
		SignatureHTML  string               `json:"signature_html"`
		DisclosureHTML string               `json:"disclosure_html"`
	}{1, ProviderOverlayRecipeV1, in, signature, disclosure}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(recipe) != nil {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	raw := bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
	sf.Bytes = bytes.Clone(sf.Bytes)
	inter.Bytes = bytes.Clone(inter.Bytes)
	return ProviderOverlayHTML{signature, disclosure, []byte(span), sf, inter, bytes.Clone(raw), providerSHA(raw)}, nil
}

func providerFragmentHTML(w, h float64, color, css, body, script string) string {
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none';font-src file:;style-src 'unsafe-inline';script-src 'unsafe-inline'"><style>@page{size:%.9fpt %.9fpt;margin:0}html,body{margin:0;padding:0;width:%.9fpt;height:%.9fpt;background:transparent}body{display:flex;align-items:center}#ink{box-sizing:border-box;width:100%%;margin:0;padding:0;color:%s}%s</style></head><body><div id="ink">%s</div><script>window.hashProviderReady=false;%s</script></body></html>`, w, h, w, h, color, css, body, script)
}

func ProviderOverlayOptions(asset FontAsset) PDFOptions {
	return PDFOptions{PreferCSSPageSize: true, WaitForExpression: "window.hashProviderReady === true", Assets: []FontAsset{{Filename: asset.Filename, Bytes: bytes.Clone(asset.Bytes), Mime: asset.Mime}}}
}

// ProviderOverlayRecipeForPolicy selects an explicit app-owned fitting policy.
// Existing callers of ProviderOverlayRecipe continue to produce exact v1 bytes.
func ProviderOverlayRecipeForPolicy(policy string, in ProviderOverlayInput) (ProviderOverlayHTML, error) {
	sf, ok := providerFontAsset(in.Font)
	if !ok {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	return ProviderOverlayRecipeForPolicyWithAssets(policy, in, sf, FontAsset{Filename: "Inter.woff2", Bytes: bytes.Clone(fontInter)})
}

// ProviderOverlayRecipeForPolicyWithAssets reconstructs the recorded policy
// with archived assets. Neither a newer default nor new bundled font bytes can
// reinterpret an existing recipe.
func ProviderOverlayRecipeForPolicyWithAssets(policy string, in ProviderOverlayInput, sf, inter FontAsset) (ProviderOverlayHTML, error) {
	if policy == ProviderOverlayRecipeV3 {
		return providerOverlayRecipeV3WithAssets(in, sf, inter)
	}
	if policy != ProviderOverlayRecipeV1 && policy != ProviderOverlayRecipeV2 {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	r, err := ProviderOverlayRecipeWithAssets(in, sf, inter)
	if err != nil || policy == ProviderOverlayRecipeV1 {
		return r, err
	}
	// V2 changes only fitting. The retained signature span, original text,
	// exact face pins, fragment sizes, colors and disclosure domain are unchanged.
	// Each line uses normal metrics of the loaded face, with measured padding
	// for real ink overhang. No clip, ellipsis, transform or fallback counts as fit.
	r.SignatureHTML = providerFragmentHTML(ProviderOverlaySignatureWidth, ProviderOverlaySignatureHeight, in.TextColor,
		fmt.Sprintf(`@font-face{font-family:'HashProvider';font-style:normal;font-weight:400;src:url('./%s') format('woff2')}#ink{font-family:'HashProvider';font-size:27pt;line-height:normal}%s`, sf.Filename, providerFitV2CSS), string(r.SignatureSpan), providerFitV2Script("HashProvider", 27, 12, 80))
	r.DisclosureHTML = providerFragmentHTML(ProviderOverlayDisclosureWidth, ProviderOverlayDisclosureHeight, in.DisclosureColor,
		`@font-face{font-family:'HashDisclosure';font-style:normal;font-weight:400;src:url('./Inter.woff2') format('woff2')}#ink{font-family:'HashDisclosure';font-size:7.5pt;line-height:10pt}`+providerFitV2CSS,
		`<span>`+html.EscapeString(in.DisclosureText)+`</span>`, providerFitV2Script("HashDisclosure", 7.5, 7.5, 512))
	raw, err := providerRecipeJSON(providerRecipeRecord{1, policy, in, r.SignatureHTML, r.DisclosureHTML})
	if err != nil {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	r.RecipeJSON, r.RecipeSHA256 = raw, providerSHA(raw)
	return r, nil
}

type providerRecipeRecord struct {
	Version        int                  `json:"version"`
	Policy         string               `json:"policy"`
	Input          ProviderOverlayInput `json:"input"`
	SignatureHTML  string               `json:"signature_html"`
	DisclosureHTML string               `json:"disclosure_html"`
}

func providerRecipeJSON(r providerRecipeRecord) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, ErrProviderOverlay
	}
	return bytes.Clone(bytes.TrimSuffix(b.Bytes(), []byte{'\n'})), nil
}

// ProviderOverlayRecipeFromArchive admits only a complete canonical recipe
// which this implementation can reproduce from its exact archived assets and
// expected source/grant/copy input. Stored HTML is never executed on recovery.
func ProviderOverlayRecipeFromArchive(raw []byte, expected ProviderOverlayInput, sf, inter FontAsset) (ProviderOverlayHTML, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || sourcejson.Validate(raw) != nil {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	var recorded providerRecipeRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&recorded) != nil || d.Decode(new(any)) != io.EOF || recorded.Version != 1 || recorded.Input != expected {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	r, err := ProviderOverlayRecipeForPolicyWithAssets(recorded.Policy, expected, sf, inter)
	if err != nil || !bytes.Equal(raw, r.RecipeJSON) {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	return r, nil
}

// V2 has a finite refusal state, not a second readiness path. A refusal causes
// the renderer's wait expression to fail; it never prints a no-fit fragment.
func ProviderOverlayOptionsForPolicy(policy string, asset FontAsset) (PDFOptions, error) {
	opts := ProviderOverlayOptions(asset)
	switch policy {
	case ProviderOverlayRecipeV1:
		return opts, nil
	case ProviderOverlayRecipeV2:
		opts.WaitForExpression = `(()=>{if(window.hashProviderFitV2Failed===true)throw new Error('hash_provider_fit_v2_refused');return window.hashProviderReady===true})()`
		return opts, nil
	case ProviderOverlayRecipeV3:
		opts.WaitForExpression = `(()=>{if(window.hashProviderFitV3Failed===true)throw new Error('hash_provider_fit_v3_refused');return window.hashProviderReady===true})()`
		return opts, nil
	default:
		return PDFOptions{}, ErrProviderOverlay
	}
}

const providerFitV2CSS = `#ink{font-style:normal;font-weight:400;font-kerning:normal;direction:ltr;text-align:left;min-width:0;padding:1px 0;white-space:pre}#ink>span{display:block}.hash-provider-line{display:block;box-sizing:border-box;width:100%;margin:0;white-space:pre;line-height:inherit}.hash-provider-baseline{display:inline-block;vertical-align:baseline;width:0;height:0;margin:0;padding:0;border:0;line-height:0}`

// The script packs complete grapheme clusters using actual shaped line metrics,
// then checks DOM line boxes, text ranges and per-line Canvas ink bounds against
// the real fixed body. A zero-height inline marker exposes the actual baseline.
// At most 31 sizes, three lines and two animation frames per size are attempted.
// Font loading, animation-frame delays and all exceptions have a five-second
// terminal refusal; only the complete measured conjunction sets ready=true.
func providerFitV2Script(family string, maximum, minimum float64, maxClusters int) string {
	return fmt.Sprintf(`(()=>{
'use strict';
window.hashProviderFitV2Failed=false;
window.hashProviderFitV2Completed=false;
let done=false;
const deadline=performance.now()+5000;
const timely=()=>{const now=performance.now();return Number.isFinite(now)&&Number.isFinite(deadline)&&now<deadline};
const finish=ok=>{if(done)return;ok=ok&&timely();done=true;clearTimeout(timer);window.hashProviderFitV2Failed=!ok;window.hashProviderFitV2Completed=true;window.hashProviderReady=ok};
const timer=setTimeout(()=>finish(false),5000);
const alive=()=>{if(done)return false;if(!timely()){finish(false);return false}return true};
const frame=()=>new Promise(requestAnimationFrame);
const finite=n=>typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=1e7;
const rect=r=>[r.left,r.top,r.right,r.bottom,r.width,r.height].every(finite)&&r.width>=0&&r.height>=0;
const inside=(r,b)=>rect(r)&&r.left>=b.left&&r.top>=b.top&&r.right<=b.right&&r.bottom<=b.bottom;
const family='%s',maximum=%g,minimum=%g,maxClusters=%d;
const run=async()=>{
 const e=document.getElementById('ink'),original=e.firstElementChild,text=original.textContent;
 if(typeof Intl.Segmenter!=='function'||!text||e.children.length!==1)throw new Error('fit');
 const clusters=Array.from(new Intl.Segmenter('und',{granularity:'grapheme'}).segment(text),s=>s.segment);
 if(!clusters.length||clusters.length>maxClusters||clusters.join('')!==text)throw new Error('fit');
 const faces=await document.fonts.load(maximum+'pt '+family,text);
 await document.fonts.ready;
 if(!alive())return;
 if(faces.length!==1||faces[0].status!=='loaded'||faces[0].family.replace(/['"]/g,'')!==family)throw new Error('fit');
 const canvas=document.createElement('canvas'),c=canvas.getContext('2d');
 if(!c||!('fontKerning'in c))throw new Error('fit');
 c.fontKerning='normal';c.textBaseline='alphabetic';c.textAlign='left';c.direction='ltr';
 const measure=t=>{const m=c.measureText(t);if(![m.width,m.actualBoundingBoxLeft,m.actualBoundingBoxRight,m.actualBoundingBoxAscent,m.actualBoundingBoxDescent].every(finite)||m.width<0)throw new Error('fit');return m};
 const need=m=>1+Math.max(0,m.actualBoundingBoxLeft)+Math.max(m.width,m.actualBoundingBoxRight)+1;
 for(let size=maximum;size>=minimum;size-=0.5){
  if(!alive())return;
  e.style.fontSize=size+'pt';c.font='normal 400 '+size+'pt '+family;
  const body=document.body.getBoundingClientRect();
  if(!rect(body)||body.width<=2||body.height<=2||!document.fonts.check(size+'pt '+family,text))throw new Error('fit');
  const parts=[];let offset=0;
  while(offset<clusters.length&&parts.length<3){
   if(!alive())return;
   let part='',best='',next=offset;
   for(let j=offset;j<clusters.length;j++){
    if(!alive())return;
    part+=clusters[j];if(need(measure(part))>body.width)break;best=part;next=j+1;
   }
   if(!best)break;parts.push(best);offset=next;
  }
  if(offset!==clusters.length||parts.join('')!==text||parts.length>3)continue;
  original.replaceChildren();
  const lines=parts.map(t=>{
   const m=measure(t),line=document.createElement('span'),baseline=document.createElement('span'),node=document.createTextNode(t);
   line.className='hash-provider-line';line.style.paddingLeft=(1+Math.max(0,m.actualBoundingBoxLeft))+'px';
   baseline.className='hash-provider-baseline';line.append(node,baseline);original.append(line);return{line,baseline,node,m};
  });
  await frame();if(!alive())return;
  for(const l of lines){
   const r=l.line.getBoundingClientRect(),baseline=l.baseline.getBoundingClientRect().top;
   if(!rect(r)||!finite(baseline))throw new Error('fit');
   l.line.style.paddingTop=Math.max(0,r.top+0.5-(baseline-l.m.actualBoundingBoxAscent))+'px';
   l.line.style.paddingBottom=Math.max(0,baseline+l.m.actualBoundingBoxDescent+0.5-r.bottom)+'px';
  }
  await frame();if(!alive())return;
  const bounds=document.body.getBoundingClientRect(),box=e.getBoundingClientRect();
  let ok=rect(bounds)&&inside(box,bounds)&&e.scrollWidth<=e.clientWidth&&e.scrollHeight<=e.clientHeight&&original.textContent===text&&original.children.length===lines.length&&lines.length<=3&&getComputedStyle(e).fontFamily.replace(/['"]/g,'')===family;
  let previousBottom=-Infinity;
  for(const l of lines){
   if(!alive())return;
   const line=l.line.getBoundingClientRect(),range=document.createRange();range.selectNodeContents(l.node);
   const ranges=Array.from(range.getClientRects()),r=range.getBoundingClientRect(),anchor=l.baseline.getBoundingClientRect(),m=measure(l.node.textContent);
   const paint={left:r.left-m.actualBoundingBoxLeft,right:r.left+m.actualBoundingBoxRight,top:anchor.top-m.actualBoundingBoxAscent,bottom:anchor.top+m.actualBoundingBoxDescent};
   paint.width=paint.right-paint.left;paint.height=paint.bottom-paint.top;
   ok=ok&&ranges.length===1&&inside(line,bounds)&&inside(r,bounds)&&inside(paint,bounds)&&paint.left>=bounds.left+0.5&&paint.right<=bounds.right-0.5&&paint.top>=bounds.top+0.5&&paint.bottom<=bounds.bottom-0.5&&paint.top>=previousBottom+0.5&&Math.abs(r.width-m.width)<=0.25&&Math.abs(anchor.left-r.left-m.width)<=0.25;
   previousBottom=paint.bottom;
  }
  if(ok){finish(true);return}
 }
 finish(false);
};
run().catch(()=>finish(false));
})()`, family, maximum, minimum, maxClusters)
}

// V3 records word-aware packing as a new recipe. V1 and V2 remain independent
// historical recipes, including their exact HTML and fitting scripts.
func providerOverlayRecipeV3WithAssets(in ProviderOverlayInput, sf, inter FontAsset) (ProviderOverlayHTML, error) {
	r, err := ProviderOverlayRecipeWithAssets(in, sf, inter)
	if err != nil {
		return ProviderOverlayHTML{}, err
	}
	r.SignatureHTML = providerFragmentHTML(ProviderOverlaySignatureWidth, ProviderOverlaySignatureHeight, in.TextColor,
		fmt.Sprintf(`@font-face{font-family:'HashProvider';font-style:normal;font-weight:400;src:url('./%s') format('woff2')}#ink{font-family:'HashProvider';font-size:27pt;line-height:normal}%s`, sf.Filename, providerFitV2CSS), string(r.SignatureSpan), providerFitV3Script("HashProvider", 27, 12, 80))
	r.DisclosureHTML = providerFragmentHTML(ProviderOverlayDisclosureWidth, ProviderOverlayDisclosureHeight, in.DisclosureColor,
		`@font-face{font-family:'HashDisclosure';font-style:normal;font-weight:400;src:url('./Inter.woff2') format('woff2')}#ink{font-family:'HashDisclosure';font-size:7.5pt;line-height:10pt}`+providerFitV2CSS,
		`<span>`+html.EscapeString(in.DisclosureText)+`</span>`, providerFitV3Script("HashDisclosure", 7.5, 7.5, 512))
	raw, err := providerRecipeJSON(providerRecipeRecord{1, ProviderOverlayRecipeV3, in, r.SignatureHTML, r.DisclosureHTML})
	if err != nil {
		return ProviderOverlayHTML{}, ErrProviderOverlay
	}
	r.RecipeJSON, r.RecipeSHA256 = raw, providerSHA(raw)
	return r, nil
}

// Ordinary U+0020 spaces are the only preferred break opportunities. A token
// includes its punctuation and nonbreaking spaces. V3 preserves every original
// grapheme, including all boundary spaces, and only splits a token when the
// entire token's measured ink/advance exceeds an empty row at the current size.
// Such overlong tokens may use the remaining current-row width. Every candidate
// is then checked against the same actual baseline, glyph and fixed-body bounds
// as V2. No text normalization, CSS clipping or fallback is a successful fit.
func providerFitV3Script(family string, maximum, minimum float64, maxClusters int) string {
	return fmt.Sprintf(`(()=>{
'use strict';
window.hashProviderFitV3Failed=false;
window.hashProviderFitV3Completed=false;
let done=false;
const deadline=performance.now()+5000;
const timely=()=>{const now=performance.now();return Number.isFinite(now)&&Number.isFinite(deadline)&&now<deadline};
const finish=ok=>{if(done)return;ok=ok&&timely();done=true;clearTimeout(timer);window.hashProviderFitV3Failed=!ok;window.hashProviderFitV3Completed=true;window.hashProviderReady=ok};
const timer=setTimeout(()=>finish(false),5000);
const alive=()=>{if(done)return false;if(!timely()){finish(false);return false}return true};
const frame=()=>new Promise(requestAnimationFrame);
const finite=n=>typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=1e7;
const rect=r=>[r.left,r.top,r.right,r.bottom,r.width,r.height].every(finite)&&r.width>=0&&r.height>=0;
const inside=(r,b)=>rect(r)&&r.left>=b.left&&r.top>=b.top&&r.right<=b.right&&r.bottom<=b.bottom;
const family='%s',maximum=%g,minimum=%g,maxClusters=%d;
const run=async()=>{
 const e=document.getElementById('ink'),original=e.firstElementChild,text=original.textContent;
 if(typeof Intl.Segmenter!=='function'||!text||e.children.length!==1)throw new Error('fit');
 const clusters=Array.from(new Intl.Segmenter('und',{granularity:'grapheme'}).segment(text),s=>s.segment);
 if(!clusters.length||clusters.length>maxClusters||clusters.join('')!==text)throw new Error('fit');
 const starts=[],ends=[];
 for(let k=0;k<clusters.length;){
  if(!alive())return;
  if(clusters[k]===' '){starts[k]=k;ends[k]=k+1;k++;continue}
  let j=k;while(j<clusters.length&&clusters[j]!==' '){if(!alive())return;j++}
  for(let n=k;n<j;n++){if(!alive())return;starts[n]=k;ends[n]=j}k=j;
 }
 const faces=await document.fonts.load(maximum+'pt '+family,text);
 await document.fonts.ready;
 if(!alive())return;
 if(faces.length!==1||faces[0].status!=='loaded'||faces[0].family.replace(/['"]/g,'')!==family)throw new Error('fit');
 const canvas=document.createElement('canvas'),c=canvas.getContext('2d');
 if(!c||!('fontKerning'in c))throw new Error('fit');
 c.fontKerning='normal';c.textBaseline='alphabetic';c.textAlign='left';c.direction='ltr';
 const measure=t=>{const m=c.measureText(t);if(![m.width,m.actualBoundingBoxLeft,m.actualBoundingBoxRight,m.actualBoundingBoxAscent,m.actualBoundingBoxDescent].every(finite)||m.width<0)throw new Error('fit');return m};
 const need=m=>1+Math.max(0,m.actualBoundingBoxLeft)+Math.max(m.width,m.actualBoundingBoxRight)+1;
 for(let size=maximum;size>=minimum;size-=0.5){
  if(!alive())return;
  e.style.fontSize=size+'pt';c.font='normal 400 '+size+'pt '+family;
  const body=document.body.getBoundingClientRect();
  if(!rect(body)||body.width<=2||body.height<=2||!document.fonts.check(size+'pt '+family,text))throw new Error('fit');
  const parts=[];let offset=0;
  while(offset<clusters.length&&parts.length<3){
   if(!alive())return;
   let part='',best='',next=offset;
   for(let j=offset;j<clusters.length;j++){
    if(!alive())return;
    part+=clusters[j];if(need(measure(part))>body.width)break;best=part;next=j+1;
   }
   if(!best)break;
   if(next<clusters.length&&clusters[next-1]!==' '&&clusters[next]!==' '){
    const start=starts[next],end=ends[next],token=clusters.slice(start,end).join('');
    if(need(measure(token))<=body.width){
     if(start<=offset)throw new Error('fit');
     next=start;best=clusters.slice(offset,next).join('');
    }
   }
   if(!best||next<=offset||need(measure(best))>body.width)throw new Error('fit');
   parts.push(best);offset=next;
  }
  if(offset!==clusters.length||parts.join('')!==text||parts.length>3)continue;
  original.replaceChildren();
  const lines=parts.map(t=>{
   const m=measure(t),line=document.createElement('span'),baseline=document.createElement('span'),node=document.createTextNode(t);
   line.className='hash-provider-line';line.style.paddingLeft=(1+Math.max(0,m.actualBoundingBoxLeft))+'px';
   baseline.className='hash-provider-baseline';line.append(node,baseline);original.append(line);return{line,baseline,node,m};
  });
  await frame();if(!alive())return;
  for(const l of lines){
   const r=l.line.getBoundingClientRect(),baseline=l.baseline.getBoundingClientRect().top;
   if(!rect(r)||!finite(baseline))throw new Error('fit');
   l.line.style.paddingTop=Math.max(0,r.top+0.5-(baseline-l.m.actualBoundingBoxAscent))+'px';
   l.line.style.paddingBottom=Math.max(0,baseline+l.m.actualBoundingBoxDescent+0.5-r.bottom)+'px';
  }
  await frame();if(!alive())return;
  const bounds=document.body.getBoundingClientRect(),box=e.getBoundingClientRect();
  let ok=rect(bounds)&&inside(box,bounds)&&e.scrollWidth<=e.clientWidth&&e.scrollHeight<=e.clientHeight&&original.textContent===text&&original.children.length===lines.length&&lines.length<=3&&getComputedStyle(e).fontFamily.replace(/['"]/g,'')===family;
  let previousBottom=-Infinity;
  for(const l of lines){
   if(!alive())return;
   const line=l.line.getBoundingClientRect(),range=document.createRange();range.selectNodeContents(l.node);
   const ranges=Array.from(range.getClientRects()),r=range.getBoundingClientRect(),anchor=l.baseline.getBoundingClientRect(),m=measure(l.node.textContent);
   const paint={left:r.left-m.actualBoundingBoxLeft,right:r.left+m.actualBoundingBoxRight,top:anchor.top-m.actualBoundingBoxAscent,bottom:anchor.top+m.actualBoundingBoxDescent};
   paint.width=paint.right-paint.left;paint.height=paint.bottom-paint.top;
   ok=ok&&ranges.length===1&&inside(line,bounds)&&inside(r,bounds)&&inside(paint,bounds)&&paint.left>=bounds.left+0.5&&paint.right<=bounds.right-0.5&&paint.top>=bounds.top+0.5&&paint.bottom<=bounds.bottom-0.5&&paint.top>=previousBottom+0.5&&Math.abs(r.width-m.width)<=0.25&&Math.abs(anchor.left-r.left-m.width)<=0.25;
   previousBottom=paint.bottom;
  }
  if(ok){finish(true);return}
 }
 finish(false);
};
run().catch(()=>finish(false));
})()`, family, maximum, minimum, maxClusters)
}

func validProviderSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func providerFontAsset(font string) (FontAsset, bool) {
	switch font {
	case "Caveat":
		return FontAsset{Filename: "Caveat.woff2", Bytes: bytes.Clone(fontCaveat)}, true
	case "Dancing Script":
		return FontAsset{Filename: "DancingScript.woff2", Bytes: bytes.Clone(fontDancingScript)}, true
	case "Great Vibes":
		return FontAsset{Filename: "GreatVibes.woff2", Bytes: bytes.Clone(fontGreatVibes)}, true
	case "Sacramento":
		return FontAsset{Filename: "Sacramento.woff2", Bytes: bytes.Clone(fontSacramento)}, true
	case "Homemade Apple":
		return FontAsset{Filename: "HomemadeApple.woff2", Bytes: bytes.Clone(fontHomemadeApple)}, true
	}
	return FontAsset{}, false
}

// Each range table below is the cmap of this exact shipped WOFF2 digest. A new
// font requires a new recipe review; existing archived recipes remain pinned.
func providerFontSupports(font string, r rune) bool {
	for _, p := range providerFontRanges[font] {
		if r >= p[0] && r <= p[1] {
			return true
		}
	}
	return false
}

var providerFontPinnedSHA = map[string]string{
	"Caveat":         "d0b7b931b8980049327e8f8f9ac264617c8200b8422d62e886473d3d9527bad3",
	"Dancing Script": "570e4265bbcb453353ce2fdf63d179332d8daa92691d567547b8a383f3b46c3b",
	"Great Vibes":    "c59dc73d29daf142ef2431f455d21464172374aa750d793a79d608735db2d856",
	"Sacramento":     "2fcd867d2812578d001b0eca921848e24de91d01986f26e038be374ec7c5cfd2",
	"Homemade Apple": "bbaa96c741caa479d4647fc567f64e5ddc71eec58ee9849cb9e8a14bee65bc30",
}

var providerFontRanges = map[string][][2]rune{
	"Caveat":         {{0x0, 0x0}, {0xd, 0xd}, {0x20, 0x7e}, {0xa0, 0xff}, {0x102, 0x102}, {0x131, 0x131}, {0x152, 0x153}, {0x2bc, 0x2bc}, {0x2c6, 0x2c6}, {0x2da, 0x2da}, {0x2dc, 0x2dc}, {0x300, 0x301}, {0x303, 0x304}, {0x308, 0x308}, {0x323, 0x323}, {0x2013, 0x2014}, {0x2018, 0x201a}, {0x201c, 0x201e}, {0x2022, 0x2022}, {0x2026, 0x2026}, {0x2032, 0x2033}, {0x2039, 0x203a}, {0x2044, 0x2044}, {0x20ac, 0x20ac}, {0x2122, 0x2122}, {0x2212, 0x2212}, {0x2215, 0x2215}},
	"Dancing Script": {{0x0, 0x0}, {0xd, 0xd}, {0x20, 0x7e}, {0xa0, 0xff}, {0x131, 0x131}, {0x152, 0x153}, {0x2bc, 0x2bc}, {0x2c6, 0x2c6}, {0x2da, 0x2da}, {0x2dc, 0x2dc}, {0x300, 0x301}, {0x303, 0x304}, {0x308, 0x309}, {0x323, 0x323}, {0x2013, 0x2014}, {0x2018, 0x201a}, {0x201c, 0x201e}, {0x2022, 0x2022}, {0x2026, 0x2026}, {0x2039, 0x203a}, {0x2044, 0x2044}, {0x20ac, 0x20ac}, {0x2122, 0x2122}, {0x2212, 0x2212}, {0x2215, 0x2215}},
	"Great Vibes":    {{0xd, 0xd}, {0x20, 0x7e}, {0xa0, 0xac}, {0xae, 0xff}, {0x102, 0x102}, {0x131, 0x131}, {0x152, 0x153}, {0x2bb, 0x2bc}, {0x2c6, 0x2c6}, {0x2da, 0x2da}, {0x2dc, 0x2dc}, {0x300, 0x301}, {0x303, 0x304}, {0x308, 0x309}, {0x323, 0x323}, {0x329, 0x329}, {0x2002, 0x2002}, {0x2009, 0x2009}, {0x200b, 0x200b}, {0x2013, 0x2014}, {0x2018, 0x201a}, {0x201c, 0x201e}, {0x2022, 0x2022}, {0x2026, 0x2026}, {0x2032, 0x2033}, {0x2039, 0x203a}, {0x2044, 0x2044}, {0x20ac, 0x20ac}, {0x2122, 0x2122}, {0x2212, 0x2212}, {0x2215, 0x2215}},
	"Sacramento":     {{0x20, 0x7e}, {0xa0, 0xff}, {0x131, 0x131}, {0x152, 0x153}, {0x2c6, 0x2c6}, {0x2da, 0x2da}, {0x2dc, 0x2dc}, {0x2013, 0x2014}, {0x2018, 0x201a}, {0x201c, 0x201e}, {0x2022, 0x2022}, {0x2026, 0x2026}, {0x2039, 0x203a}, {0x2044, 0x2044}, {0x20ac, 0x20ac}, {0x2122, 0x2122}, {0x2212, 0x2212}, {0x2215, 0x2215}},
	"Homemade Apple": {{0x20, 0x7e}, {0xa0, 0xff}, {0x131, 0x131}, {0x141, 0x142}, {0x152, 0x153}, {0x2c6, 0x2c6}, {0x2da, 0x2da}, {0x2dc, 0x2dc}, {0x2013, 0x2014}, {0x2018, 0x201a}, {0x201c, 0x201e}, {0x2022, 0x2022}, {0x2026, 0x2026}, {0x2039, 0x203a}, {0x2044, 0x2044}, {0x20ac, 0x20ac}, {0x2122, 0x2122}, {0x2212, 0x2212}},
}

func providerFontFilename(font string) string {
	switch font {
	case "Caveat":
		return "Caveat.woff2"
	case "Dancing Script":
		return "DancingScript.woff2"
	case "Great Vibes":
		return "GreatVibes.woff2"
	case "Sacramento":
		return "Sacramento.woff2"
	case "Homemade Apple":
		return "HomemadeApple.woff2"
	}
	return ""
}
