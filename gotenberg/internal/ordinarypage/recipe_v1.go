// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ordinarypage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

const RecipeSchemaV1 = "hash-ordinary-page-recipe-v1"
const RecipeIDV1 = "hash-ordinary-page-inter-11px-v1"
const PrintRecipeV1 = "all-pages;scale=1;zero-margins;css-page-size;transparent;background;no-headers;no-tags;no-outline;viewport-csspx=points*96/72;font=11csspx=8.25pt;raw-grapheme-wrap;CRLF-CR-LF-hard-breaks;no-normalization"
const CheckboxPathV1 = "M1 5 L4 8 L10 1"
const CoreCSSV1 = `@font-face{font-family:"Inter";src:url("data:font/woff2;base64,%s") format("woff2");font-weight:400;font-style:normal;font-display:block}@page{size:%spt %spt;margin:0}html,body{margin:0;padding:0;width:%spt;height:%spt;background:transparent;-webkit-print-color-adjust:exact;print-color-adjust:exact}.ordinary-field{position:absolute;overflow:visible;display:block}text{white-space:pre;font-family:Inter;font-size:11px;font-weight:400;font-style:normal;font-kerning:normal;font-variant-ligatures:normal;font-variant-caps:normal;letter-spacing:0;word-spacing:0;direction:ltr;unicode-bidi:isolate;fill:#111;stroke:none} .ordinary-mark{overflow:visible} .ordinary-mark path{fill:none;stroke:#111;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}`
const HTMLTemplateV1 = `<!doctype html><html data-ordinary-policy="%s" data-ordinary-input="%s"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src data:; script-src 'none'; base-uri 'none'; form-action 'none'"><style>%s</style></head><body></body></html>`

func KnownRecipeV1() RecipeV1 {
	return RecipeV1{Schema: RecipeSchemaV1, RecipeID: RecipeIDV1, HTMLTemplateSHA256: digestV1([]byte(HTMLTemplateV1)),
		CoreCSSSHA256: digestV1([]byte(CoreCSSV1)), MeasurementSHA256: digestV1([]byte(MeasurementFunctionV1)),
		SnapshotSHA256: digestV1([]byte(SnapshotFunctionV1)), PrintRecipeSHA256: digestV1([]byte(PrintRecipeV1)),
		Fonts: []FontAssetV1{{File: FontFileV1, Family: FontFamilyV1, SHA256: FontSHA256V1, Bytes: FontBytesV1}}}
}
func RecipeJSONV1() []byte   { b, _ := json.Marshal(KnownRecipeV1()); return b }
func RecipeSHA256V1() string { return digestV1(RecipeJSONV1()) }
func GeneratedHTMLV1(p PlanV1, font []byte) ([]byte, error) {
	if ValidatePlanV1(p) != nil || len(font) != FontBytesV1 || digestV1(font) != FontSHA256V1 {
		return nil, ErrInvalidV1
	}
	sha, err := PlanSHA256V1(p)
	if err != nil {
		return nil, err
	}
	w, h, _ := p.Geometry.ViewportPointsV1()
	width, height := strconv.FormatFloat(w, 'g', -1, 64), strconv.FormatFloat(h, 'g', -1, 64)
	css := fmt.Sprintf(CoreCSSV1, base64.StdEncoding.EncodeToString(font), width, height, width, height)
	html := []byte(fmt.Sprintf(HTMLTemplateV1, PolicyV1, sha, css))
	if len(html) > MaxHTMLBytesV1 {
		return nil, ErrInvalidV1
	}
	return html, nil
}

// Values enter trusted isolated-world textContent only. There is no supplied
// HTML/CSS/URL/script. The native font and actual SVG cells are observed;
// source PDF validation and the publication credential remain caller-owned.
const MeasurementFunctionV1 = `async function(input) {
 "use strict";
 const started=performance.now();let work=0,lineCount=0;
 const alive=()=>{if(++work>100000||performance.now()-started>2000)throw new Error("budget");};
 const finite=v=>Number.isFinite(v)&&Math.abs(v)<=100000;
 const near=(a,b)=>Number.isFinite(a)&&Math.abs(a-b)<=0.001;
 const scripts=()=>!document.documentElement.hasAttribute("data-hash-page-script")&&!document.documentElement.hasAttribute("data-hash-event-handler")&&!document.getElementById("hash-page-script-effect");
 if(document.documentElement.getAttribute("data-ordinary-policy")!==input.policy||document.documentElement.getAttribute("data-ordinary-input")!==input.inputSha||document.body.childNodes.length!==0||!scripts()||!matchMedia("print").matches||typeof Intl.Segmenter!=="function"||!near(input.fontSize,11)||!near(input.padding,2))throw new Error("document");
 const loaded=await document.fonts.load('11px "Inter"',"Mg");await document.fonts.ready;alive();
 if(loaded.length!==1||loaded[0].status!=="loaded")throw new Error("font");
 const canvas=document.createElement("canvas"),ctx=canvas.getContext("2d");if(!ctx)throw new Error("canvas");
 ctx.font='11px "Inter"';ctx.textAlign="left";ctx.textBaseline="alphabetic";ctx.direction="ltr";ctx.fontKerning="normal";ctx.fontVariantCaps="normal";
 const metric=text=>{
  alive();const m=ctx.measureText(text),r={advance:m.width,left:m.actualBoundingBoxLeft,right:m.actualBoundingBoxRight,ascent:m.actualBoundingBoxAscent,descent:m.actualBoundingBoxDescent,fontAscent:m.fontBoundingBoxAscent,fontDescent:m.fontBoundingBoxDescent};
  if(Object.values(r).some(v=>!finite(v)))throw new Error("metric");return r;
 };
 const reference=metric("Mg");
 const extent=m=>Math.max(m.advance,m.right)-Math.min(0,-m.left);
 const segmenter=new Intl.Segmenter("und",{granularity:"grapheme"}),ns="http://www.w3.org/2000/svg";
 const boxes=[],grid=new Map();
 const unobscured=(id,b)=>{
  if(b.width<=0||b.height<=0)return;
  const x0=Math.floor(b.x/64),x1=Math.floor((b.x+b.width)/64),y0=Math.floor(b.y/64),y1=Math.floor((b.y+b.height)/64);
  if((x1-x0+1)*(y1-y0+1)>10000)throw new Error("budget");
  const seen=new Set();
  for(let x=x0;x<=x1;x++)for(let y=y0;y<=y1;y++){
   alive();const key=x+"/"+y,list=grid.get(key)||[];
   for(const n of list){if(seen.has(n))continue;seen.add(n);alive();const other=boxes[n];
    if(other.id!==id&&Math.min(b.x+b.width,other.b.x+other.b.width)-Math.max(b.x,other.b.x)>0.001&&Math.min(b.y+b.height,other.b.y+other.b.height)-Math.max(b.y,other.b.y)>0.001)throw new Error("overlap");
   }
  }
  const index=boxes.length;boxes.push({id,b});
  for(let x=x0;x<=x1;x++)for(let y=y0;y<=y1;y++){alive();const key=x+"/"+y,list=grid.get(key)||[];list.push(index);grid.set(key,list);if(grid.size>100000)throw new Error("budget");}
 };
 const fields=[];let expectedBody="";
 for(let i=0;i<input.fields.length;i++){
  alive();const f=input.fields[i],svg=document.createElementNS(ns,"svg");
  svg.id="ordinary-field-"+i;svg.setAttribute("class","ordinary-field");svg.setAttribute("width",f.widthPx);svg.setAttribute("height",f.heightPx);svg.setAttribute("viewBox","0 0 "+f.widthPx+" "+f.heightPx);
  svg.style.left=f.leftPx+"px";svg.style.top=f.topPx+"px";document.body.appendChild(svg);
  let lines=[],markBBox={x:0,y:0,width:0,height:0},markPath="",checked=false,noInk=true;
  if(f.type==="checkbox"){
   checked=f.checked;
   if(checked){
    if(f.widthPx<15||f.heightPx<15)throw new Error("unreadable");
    const mark=document.createElementNS(ns,"svg");mark.id="ordinary-mark-"+i;mark.setAttribute("class","ordinary-mark");mark.setAttribute("x",2);mark.setAttribute("y",(f.heightPx-11)/2);mark.setAttribute("width",11);mark.setAttribute("height",11);mark.setAttribute("viewBox","0 0 11 11");
    const path=document.createElementNS(ns,"path");path.setAttribute("d",input.checkboxPath);mark.appendChild(path);svg.appendChild(mark);
    const b=svg.getBBox();markBBox={x:b.x,y:b.y,width:b.width,height:b.height};markPath=path.getAttribute("d");
    if(Object.values(markBBox).some(v=>!finite(v))||b.width<=0||b.height<=0||b.x-0.75<2-0.001||b.y-0.75<2-0.001||b.x+b.width+0.75>f.widthPx-2+0.001||b.y+b.height+0.75>f.heightPx-2+0.001)throw new Error("unreadable");
    unobscured(f.id,{x:f.leftPx+b.x-0.75,y:f.topPx+b.y-0.75,width:b.width+1.5,height:b.height+1.5});noInk=false;
   }
  }else if(f.visibleValue!==""){
   const innerW=f.widthPx-4,innerH=f.heightPx-4;if(innerW<=0||innerH<=0)throw new Error("unreadable");
   const pending=[];
   const add=(text,hardBreak)=>{alive();if(++lineCount>10000)throw new Error("budget");const m=metric(text);pending.push({text,hardBreak,m,height:Math.max(13.2,Math.max(0,m.ascent,reference.fontAscent)+Math.max(0,m.descent,reference.fontDescent))});};
   const hard=f.visibleValue.match(/[^\r\n]*(?:\r\n|\r|\n|$)/gu);
   if(!hard)throw new Error("text");
   for(let segmentIndex=0;segmentIndex<hard.length;segmentIndex++){
    const part=hard[segmentIndex];if(part===""&&segmentIndex===hard.length-1&&f.visibleValue.length>0&&!/[\r\n]$/u.test(f.visibleValue))continue;
    let hardBreak="",text=part;
    if(part.endsWith("\r\n")){hardBreak="\r\n";text=part.slice(0,-2);}else if(part.endsWith("\r")||part.endsWith("\n")){hardBreak=part.slice(-1);text=part.slice(0,-1);}
    const ends=Array.from(segmenter.segment(text),v=>v.index+v.segment.length);if(ends.length>4096)throw new Error("budget");
    if(ends.length===0){add("",hardBreak);continue;}
    let start=0,at=0;
    while(at<ends.length){
     alive();let low=at,high=ends.length-1,best=-1;
     while(low<=high){const mid=(low+high)>>1,candidate=text.slice(start,ends[mid]);if(extent(metric(candidate))<=innerW){best=mid;low=mid+1;}else high=mid-1;}
     if(best<at)throw new Error("unreadable");
     const last=best===ends.length-1;add(text.slice(start,ends[best]),last?hardBreak:"");start=ends[best];at=best+1;
    }
   }
   const total=pending.reduce((n,l)=>n+l.height,0);if(total>innerH)throw new Error("unreadable");
   let top=(f.heightPx-total)/2;noInk=false;expectedBody+=f.visibleValue;
   for(let j=0;j<pending.length;j++){
    alive();const l=pending[j],m=l.m,node=document.createElementNS(ns,"text"),x=2-Math.min(0,-m.left),y=top+Math.max(0,m.ascent,reference.fontAscent);
    node.id="ordinary-line-"+i+"-"+j;node.setAttribute("x",x);node.setAttribute("y",y);node.textContent=l.text;svg.appendChild(node);if(l.hardBreak)svg.appendChild(document.createTextNode(l.hardBreak));
    const b=node.getBBox(),bbox={x:b.x,y:b.y,width:b.width,height:b.height},empty=l.text.trim()==="",style=getComputedStyle(node);
    if(node.textContent!==l.text||!near(parseFloat(style.fontSize),11)||style.visibility!=="visible"||style.opacity!=="1"||style.fill!=="rgb(17, 17, 17)"||Object.values(bbox).some(v=>!finite(v))||b.width<0||b.height<0||(!empty&&(b.width<=0||b.height<=0||b.x<2-0.25||b.y<2-0.25||b.x+b.width>f.widthPx-2+0.25||b.y+b.height>f.heightPx-2+0.25))||x-m.left<2-0.25||x+m.right>f.widthPx-2+0.25||y-m.ascent<2-0.25||y+m.descent>f.heightPx-2+0.25)throw new Error("unreadable");
    if(!empty)unobscured(f.id,{x:f.leftPx+b.x,y:f.topPx+b.y,width:b.width,height:b.height});
    lines.push({text:l.text,hardBreak:l.hardBreak,x,y,advance:m.advance,inkLeft:m.left,inkRight:m.right,inkAscent:m.ascent,inkDescent:m.descent,fontAscent:reference.fontAscent,fontDescent:reference.fontDescent,bbox,fonts:[]});top+=l.height;
   }
   if(svg.textContent!==f.visibleValue)throw new Error("text");
  }
  const placed=svg.getBoundingClientRect(),viewportBBox={x:placed.x,y:placed.y,width:placed.width,height:placed.height};
  if([placed.x-f.leftPx,placed.y-f.topPx,placed.width-f.widthPx,placed.height-f.heightPx].some(v=>!Number.isFinite(v)||Math.abs(v)>1/32))throw new Error("geometry");
  fields.push({id:f.id,type:f.type,noInk,checked,fontSizePx:f.type==="checkbox"?0:11,markSizePx:checked?11:0,viewportBBox,lines,markBBox,markPath});
 }
 alive();return {schema:1,policy:input.policy,inputSha256:input.inputSha,fontSha256:input.fontSha,textPreserved:document.body.textContent===expectedBody,unobscured:true,printMedia:matchMedia("print").matches,documentScriptsBlocked:scripts(),fields};
}`

// Snapshot observes existing nodes; it does not fit, rebuild or normalize.
// Exact DOM/computed-style hashes supplement actual boxes and platform fonts.
// Raw values remain in the plan/measurement; no claim that CRLF and LF have
// different visible ink is made.
const SnapshotFunctionV1 = `async function(input) {
 "use strict";
 const started=performance.now();let work=0;
 const alive=()=>{if(++work>100000||performance.now()-started>2000)throw new Error("budget");};
 const near=(a,b)=>Number.isFinite(a)&&Math.abs(a-b)<=0.001;
 const box=n=>{const b=n.getBoundingClientRect();return {x:b.x,y:b.y,width:b.width,height:b.height};};
 const same=(a,b)=>["x","y","width","height"].every(k=>near(a[k],b[k]));
 const bbox=n=>{const b=n.getBBox();return {x:b.x,y:b.y,width:b.width,height:b.height};};
 const styleNames=["display","visibility","opacity","fill","stroke","stroke-width","font-family","font-size","font-weight","font-style","white-space","direction","unicode-bidi","letter-spacing","word-spacing","transform","clip-path","mask","filter","overflow","mix-blend-mode","position","left","top","width","height"];
 const styles=n=>{alive();const s=getComputedStyle(n);return styleNames.map(k=>[k,s.getPropertyValue(k)]);};
 const visible=n=>{const s=getComputedStyle(n);if(s.display==="none"||s.visibility!=="visible"||s.opacity!=="1"||s.transform!=="none"||s.filter!=="none"||s.clipPath!=="none"||s.mixBlendMode!=="normal")throw new Error("style");};
 if(!matchMedia("print").matches||document.fonts.status!=="loaded"||document.documentElement.getAttribute("data-ordinary-policy")!==input.policy||document.documentElement.getAttribute("data-ordinary-input")!==input.inputSha||document.documentElement.hasAttribute("data-hash-page-script")||document.documentElement.hasAttribute("data-hash-event-handler")||document.getElementById("hash-page-script-effect")||document.body.childNodes.length!==input.fields.length)throw new Error("document");
 const capturedStyles=[styles(document.documentElement),styles(document.body)],fields=[];
 for(let i=0;i<input.fields.length;i++){
  alive();const f=input.fields[i],svg=document.body.childNodes[i];
  if(svg.nodeName!=="svg"||svg.namespaceURI!=="http://www.w3.org/2000/svg"||svg.id!=="ordinary-field-"+i||!same(box(svg),f.viewportBBox))throw new Error("geometry");
  visible(svg);const fieldStyles=[styles(svg)],lines=[];
  let at=0,markBBox={x:0,y:0,width:0,height:0};
  if(f.checked){
   if(svg.childNodes.length!==1)throw new Error("mark");
   const mark=svg.childNodes[0],path=mark.childNodes[0];
   if(mark.nodeName!=="svg"||mark.id!=="ordinary-mark-"+i||mark.childNodes.length!==1||path.nodeName!=="path"||path.getAttribute("d")!==f.markPath||!same(bbox(svg),f.markBBox))throw new Error("mark");
   visible(mark);visible(path);fieldStyles.push(styles(mark),styles(path));markBBox=bbox(svg);at=svg.childNodes.length;
  }
  for(let j=0;j<f.lines.length;j++){
   alive();const l=f.lines[j],node=svg.childNodes[at++];
   if(!node||node.nodeName!=="text"||node.id!=="ordinary-line-"+i+"-"+j||node.textContent!==l.text||!near(+node.getAttribute("x"),l.x)||!near(+node.getAttribute("y"),l.y)||!same(bbox(node),l.bbox))throw new Error("line");
   visible(node);fieldStyles.push(styles(node));lines.push({bbox:bbox(node),fonts:[]});
   if(l.hardBreak){const hard=svg.childNodes[at++];if(!hard||hard.nodeType!==3||hard.textContent!==l.hardBreak)throw new Error("break");}
  }
  if(at!==svg.childNodes.length)throw new Error("extra");
  capturedStyles.push(fieldStyles);fields.push({id:f.id,viewportBBox:box(svg),lines,markBBox});
 }
 const encoder=new TextEncoder();
 const sha=async text=>{alive();if(text.length>16777216)throw new Error("budget");const bytes=encoder.encode(text);if(bytes.length>16777216)throw new Error("budget");const h=await crypto.subtle.digest("SHA-256",bytes);return Array.from(new Uint8Array(h),b=>b.toString(16).padStart(2,"0")).join("");};
 const domSha256=await sha(document.documentElement.outerHTML),computedStylesSha256=await sha(JSON.stringify(capturedStyles)),bodyTextSha256=await sha(document.body.textContent);
 alive();return {schema:1,inputSha256:input.inputSha,recipeSha256:input.recipeSha,domSha256,computedStylesSha256,bodyTextSha256,fields};
}`
