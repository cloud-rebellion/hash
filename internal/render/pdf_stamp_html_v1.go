// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"fmt"
	"strings"
)

type PDFStampItemV1 struct {
	XPct, YPct, WPct, HPct float64
	HTML                   string
}

// buildPageOverlayHTML renders the overlay HTML for one page. The body fills
// the whole page; each item is absolutely positioned by percentage so it lands
// where the designer placed it once the page is stamped 1:1.
func BuildPageOverlayHTMLV1(items []PDFStampItemV1) string {
	return BuildSizedPageOverlayHTMLV1(items, 0, 0)
}

func BuildSizedPageOverlayHTMLV1(items []PDFStampItemV1, width, height float64) string {
	var sb strings.Builder
	sb.WriteString(`<!doctype html><html><head><meta charset="utf-8"><style>`)
	if width > 0 && height > 0 {
		fmt.Fprintf(&sb, `@page{margin:0;size:%.9fpt %.9fpt}`, width, height)
	} else {
		sb.WriteString(`@page{margin:0}`)
	}
	sb.WriteString(`html,body{margin:0;padding:0;height:100%;width:100%}`)
	sb.WriteString(`.f{position:absolute;box-sizing:border-box;display:flex;align-items:center;` +
		`font-family:Inter,system-ui,sans-serif;font-size:11px;color:#111;overflow:hidden;line-height:1.2}`)
	sb.WriteString(SignatureCSSV1())
	sb.WriteString(`</style></head><body>`)
	for _, it := range items {
		fmt.Fprintf(&sb,
			`<div class="f" style="left:%.4f%%;top:%.4f%%;width:%.4f%%;height:%.4f%%">%s</div>`,
			it.XPct, it.YPct, it.WPct, it.HPct, it.HTML)
	}
	sb.WriteString(`</body></html>`)
	return sb.String()
}
