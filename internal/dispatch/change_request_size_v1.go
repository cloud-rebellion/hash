// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"fmt"
	"math"
)

// ChangeRequestNotificationComponentsV1 bounds the three logical output byte
// counts of ONE unchanged KindChangesRequested render of this actual context.
// It performs length arithmetic only, before Render parses or escapes input.
// The caller still owns the context, templates, rendering work, output buffers
// and last consumers. These counts confer no work or transaction authority and
// are not allocator, GC or RSS bounds. Other notification kinds are not covered.
// The companion template-shape test binds the interpolation multiplicities and
// contexts used here to the actual templates in templates.go.
func ChangeRequestNotificationComponentsV1(ctx TemplateContext) (subjectBytes, htmlBytes, textBytes int64, err error) {
	subjectBytes = int64(len(" requested changes to "))
	htmlBytes = int64(len(changesRequestedHTML))
	textBytes = int64(len(changesRequestedText))
	for _, value := range [...]string{ctx.RecipientName, ctx.DocumentName} {
		subjectBytes, err = addChangeRequestNotificationBytesV1(subjectBytes, int64(len(value)), 1)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	// Each field occurs once in each body. Six bytes per source byte covers
	// HTML text escaping, NUL/invalid UTF8 replacement and the text body's
	// existing html/template escaping. Counting the complete source templates
	// also includes all optional literal branches and overcounts action syntax.
	for _, value := range [...]string{ctx.RecipientName, ctx.DocumentName, ctx.ChangeContext, ctx.ChangeQuote, ctx.DeclineReason, ctx.ChangeProposed} {
		htmlBytes, err = addChangeRequestNotificationBytesV1(htmlBytes, int64(len(value)), 6)
		if err != nil {
			return 0, 0, 0, err
		}
		textBytes, err = addChangeRequestNotificationBytesV1(textBytes, int64(len(value)), 6)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	for _, value := range [...]string{ctx.ApproveURL, ctx.DenyURL, ctx.OpenURL} {
		// URL normalization can first percent-encode each byte into three;
		// subsequent quoted-attribute escaping is bounded by six. The fixed
		// filter replacement is included even when a URL is empty. Original
		// Render/validateEmailLink still decides URL acceptance and errors.
		htmlBytes, err = addChangeRequestNotificationBytesV1(htmlBytes, int64(len(value)), 18)
		if err != nil {
			return 0, 0, 0, err
		}
		htmlBytes, err = addChangeRequestNotificationBytesV1(htmlBytes, int64(len("#ZgotmplZ")), 1)
		if err != nil {
			return 0, 0, 0, err
		}
		textBytes, err = addChangeRequestNotificationBytesV1(textBytes, int64(len(value)), 6)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	return subjectBytes, htmlBytes, textBytes, nil
}

func addChangeRequestNotificationBytesV1(total, size, factor int64) (int64, error) {
	if total < 0 || size < 0 || factor <= 0 || size > (math.MaxInt64-total)/factor {
		return 0, fmt.Errorf("change request notification size overflows")
	}
	return total + size*factor, nil
}
