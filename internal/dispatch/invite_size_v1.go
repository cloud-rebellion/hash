// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"fmt"
	"math"
	"strings"

	"github.com/bright-interaction/hash/internal/i18n"
)

// InviteNotificationComponentsV1 prices the three logical outputs of ONE
// original localized KindInvite/acknowledgement render. Only trusted fixed
// catalog strings are inspected here; actual context values are measured by
// length before Render substitutes/escapes them. This is neither admission nor
// a Go allocator/GC/RSS or downstream SMTP capacity proof. Render retains its
// original URL validation/error and locale fallback decisions.
func InviteNotificationComponentsV1(ctx TemplateContext) (subjectBytes, htmlBytes, textBytes int64, err error) {
	loc := i18n.Normalize(ctx.Locale)
	prefix := catalogPrefix(KindInvite, ctx)
	// Original localization substitutes each token once, never recursively.
	params := [...]struct{ token, value string }{
		{"{sender}", ctx.SenderName}, {"{email}", ctx.SenderEmail}, {"{document}", ctx.DocumentName},
		{"{recipient}", ctx.RecipientName}, {"{org}", ctx.OrgName}, {"{expires_at}", ctx.DownloadExpiresAt},
	}
	translated := func(key string) (int64, error) {
		literal := i18n.T(loc, key, nil)
		n := int64(len(literal))
		for _, p := range params {
			count := int64(strings.Count(literal, p.token))
			var e error
			n, e = inviteAddBytesV1(n, int64(len(p.value)), count)
			if e != nil {
				return 0, e
			}
		}
		return n, nil
	}
	subjectBytes, err = translated(prefix + ".subject")
	if err != nil {
		return 0, 0, 0, err
	}
	// The complete original fallback includes more literal markup than the
	// shared localized skeleton+CTA+or-open block. The source-topology oracle
	// binds that relation. Catalog text is added separately, with six-byte HTML
	// escaping, including invalid UTF8/NUL replacement. SignURL occurs three
	// times in localized HTML and once in the plain text output. Beacon ignored.
	htmlBytes = int64(len(inviteHTML))
	textBytes = int64(len(inviteText))
	for _, suffix := range [...]string{"eyebrow", "heading", "body", "cta"} {
		n, e := translated(prefix + "." + suffix)
		if e != nil {
			return 0, 0, 0, e
		}
		htmlBytes, e = inviteAddBytesV1(htmlBytes, n, 6)
		if e != nil {
			return 0, 0, 0, e
		}
		if suffix != "eyebrow" {
			textBytes, e = inviteAddBytesV1(textBytes, n, 1)
			if e != nil {
				return 0, 0, 0, e
			}
		}
	}
	footer, e := translated(footerKey(KindInvite, ctx))
	if e != nil {
		return 0, 0, 0, e
	}
	htmlBytes, e = inviteAddBytesV1(htmlBytes, footer, 6)
	if e != nil {
		return 0, 0, 0, e
	}
	textBytes, e = inviteAddBytesV1(textBytes, footer, 1)
	if e != nil {
		return 0, 0, 0, e
	}
	open, e := translated("email.common.orOpenUrl")
	if e != nil {
		return 0, 0, 0, e
	}
	htmlBytes, e = inviteAddBytesV1(htmlBytes, open, 6)
	if e != nil {
		return 0, 0, 0, e
	}
	htmlBytes, e = inviteAddBytesV1(htmlBytes, int64(len(ctx.SignURL)), 18)
	if e != nil {
		return 0, 0, 0, e
	}
	textBytes, e = inviteAddBytesV1(textBytes, int64(len(ctx.SignURL)), 1)
	if e != nil {
		return 0, 0, 0, e
	}
	return subjectBytes, htmlBytes, textBytes, nil
}
func inviteAddBytesV1(total, size, factor int64) (int64, error) {
	if total < 0 || size < 0 || factor < 0 || (factor > 0 && size > (math.MaxInt64-total)/factor) {
		return 0, fmt.Errorf("invite notification size overflows")
	}
	return total + size*factor, nil
}
