// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"fmt"
	"github.com/bright-interaction/hash/internal/i18n"
	"strings"
)

// Only the two original completion email kinds are priced. This performs
// source-length arithmetic before substitution/escaping/template parsing; it
// grants no admission, SQL, provider or caller model authority. The unchanged
// renderer still decides locale, URL validity and required expiry errors.
func CompletedNotificationComponentsV1(kind string, ctx TemplateContext) (subjectBytes, htmlBytes, textBytes int64, err error) {
	if kind == KindCompletedSender {
		suffix := " signing ceremony complete"
		if ctx.Acknowledgement {
			suffix = " acknowledgements complete"
		}
		subjectBytes, err = inviteAddBytesV1(int64(len(suffix)), int64(len(ctx.DocumentName)), 1)
		if err != nil {
			return 0, 0, 0, err
		}
		htmlBytes = int64(len(completedSenderHTML))
		textBytes = int64(len(completedSenderText))
		// Each branch has a document and two distinct URL insertions. Counting BOTH fixed
		// branches permits no undercount and changes no original branch decision.
		htmlBytes, err = inviteAddBytesV1(htmlBytes, int64(len(ctx.DocumentName)), 12)
		if err != nil {
			return 0, 0, 0, err
		}
		textBytes, err = inviteAddBytesV1(textBytes, int64(len(ctx.DocumentName)), 12)
		if err != nil {
			return 0, 0, 0, err
		}
		htmlBytes, err = inviteAddBytesV1(htmlBytes, int64(len(ctx.DownloadURL)+len(ctx.AuditCertURL)+len(ctx.PackagePortalURL)), 18)
		if err != nil {
			return 0, 0, 0, err
		}
		htmlBytes, err = inviteAddBytesV1(htmlBytes, int64(len("#ZgotmplZ")), 1)
		if err != nil {
			return 0, 0, 0, err
		}
		textBytes, err = inviteAddBytesV1(textBytes, int64(len(ctx.DownloadURL)+len(ctx.AuditCertURL)+len(ctx.PackagePortalURL)), 6)
		return subjectBytes, htmlBytes, textBytes, err
	}
	if kind != KindCompletedSigner {
		return 0, 0, 0, fmt.Errorf("completion notification kind is unsupported")
	}
	loc := i18n.Normalize(ctx.Locale)
	prefix := catalogPrefix(kind, ctx)
	params := [...]struct{ token, value string }{{"{sender}", ctx.SenderName}, {"{email}", ctx.SenderEmail}, {"{document}", ctx.DocumentName}, {"{recipient}", ctx.RecipientName}, {"{org}", ctx.OrgName}, {"{expires_at}", ctx.DownloadExpiresAt}}
	translated := func(key string) (int64, error) {
		literal := i18n.T(loc, key, nil)
		n := int64(len(literal))
		for _, p := range params {
			var e error
			n, e = inviteAddBytesV1(n, int64(len(p.value)), int64(strings.Count(literal, p.token)))
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
	htmlBytes = int64(len(completedSignerHTML))
	textBytes = int64(len(completedSignerText))
	// Localized shared skeleton is below the complete original fallback. Every
	// fixed catalog insertion and optional CTA is then added independently.
	for _, suffix := range [...]string{"eyebrow", "heading", "body", "cta", "auditCta", "footer"} {
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
	htmlBytes, err = inviteAddBytesV1(htmlBytes, int64(len(ctx.DownloadURL)+len(ctx.AuditCertURL)+len(ctx.PackagePortalURL)), 6)
	if err != nil {
		return 0, 0, 0, err
	}
	textBytes, err = inviteAddBytesV1(textBytes, int64(len(ctx.DownloadURL)+len(ctx.AuditCertURL)+len(ctx.PackagePortalURL)), 1)
	return subjectBytes, htmlBytes, textBytes, err
}

// The original sender branch parses only these two fixed application-owned
// templates. Actual output/context demand remains separate and source-derived.
func CompletedSenderTemplateSourceBytesV1() int64 {
	return int64(len(completedSenderHTML) + len(completedSenderText))
}
