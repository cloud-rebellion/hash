// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package htmlmaster

import (
	"net/url"
	"strings"
	"unicode"
)

// Source links produce renderer navigation annotations; Hash PDF cleaning
// currently flattens them. These links are never render resources.
// Resource fetching remains restricted to admitted hash-asset images/fonts.
func validSourceLinkV1(raw string) bool {
	if raw == "" || strings.ContainsAny(raw, "\\") {
		return false
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Opaque == "" && u.User == nil && u.Host != "" && u.Hostname() != ""
}
