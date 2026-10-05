// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package frontend

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
)

var inlineScriptRe = regexp.MustCompile(`(?s)<script\b([^>]*)>(.*?)</script>`)

// InlineScriptCSP hashes exact bootstrap script text, allowing the built SPA
// under strict script-src without enabling arbitrary inline scripts.
func InlineScriptCSP(shell []byte) string {
	var result strings.Builder
	for _, match := range inlineScriptRe.FindAllSubmatch(shell, -1) {
		if strings.Contains(strings.ToLower(string(match[1])), "src=") {
			continue
		}
		sum := sha256.Sum256(match[2])
		result.WriteString(" 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'")
	}
	return result.String()
}
