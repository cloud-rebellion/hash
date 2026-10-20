// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blocks

import (
	"golang.org/x/net/html"
)

// These fixed construction points add no parser, grammar, limits or validity
// policy. The original checked parser runs its original source/token guard;
// actual native callers fund tokenization, original DOM and canonical output
// before each can allocate. An admission failure never returns partial output.
type HTMLImportConstructionV1 interface {
	BeforeHTMLTokensV1(string) error
	BeforeHTMLDOMV1(string) error
	BeforeHTMLBlocksV1(*html.Node) error
}
type MarkdownImportConstructionV1 interface{ BeforeMarkdownBlocksV1(string) error }
