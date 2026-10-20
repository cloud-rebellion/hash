// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"bytes"
	"context"
	"errors"
)

// MaxHTMLMultipartBytes bounds the complete encoded request BODY, including
// multipart headers, fields and final framing. It is not an HTTP-header limit.
const MaxHTMLMultipartBytes = 24 << 20

var ErrHTMLMultipartTooLarge = errors.New("HTML render request exceeds the 24 MiB multipart body limit")

// htmlMultipartBuffer refuses an overflowing write atomically and remains
// failed even if a caller tries to write a later field or closing boundary.
// bytes.Buffer's capacity may exceed its length; existing local-owner growth
// accounting remains in force. This is an encoded-byte bound, not an RSS claim.
type htmlMultipartBuffer struct {
	bytes.Buffer
	err error
}

func (b *htmlMultipartBuffer) Write(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if len(p) > MaxHTMLMultipartBytes-b.Len() {
		b.err = ErrHTMLMultipartTooLarge
		return 0, b.err
	}
	return b.Buffer.Write(p)
}

// Preflight precedes []byte(html), MIME-header assembly and WriteField's
// string conversion. Charge raw components and a genuine lower bound on each
// part's framing; the writer then enforces the exact serialized size.
// No caller-supplied counts, and no arbitrary attachment-count ceiling.
func validateHTMLMultipartSize(ctx context.Context, source string, opts PDFOptions) error {
	remaining := MaxHTMLMultipartBytes
	charge := func(n int) bool {
		if n < 0 || n > remaining {
			return false
		}
		remaining -= n
		return true
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !charge(len(source)) || !charge(64) ||
		!charge(len(opts.WaitForExpression)) || !charge(len(opts.WaitDelay)) {
		return ErrHTMLMultipartTooLarge
	}
	assets := opts.Assets
	if assets == nil {
		assets = FontAssets()
	}
	for _, asset := range assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		mime := asset.Mime
		if mime == "" {
			mime = "font/woff2"
		}
		if !charge(64) || !charge(len(asset.Bytes)) ||
			!charge(len(asset.Filename)) || !charge(len(mime)) {
			return ErrHTMLMultipartTooLarge
		}
	}
	return nil
}
