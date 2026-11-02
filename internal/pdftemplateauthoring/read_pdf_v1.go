// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdftemplateauthoring

import (
	"context"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
)

// WithPDFBodyV1 is a retained native read consumer, not a new credential or a
// caller-created provider permit. ReadV1 already retired its physical SQL work.
func (r *ReadResultV1) WithPDFBodyV1(ctx context.Context, client *storage.Client, consume func([]byte) error) error {
	if r == nil || r.state == nil || r.state.source == nil {
		return pdfadmission.ErrPDFTemplateSourceV1
	}
	return r.state.source.WithPDFBodyV1(ctx, client, consume)
}
