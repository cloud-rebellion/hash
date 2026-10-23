// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestSupersessionContextCannotUseReaderShellOrAvailabilityFlagAsAuthorityV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, r := range []*ApplicationHTMLAuthoringReaderV1{nil, {}, func() *ApplicationHTMLAuthoringReaderV1 {
		x := &ApplicationHTMLAuthoringReaderV1{}
		x.self = x
		return x
	}()} {
		for _, available := range []bool{false, true} {
			if raw, err := r.ReadPreSignSupersessionContextV1(ctx, uuid.New(), uuid.New(), available); err == nil || raw != nil {
				t.Fatal("shell manufactured authenticated retained parent context")
			}
		}
	}
}
