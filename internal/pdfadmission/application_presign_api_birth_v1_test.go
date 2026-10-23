// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
)

func TestPreSignAPIBirthCannotUseReaderOrCredentialShellsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, reader := range []*ApplicationHTMLAuthoringReaderV1{nil, {}, func() *ApplicationHTMLAuthoringReaderV1 {
		r := &ApplicationHTMLAuthoringReaderV1{}
		r.self = r
		return r
	}()} {
		api := auth.PreSignAPIAdmissionV1{}
		request := uuid.New()
		if _, err := reader.LockPreSignAPIBirthAuthorityV1(ctx, api, presign.Reference{}, presign.Reference{}); err == nil {
			t.Fatal("shell manufactured API authority")
		}
		if _, err := reader.ReadPreSignAPISourceV1(ctx, api, request); err == nil {
			t.Fatal("shell read an original source")
		}
		if err := reader.SealPreSignAPISourceV1(ctx, api, PreSignAPISourceCommandV1{}, presign.TemplatePin{}); err == nil {
			t.Fatal("shell manufactured source provenance")
		}
		if _, _, err := reader.ClosePreSignAPISourceV1(ctx, api, request, uuid.New()); err == nil {
			t.Fatal("shell manufactured original closure")
		}
	}
}
