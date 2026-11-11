// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/documentpurpose"
)

func TestAgentReviewRefusedForSigningPurposeAndUnknownMetadata(t *testing.T) {
	for _, p := range []documentpurpose.Purpose{documentpurpose.Document, documentpurpose.Presentation} {
		md, err := documentpurpose.With([]byte(`{}`), p)
		if err != nil {
			t.Fatal(err)
		}
		if err = requireNonSigningForAgentReviewV1(md); err != nil {
			t.Fatalf("agent review of %s refused: %v", p, err)
		}
	}
	signing, err := documentpurpose.With([]byte(`{}`), documentpurpose.Signing)
	if err != nil {
		t.Fatal(err)
	}
	for name, md := range map[string][]byte{
		"explicit signing": signing, "empty metadata (historical signing)": nil, "no purpose key": []byte(`{"other":1}`),
	} {
		if err := requireNonSigningForAgentReviewV1(md); !errors.Is(err, errHumanReviewRequiredV1) {
			t.Fatalf("%s: agent review allowed: %v", name, err)
		}
	}
	if err := requireNonSigningForAgentReviewV1([]byte(`{"hash_document_purpose":"garbage"}`)); err == nil || errors.Is(err, errHumanReviewRequiredV1) == false && !errors.Is(err, documentpurpose.ErrInvalid) {
		t.Fatalf("malformed purpose must fail closed: %v", err)
	}
	if got := safeMCPDesignFailureV1(errHumanReviewRequiredV1); !errors.Is(got, errHumanReviewRequiredV1) {
		t.Fatal("refusal reason collapsed into the generic failure", got)
	}
}
