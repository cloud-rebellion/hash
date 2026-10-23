// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type htmlAuditPrivateCause488V1 struct{}

func (*htmlAuditPrivateCause488V1) Error() string { return "PRIVATE_HEADER_BODY_SQL_PATH" }
func TestPreSign488NativeAuditDiagnosticPreservesFailureAndPrivacyV1(t *testing.T) {
	var session *ApplicationSessionV1
	_, err := session.NewHTMLAuditEventV1(context.Background(), HTMLAuditPreSignCommittedV1, uuid.New(), uuid.New(), pgtype.UUID{}, pgtype.UUID{}, HTMLAuditPreSignCommittedV1.KindV1(), "", "", nil)
	if !errors.Is(err, ErrHTMLAuditEventV1) || HTMLPreSignAuditFailureStageV1(err) != "prepare_scope" {
		t.Fatal("actual refused native prepare did not retain its sentinel and fixed scope stage")
	}
	invalid := &ApplicationHTMLAuditEventConsumerV1{purpose: HTMLAuditPreSignCommittedV1}
	err = invalid.WithPreparedV1(context.Background(), nil)
	if !errors.Is(err, ErrHTMLAuditEventV1) || HTMLPreSignAuditFailureStageV1(err) != "append_scope" {
		t.Fatal("actual refused native append lost its original refusal")
	}
	private := &htmlAuditPrivateCause488V1{}
	cause := errors.Join(private, ErrHTMLAuditEventV1)
	for _, stage := range []string{"prepare_scope", "prepare_shape", "prepare_resources", "prepare_session", "prepare_loan", "prepare_clone", "prepare_marshal", "append_scope", "append_document", "append_chain", "append_head", "append_callback", "append_identity", "append_insert", "append_cache", "append_return"} {
		e := htmlAuditFailureV1(HTMLAuditPreSignCommittedV1, stage, cause)
		var actual *htmlAuditPrivateCause488V1
		if !errors.Is(e, ErrHTMLAuditEventV1) || !errors.As(e, &actual) || actual != private || HTMLPreSignAuditFailureStageV1(fmt.Errorf("foreign: %w", e)) != stage {
			t.Fatal("diagnostic changed typed original cause or fixed substage")
		}
		if strings.Contains(e.Error(), "PRIVATE") || len(e.Error()) > 64 {
			t.Fatal("native diagnostic exposed a private cause or unbounded output")
		}
	}
	if htmlAuditFailureV1(HTMLAuditPreSignCommittedV1, "prepare_scope", nil) != nil {
		t.Fatal("successful audit became an error")
	}
	if htmlAuditFailureV1(HTMLAuditDocumentSentV1, "prepare_scope", cause) != cause {
		t.Fatal("historical non-presign audit error identity changed")
	}
	if HTMLPreSignAuditFailureStageV1(errors.New("prepare_scope PRIVATE_HEADER_BODY_SQL_PATH")) != "" {
		t.Fatal("foreign plaintext supplied a native substage")
	}
	unknown := htmlAuditFailureV1(HTMLAuditPreSignCommittedV1, "PRIVATE_DYNAMIC_FILENAME", cause)
	if HTMLPreSignAuditFailureStageV1(unknown) != "prepare_scope" || strings.Contains(unknown.Error(), "PRIVATE") {
		t.Fatal("dynamic label escaped fixed fallback")
	}
}
