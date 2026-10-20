// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestPackageResponseRequiresOriginalNativeReaderV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	var factory ApplicationSessionFactoryV1
	var reader ApplicationSignerReaderV1
	if request, err := factory.NewPackageResponseRequestV1(ctx, &reader, nil, "accepted"); err == nil || request != nil {
		t.Fatal("zero reader minted response authority")
	}
	var work ApplicationHTMLSendWorkV1
	if finish, err := work.BeginPackageResponseV1(ctx, &ApplicationPackageResponseRequestV1{}); err == nil || finish != nil {
		t.Fatal("zero request minted a response mutation")
	}
	if err := work.ValidatePackageResponseV1(ctx); err == nil {
		t.Fatal("unbound work validated consent")
	}
	if err := work.RecordPackageResponseV1(ctx, &ApplicationHTMLAuditEventConsumerV1{}); err == nil {
		t.Fatal("unbound work wrote a receipt")
	}
	if matched, err := work.MatchPriorPackageResponseV1(ctx); err == nil || matched {
		t.Fatal("unbound work recovered an invented receipt")
	}
	// A copied private state cannot close the original, even if its fields look
	// plausible. Ordinary public-shell copies share the single owner instead.
	original := &applicationPackageResponseRequestV1{}
	original.self = original
	copy := &applicationPackageResponseRequestV1{self: original}
	(&ApplicationPackageResponseRequestV1{state: copy}).CloseConsumerV1()
	if original.closed || original.consumerClosed {
		t.Fatal("copied private state closed original")
	}
}

func TestPackageResponseAuditCannotWidenHistoricalSchemasV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	copy := documentpackage.IncorporationCopyV1()
	r := documentpackage.ResponseV1{ManifestSHA256: strings.Repeat("a", 64), LegalCommitmentSHA256: strings.Repeat("b", 64), IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256, Consent: true}
	payload := map[string]any{"recipient_email": "participant@example.test"}
	if err := r.BindAuditPayloadV1(payload, uuid.NewString(), uuid.NewString(), "2", "accepted"); err != nil {
		t.Fatal(err)
	}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditAcknowledgedV1, payload); err == nil {
		t.Fatal("historical acknowledgement accepted expanded package schema")
	}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditPackageAcknowledgedV1, payload); err != nil {
		t.Fatal("new fixed package event shape refused", err)
	}
	var session ApplicationSessionV1
	if owner, err := session.NewHTMLAuditEventV1(ctx, HTMLAuditPackageAcknowledgedV1, uuid.New(), uuid.New(), pgtype.UUID{Bytes: uuid.New(), Valid: true}, pgtype.UUID{}, "document.accepted", "", "", payload); err == nil || owner != nil {
		t.Fatal("generic event producer minted package response without native work")
	}
	payload["caller_authority"] = true
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditPackageAcknowledgedV1, payload); err == nil {
		t.Fatal("package event accepted invented authority")
	}
}
