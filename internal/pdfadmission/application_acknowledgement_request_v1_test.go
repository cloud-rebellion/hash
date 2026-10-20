// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/article13"
)

func TestAcknowledgementRequestPricesConcreteEscapedNoticeBeforeCanonicalizationV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	evidence := article13.Evidence{Schema: article13.SchemaV1, Digest: strings.Repeat("a", 64), Snapshot: article13.Snapshot{Schema: article13.SchemaV1, Controller: strings.Repeat("\x01é<&", 4096), Copy: article13.Copy{RightsBody: strings.Repeat("\u2028\n\t", 4096)}}}
	parent, err := acknowledgementRequestParentBytesV1(ctx, "127.0.0.1", strings.Repeat("\x00é<&", 2048), evidence)
	if err != nil {
		t.Fatal(err)
	}
	// Independent concrete encoder output, including real escaping. This is a
	// logical producer bound; this pure test makes no native SQL or RSS claim.
	wire, err := json.Marshal(evidence)
	if err != nil || parent <= int64(len(wire)) {
		t.Fatal("actual escaped Article13 canonical output omitted", len(wire), parent, err)
	}
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := acknowledgementRequestParentBytesV1(stopped, "", "", evidence); err == nil {
		t.Fatal("cancelled notice preparation admitted")
	}
}

func TestAcknowledgementRequestRequiresGenuineOriginalReaderV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	var factory ApplicationSessionFactoryV1
	var reader ApplicationSignerReaderV1
	if request, err := factory.NewAcknowledgementRequestV1(ctx, &reader, "", "", article13.Evidence{}); err == nil || request != nil {
		t.Fatal("zero reader minted acknowledgement provenance")
	}
	var work ApplicationHTMLSendWorkV1
	if finish, err := work.BeginAcknowledgementMutationV1(ctx, &ApplicationAcknowledgementRequestV1{}); err == nil || finish != nil {
		t.Fatal("zero request minted native mutation")
	}
	var request ApplicationAcknowledgementRequestV1
	request.CloseConsumerV1()
	if _, _, err := request.MetadataV1(); err == nil {
		t.Fatal("zero request supplied retained metadata")
	}
	original := &applicationAcknowledgementRequestV1{}
	original.self = original
	copy := &applicationAcknowledgementRequestV1{self: original}
	(&ApplicationAcknowledgementRequestV1{state: copy}).CloseConsumerV1()
	if original.consumerClosed || original.closed {
		t.Fatal("copied request shell retired original owner")
	}
}

func TestAcknowledgementAuditPurposePreservesOriginalExactFieldsV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	if HTMLAuditAcknowledgedV1.KindV1() != "document.accepted" {
		t.Fatal("acceptance event kind changed")
	}
	payload := map[string]any{"recipient_email": "recipient@example.test", "notice_schema": article13.SchemaV1, "notice_digest": strings.Repeat("a", 64), "notice_snapshot": article13.Snapshot{Schema: article13.SchemaV1}}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditAcknowledgedV1, payload); err != nil {
		t.Fatal("original acknowledgement evidence shape refused", err)
	}
	payload["invented_authority"] = true
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditAcknowledgedV1, payload); err == nil {
		t.Fatal("acknowledgement producer accepted an invented schema")
	}
}
