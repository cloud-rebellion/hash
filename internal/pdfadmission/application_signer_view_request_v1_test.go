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

func TestSignerViewRequestPricesConcreteEscapedNoticeBeforeCanonicalizationV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	evidence := article13.Evidence{Schema: article13.SchemaV1, Digest: strings.Repeat("a", 64), Snapshot: article13.Snapshot{Schema: article13.SchemaV1, Controller: strings.Repeat("\x01é<&", 4096), Copy: article13.Copy{RightsBody: strings.Repeat("\u2028\n\t", 4096)}}}
	parent, err := signerViewRequestParentBytesV1(ctx, "127.0.0.1", strings.Repeat("\x00é<&", 2048), evidence)
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
	if _, err := signerViewRequestParentBytesV1(stopped, "", "", evidence); err == nil {
		t.Fatal("cancelled notice preparation admitted")
	}
}

func TestSignerViewRequestRequiresGenuineOriginalReaderV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	var factory ApplicationSessionFactoryV1
	var reader ApplicationSignerReaderV1
	if request, err := factory.NewSignerViewRequestV1(ctx, &reader, "", "", article13.Evidence{}); err == nil || request != nil {
		t.Fatal("zero reader minted signerView provenance")
	}
	var work ApplicationHTMLSendWorkV1
	if finish, err := work.BeginSignerViewMutationV1(ctx, &ApplicationSignerViewRequestV1{}); err == nil || finish != nil {
		t.Fatal("zero request minted native mutation")
	}
	var request ApplicationSignerViewRequestV1
	request.CloseConsumerV1()
	if _, _, err := request.MetadataV1(); err == nil {
		t.Fatal("zero request supplied retained metadata")
	}
	original := &applicationSignerViewRequestV1{}
	original.self = original
	copy := &applicationSignerViewRequestV1{self: original}
	(&ApplicationSignerViewRequestV1{state: copy}).CloseConsumerV1()
	if original.consumerClosed || original.closed {
		t.Fatal("copied request shell retired original owner")
	}
}

func TestSignerViewAuditPurposePreservesOriginalExactFieldsV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	if HTMLAuditSignerViewedV1.KindV1() != "document.viewed" {
		t.Fatal("acceptance event kind changed")
	}
	payload := map[string]any{"notice_schema": article13.SchemaV1, "notice_digest": strings.Repeat("a", 64), "notice_snapshot": article13.Snapshot{Schema: article13.SchemaV1}}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditSignerViewedV1, payload); err != nil {
		t.Fatal("original signerView evidence shape refused", err)
	}
	payload["invented_authority"] = true
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditSignerViewedV1, payload); err == nil {
		t.Fatal("signerView producer accepted an invented schema")
	}
}
