// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestResponseReportReadinessUsesAllFreshRequiredRowsV1(t *testing.T) {
	r := func(role, status string) *generated.Recipient {
		return &generated.Recipient{Role: role, Status: status}
	}
	for _, tc := range []struct {
		name, kind string
		roles      []string
		rows       []*generated.Recipient
		ready      bool
		invalid    bool
	}{
		{"signed_complete", "signed", []string{"seller", "buyer"}, []*generated.Recipient{r("seller", "signed"), r("buyer", "signed"), r("cc", "pending"), r("viewer", "pending")}, true, false},
		{"signed_partial", "signed", []string{"seller", "buyer"}, []*generated.Recipient{r("seller", "signed"), r("buyer", "pending")}, false, false},
		{"second_required_party_pending", "signed", []string{"buyer"}, []*generated.Recipient{r("buyer", "signed"), r("buyer", "pending")}, false, false},
		{"required_role_absent", "signed", []string{"seller", "buyer"}, []*generated.Recipient{r("seller", "signed")}, false, true},
		{"no_required_roles", "signed", nil, []*generated.Recipient{r("buyer", "signed")}, false, true},
		{"accepted_complete", "accepted", nil, []*generated.Recipient{r("buyer", "accepted"), r("cc", "pending")}, true, false},
		{"accepted_partial", "accepted", nil, []*generated.Recipient{r("buyer", "accepted"), r("seller", "pending")}, false, false},
		{"accepted_only_cc", "accepted", nil, []*generated.Recipient{r("cc", "pending")}, false, true},
		{"nil_row", "accepted", nil, []*generated.Recipient{nil}, false, true},
		{"wrong_mode", "other", []string{"buyer"}, []*generated.Recipient{r("buyer", "signed")}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready, err := responseReportRecipientsReadyV1(tc.kind, tc.roles, tc.rows)
			if ready != tc.ready || (err != nil) != tc.invalid {
				t.Fatalf("ready=%v err=%v", ready, err)
			}
		})
	}
}

func TestResponseReportUnissuedOrCopiedOwnersRefuseV1(t *testing.T) {
	ctx := context.Background()
	work := &ApplicationHTMLSendWorkV1{}
	work.self = work
	copy := &ApplicationHTMLSendWorkV1{self: work}
	audit := &ApplicationHTMLAuditEventConsumerV1{}
	audit.self = audit
	for _, w := range []*ApplicationHTMLSendWorkV1{nil, {}, work, copy} {
		if err := w.PrepareResponseReportFamilyV1(ctx); !errors.Is(err, ErrHTMLSendWorkV1) {
			t.Fatalf("unissued family preparation: %v", err)
		}
		if err := w.AdmitResponseReportV1(ctx, audit); !errors.Is(err, ErrHTMLSendWorkV1) {
			t.Fatalf("unissued response admission: %v", err)
		}
		if row, members, err := w.BeginHistoricalFinalizingV1(ctx); row != nil || members != nil || !errors.Is(err, ErrHTMLSendWorkV1) {
			t.Fatalf("unissued historical claim: %v %v %v", row, members, err)
		}
	}
}

func TestResponseReportPrivateSizingReservationsAreFixedSafeBytesV1(t *testing.T) {
	clock, err := time.Parse(time.RFC3339Nano, responseCertificateSizingTimestampV1)
	if err != nil || clock.UTC().Format(time.RFC3339Nano) != responseCertificateSizingTimestampV1 || len(responseCertificateSizingTimestampV1) != len("9999-12-31T23:59:59.999999999Z") {
		t.Fatalf("invalid canonical sizing clock: %v", err)
	}
	if len(responseCertificateSizingDigestV1) != 64 {
		t.Fatal("sizing digest is not exactly SHA-256 hex width")
	}
	for _, c := range responseCertificateSizingDigestV1 {
		if c < '0' || c > '9' {
			t.Fatal("sizing digest contains escaped or non-hex content")
		}
	}
}
