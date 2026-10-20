// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"net/netip"
	"testing"
)

// These are immutable output/measurement regressions. Actual PG journeys must
// separately prove the same native State/M94/header and constructor boundary.
func TestHistoricalCertificateEventViewDoesNotChangePrivateEvidenceV1(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.4")
	view := &generated.Event{Kind: "document.signed", Ua: pgtype.Text{String: "browser", Valid: true}, PayloadJson: []byte("{}"), PayloadHashed: []byte("canonical"), PrevHash: bytes.Repeat([]byte{1}, 32), RowHash: bytes.Repeat([]byte{2}, 32), Ip: &ip}
	private := historicalCertificateCloneEventV1(view)
	wantRaw := int64(len(view.Kind) + len(view.Ua.String) + len(view.PayloadHashed) + len(view.PrevHash) + len(view.RowHash))
	actual, err := historicalCertificateEventRawV1(view)
	if err != nil || actual != wantRaw {
		t.Fatalf("complete original raw schema changed: %d %v", actual, err)
	}
	view.PayloadJson[0] = 'x'
	view.PayloadHashed[0] = 'x'
	view.PrevHash[0] = 3
	view.RowHash[0] = 4
	*view.Ip = netip.MustParseAddr("192.0.2.5")
	if string(private.PayloadJson) != "{}" || string(private.PayloadHashed) != "canonical" || private.PrevHash[0] != 1 || private.RowHash[0] != 2 || private.Ip.String() != "192.0.2.4" {
		t.Fatal("returned event changed private admitted evidence")
	}
	// JSON wire is deliberately priced separately from this original raw schema.
	view.PayloadJson = bytes.Repeat([]byte("x"), 8192)
	raw, err := historicalCertificateEventRawV1(view)
	if err != nil || raw != actual {
		t.Fatal("raw schema silently expanded or excluded a real raw field")
	}
	if historicalCertificateClaimsOutputResourcesV1() <= 0 {
		t.Fatal("derived fixed claim output has no native price")
	}
}
