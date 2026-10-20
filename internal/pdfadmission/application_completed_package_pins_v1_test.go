// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestCompletedPackagePurposeCannotMintFromCallerRowsV1(t *testing.T) {
	var f ApplicationSessionFactoryV1
	var r ApplicationSignerReaderV1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if h, err := f.NewCompletedSignerPackageReadInputV1(ctx, &r); err == nil || h != nil {
		t.Fatal("zero reader minted completed package input")
	}
	if h, err := f.NewCompletedSignerPackageMemberReadV1(ctx, &r, nil, SignerPackageMemberExpectedV1{}); err == nil || h != nil {
		t.Fatal("zero reader minted completed byte owner")
	}
	if signerPackageActiveProfileV1.readerModeV1() != SignerReadActiveResponseV1 || signerPackageCompletedProfileV1.readerModeV1() != SignerReadCompletedV1 || applicationSignerPackageProfileV1(0).readerModeV1() != "" {
		t.Fatal("public purposes share authority")
	}
}
func TestCompletedPackagePinsPreserveOpaqueValuesAndLegacyAbsenceV1(t *testing.T) {
	d := &generated.Document{Status: "completed", CompletionEffectiveAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true}, FinalPdfKey: pgtype.Text{String: " exact old final key ", Valid: true}, FinalPdfVersionID: pgtype.Text{String: " exact opaque version ", Valid: true}, FinalPdfSha: make([]byte, 32)}
	d.FinalPdfSha[0] = 7
	p, err := completedPackagePinsV1(d)
	if err != nil {
		t.Fatal("ordinary completed observation required an invented report", err)
	}
	copy := p.cloneV1()
	d.FinalPdfSha[0] = 9
	if copy.keys[0] != " exact old final key " || copy.versions[0] != " exact opaque version " || copy.sums[0][0] != 7 || copy.keys[1] != "" {
		t.Fatal("original completed pin was replaced, normalized or invented")
	}
	d.Status = "sent"
	if _, err := completedPackagePinsV1(d); err == nil {
		t.Fatal("active row treated as completed observation")
	}
}
