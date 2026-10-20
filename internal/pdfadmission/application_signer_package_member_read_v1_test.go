// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are finite receipt/owner tests, not token/SQL/provider acceptance. The
// handler PG journey and actual local SDK tests own those distinct assertions.
func TestSignerPackageMemberVerifiedReceiptV1(t *testing.T) {
	org, root, packageID, memberID, attemptID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	deadline := time.Date(2037, 1, 2, 3, 4, 5, 0, time.UTC)
	var namespace [32]byte
	namespace[0] = 41
	digest := bytes.Repeat([]byte{7}, 32)
	m := documentpackage.MemberV1{DocumentID: memberID, PDF: documentpackage.PDFPinV1{Key: " exact opaque key ", VersionID: " exact opaque version ", SHA256: hex.EncodeToString(digest), Bytes: 1234, Pages: 2}}
	a := HTMLSendPackageAttemptObservationV1{AttemptID: attemptID, Outcome: HTMLSendPackageAttemptCompletedV1, Capture: HTMLSendPackageCaptureMetadataV1{OrgID: org, DocumentID: root, PackageID: packageID, Revision: 4, MemberCount: 3}, RetainUntil: deadline}
	original := generated.ListDocumentPackageSendRetentionMembersV1Row{AttemptID: attemptID, OrgID: org, DocumentID: root, PackageID: packageID, CaptureRevision: 4, MemberCount: 3, MemberPosition: 2, MemberDocumentID: memberID, PdfKey: m.PDF.Key, PdfVersionID: m.PDF.VersionID, PdfSha256: digest, PdfBytes: 1234, PdfPages: 2, ProviderNamespaceSha256: namespace[:], StartedAt: pgtype.Timestamptz{Time: deadline.Add(-time.Hour), Valid: true}, VerifiedAt: pgtype.Timestamptz{Time: deadline.Add(-time.Minute), Valid: true}, ObservedMode: pgtype.Text{String: "COMPLIANCE", Valid: true}, ObservedRetainUntil: pgtype.Timestamptz{Time: deadline.Add(time.Hour), Valid: true}, VerifierProfile: pgtype.Text{String: "s3-compliance-digest-v1", Valid: true}}
	if !signerPackageMemberReceiptV1(&original, a, m, 2, namespace) {
		t.Fatal("exact verified annex receipt refused")
	}
	for _, tc := range []struct {
		name   string
		change func(*generated.ListDocumentPackageSendRetentionMembersV1Row)
	}{
		{"another attempt cannot supply receipt", func(r *generated.ListDocumentPackageSendRetentionMembersV1Row) { r.AttemptID = uuid.New() }},
		{"same key other version cannot supply bytes", func(r *generated.ListDocumentPackageSendRetentionMembersV1Row) { r.PdfVersionID = "other-version" }},
		{"exact opaque key cannot be trimmed", func(r *generated.ListDocumentPackageSendRetentionMembersV1Row) {
			r.PdfKey = strings.TrimSpace(r.PdfKey)
		}},
		{"other provider namespace cannot supply receipt", func(r *generated.ListDocumentPackageSendRetentionMembersV1Row) {
			r.ProviderNamespaceSha256 = bytes.Repeat([]byte{9}, 32)
		}},
		{"unverified marker cannot supply receipt", func(r *generated.ListDocumentPackageSendRetentionMembersV1Row) { r.VerifiedAt = pgtype.Timestamptz{} }},
		{"governance does not prove compliance", func(r *generated.ListDocumentPackageSendRetentionMembersV1Row) { r.ObservedMode.String = "GOVERNANCE" }},
		{"shorter retention cannot satisfy original target", func(r *generated.ListDocumentPackageSendRetentionMembersV1Row) {
			r.ObservedRetainUntil.Time = deadline.Add(-time.Second)
		}},
		{"other position cannot substitute selected annex", func(r *generated.ListDocumentPackageSendRetentionMembersV1Row) { r.MemberPosition = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := original
			tc.change(&r)
			if signerPackageMemberReceiptV1(&r, a, m, 2, namespace) {
				t.Fatal("mismatched receipt accepted")
			}
		})
	}
	original.ObservedRetainUntil.Time = deadline
	if !signerPackageMemberReceiptV1(&original, a, m, 2, namespace) {
		t.Fatal("exact original deadline refused")
	}
}

func TestSignerPackageMemberOriginalBorrowRetirementV1(t *testing.T) {
	// No SQL authority is constructed here: only the private bookkeeping owner,
	// its existing reader-retirement predicate and copied close are exercised.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p := &applicationSessionFactoryStateV1{}
	f := &ApplicationSessionFactoryV1{state: p}
	originalReleased, nativeReleased := 0, 0
	reader := &ApplicationSignerReaderV1{factory: f, models: &ApplicationSignerReadModelsV1{Document: &generated.Document{}}, packageMemberBorrowers: 1, consumers: []func(){func() { originalReleased++ }}}
	reader.self = reader
	call, stop := context.WithCancel(ctx)
	s := &applicationSignerPackageMemberReadStateV1{factory: f, reader: reader, ctx: call, cancel: stop, originalBorrow: true, active: 1, release: func() { nativeReleased++ }}
	s.self = s
	p.signerPackageMemberReads[0] = s
	h := &ApplicationSignerPackageMemberReadV1{state: s}
	copied := *h
	reader.CloseConsumerV1()
	copied.CloseConsumerV1()
	if err := h.CloseV1(ctx); !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatal("active original operation was treated as joined", err)
	}
	if h.RetiredV1() || nativeReleased != 0 || originalReleased != 0 || reader.models == nil || reader.packageMemberBorrowers != 1 || f.PendingV1().SignerPackageMemberReads != 1 {
		t.Fatal("copied close/cancel refunded active original reader or native controls")
	}
	if err := reader.reconcileV1(ctx); !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatal("original reader retired around active native borrower", err)
	}
	s.finishV1()
	if !h.RetiredV1() || nativeReleased != 1 || originalReleased != 1 || reader.models != nil || reader.packageMemberBorrowers != 0 || f.PendingV1().SignerPackageMemberReads != 0 {
		t.Fatal("actual last-use did not retire once")
	}
	copied.CloseConsumerV1()
	if err := copied.CloseV1(ctx); err != nil || nativeReleased != 1 || originalReleased != 1 || reader.packageMemberBorrowers != 0 {
		t.Fatal("copied close retired original borrow twice", err)
	}
}

func TestSignerPackageMemberUnboundInputV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, h := range []*ApplicationSignerPackageMemberReadV1{nil, {}, {state: &applicationSignerPackageMemberReadStateV1{ctx: ctx}}} {
		if h.LoadV1() == nil {
			t.Fatal("unbound shell supplied native read authority")
		}
		if _, err := h.ObservationV1(); err == nil {
			t.Fatal("unbound shell supplied observation")
		}
		if h.WithPDFV1(func(SignerPackageMemberPDFMetadataV1, []byte) error { t.Fatal("unbound PDF delivered"); return nil }) == nil {
			t.Fatal("unbound output accepted")
		}
		h.CloseConsumerV1()
	}
	if _, err := new(ApplicationSessionFactoryV1).NewSignerPackageMemberReadV1(ctx, new(ApplicationSignerReaderV1), nil, SignerPackageMemberExpectedV1{}); err == nil {
		t.Fatal("caller reader became native authority")
	}
}
