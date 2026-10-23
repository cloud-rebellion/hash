// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/noticeaccess"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Pure metadata ownership tests, not fabricated native source/retention
// acceptance. The real initial/fresh read and provider journey is E2E below.
func laterNoticeSnapshot484Input() (noticeaccess.InputV1, amendments.IssueNoticeV1, []byte) {
	packageID := uuid.New()
	in := noticeaccess.InputV1{OrgID: uuid.New(), FileSetBytes: []byte(`{"exact":"stored"}`), Subject: "Synthetic notice", Text: "Synthetic exact later files", ReplyTo: "owner@example.test", FromName: "Synthetic owner", RecipientEmails: []string{"legal@example.test"}, FileSet: amendments.FileSetV1{Schema: "hash-amendment-files-v1", DocumentID: uuid.New(), PackageID: &packageID, PackageGeneration: "1", Files: []amendments.FileV1{{Title: "Exact file", Key: "synthetic/exact.pdf", VersionID: " frozen terminal+/opaque=version ", SHA256: strings.Repeat("a", 64), IntakeReportSHA256: strings.Repeat("b", 64)}}}}
	request := amendments.IssueNoticeV1{RequestID: uuid.New(), ExpectedHeadRevision: "1", Subject: in.Subject, Text: in.Text, RecipientEmails: []string{"legal@example.test"}, Reviewed: true}
	return in, request, []byte(`{"original":"immutable"}`)
}
func TestLaterNoticeSnapshotDetachedExactOpaqueMetadata484(t *testing.T) {
	in, request, pins := laterNoticeSnapshot484Input()
	cost, err := laterNoticeSnapshotResourcesV1(in, request, pins)
	if err != nil || cost <= 0 || cost > 8<<20 {
		t.Fatal("bounded metadata snapshot accidentally became another broad native read", cost, err)
	}
	cloned, captured, original := laterNoticeCloneSnapshotV1(in, request, pins)
	version := in.FileSet.Files[0].VersionID
	packageID := *in.FileSet.PackageID
	clear(in.FileSetBytes)
	clear(pins)
	in.FileSet.Files[0].Title = "caller changed"
	in.FileSet.Files[0].VersionID = "caller changed"
	*in.FileSet.PackageID = uuid.New()
	in.RecipientEmails[0] = "other@example.test"
	request.RecipientEmails[0] = "other@example.test"
	if !bytes.Equal(cloned.FileSetBytes, []byte(`{"exact":"stored"}`)) || !bytes.Equal(original, []byte(`{"original":"immutable"}`)) || cloned.FileSet.Files[0].Title != "Exact file" || cloned.FileSet.Files[0].VersionID != version || *cloned.FileSet.PackageID != packageID || cloned.RecipientEmails[0] != "legal@example.test" || captured.RecipientEmails[0] != "legal@example.test" {
		t.Fatal("detached owner retained mutable original buffers or normalized an opaque version")
	}
}
func TestLaterNoticeSnapshotRefusesOversizedRetainedMetadata484(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*noticeaccess.InputV1, *amendments.IssueNoticeV1, *[]byte)
	}{
		{"file_set", func(in *noticeaccess.InputV1, _ *amendments.IssueNoticeV1, _ *[]byte) {
			in.FileSetBytes = make([]byte, noticeaccess.MaxFileSetBytesV1+1)
		}},
		{"original_pins", func(_ *noticeaccess.InputV1, _ *amendments.IssueNoticeV1, pins *[]byte) { *pins = make([]byte, 32769) }},
		{"files", func(in *noticeaccess.InputV1, _ *amendments.IssueNoticeV1, _ *[]byte) {
			in.FileSet.Files = make([]amendments.FileV1, 18)
		}},
		{"audience", func(in *noticeaccess.InputV1, _ *amendments.IssueNoticeV1, _ *[]byte) {
			in.RecipientEmails = make([]string, 33)
		}},
		{"opaque_version", func(in *noticeaccess.InputV1, _ *amendments.IssueNoticeV1, _ *[]byte) {
			in.FileSet.Files[0].VersionID = strings.Repeat("x", 1025)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			in, request, pins := laterNoticeSnapshot484Input()
			test.change(&in, &request, &pins)
			if cost, err := laterNoticeSnapshotResourcesV1(in, request, pins); err == nil || cost != 0 {
				t.Fatal("unbounded metadata admitted before independent retention", cost, err)
			}
		})
	}
}
func TestLaterNoticeSnapshotCloseJoinsActualActiveBorrower484(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	limit := workguard.VectorV1{ParentBytes: 64}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	// Invalid-for-native-source shell exercises only the actual metadata grant
	// and active-consumer retirement primitive; it cannot authorize SQL/provider.
	h := &ApplicationLaterAmendmentNoticeV1{ctx: ctx, factory: &applicationSessionFactoryStateV1{}, snapshotGrant: grant}
	h.self = h
	if err = h.beginV1(); err != nil {
		t.Fatal(err)
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).Global.ParentBytes != 32 || h.retired || h.snapshotGrant == nil {
		t.Fatal("Close refunded a still-active detached metadata borrower")
	}
	h.finishV1()
	if got := c.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 || !h.retired || h.snapshotGrant != nil {
		t.Fatal("actual final consumer did not join the retained metadata grant", got)
	}
	h.CloseConsumerV1()
}
