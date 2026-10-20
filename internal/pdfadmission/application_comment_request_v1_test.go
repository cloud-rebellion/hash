// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func TestCommentInputRejectsReplacementContextBeforeIOV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	h, err := f.NewStaffCommentHTTPInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseConsumerV1()
	other, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	reader := &commentContextReaderV1{Reader: strings.NewReader(`{"body":"bounded"}`)}
	if _, release, err := h.DecodeStaffJSONV1(other, reader); !errors.Is(err, ErrCommentInputV1) || release != nil || reader.reads != 0 {
		t.Fatal("replacement context reached input IO", err, reader.reads)
	}
	_, release, err := h.DecodeStaffJSONV1(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}
	release()
	h.CloseConsumerV1()
	if c.SnapshotV1(org).Global != (workguard.VectorV1{}) {
		t.Fatal("genuine input did not drain")
	}
}

type commentContextReaderV1 struct {
	io.Reader
	reads int
}

func (r *commentContextReaderV1) Read(p []byte) (int, error) { r.reads++; return r.Reader.Read(p) }
func (r *commentContextReaderV1) Close() error               { return nil }

func TestStaffCommentRequestDerivesOnceFromCapturedInputV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	org, doc, user := uuid.New(), uuid.New(), uuid.New()
	h, err := f.NewStaffCommentHTTPInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	_, decoded, err := h.DecodeStaffJSONV1(ctx, io.NopCloser(strings.NewReader(`{"body":"actual private body"}`)))
	if err != nil {
		t.Fatal(err)
	}
	decoded()
	foreign, _ := htmlInputFactoryTestV1(t, 64<<20)
	if _, err = foreign.NewStaffCommentRequestV1(h, org, doc, user); err == nil {
		t.Fatal("foreign factory adopted input")
	}
	if _, err = f.NewStaffCommentRequestV1(h, uuid.New(), doc, user); err == nil {
		t.Fatal("foreign org adopted input")
	}
	req, err := f.NewStaffCommentRequestV1(h, org, doc, user)
	if err != nil {
		t.Fatal(err)
	}
	body, ip, ua, notice, err := req.MetadataV1()
	if err != nil || body != "actual private body" || ip != "" || ua != "" || notice.Schema != "" {
		t.Fatal("private staff declaration changed", err)
	}
	if _, err = f.NewStaffCommentRequestV1(h, org, doc, user); err == nil {
		t.Fatal("bound input reused")
	}
	op, err := req.NewOperationV1()
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	if op.deadline != deadline || op.original.Done() == ctx.Done() {
		t.Fatal("operation renewed original deadline or missed captured child")
	}
	if _, err = req.NewOperationV1(); err == nil {
		t.Fatal("operation regenerated")
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = op.CloseV1(cleanup); err != nil {
		t.Fatal(err)
	}
	copyHandle := *req
	copyHandle.CloseConsumerV1()
	req.CloseConsumerV1()
	h.CloseConsumerV1()
	if c.SnapshotV1(org).Global != (workguard.VectorV1{}) || f.PendingV1().HTMLInputProducers != 0 {
		t.Fatal("actual joined request/input debt remained")
	}
}

func TestCommentRequestCannotRenewCancelledInputOrInventReaderV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	h, err := f.NewSignerCommentHTTPInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	raw, release, err := h.ReadSignerJSONV1(ctx, io.NopCloser(strings.NewReader(`{"body":"genuine"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"body":"genuine"}` {
		t.Fatal("private source missing")
	}
	if err = h.CaptureSignerBodyV1(ctx, "genuine"); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err = f.NewSignerCommentRequestV1(nil, h, "", "", article13.Evidence{}); !errors.Is(err, ErrCommentRequestV1) {
		t.Fatal("nil reader granted public mutation")
	}
	cancel()
	if _, err = f.NewStaffCommentRequestV1(h, org, uuid.New(), uuid.New()); !errors.Is(err, ErrCommentRequestV1) {
		t.Fatal("cancelled input renewed")
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).Global != (workguard.VectorV1{}) {
		t.Fatal("cancelled original did not drain")
	}
}

func TestCommentAuditSchemasKeepOriginalSideAndNoticeBoundaryV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, p := range []HTMLAuditPurposeV1{HTMLAuditSignerCommentV1, HTMLAuditStaffCommentV1} {
		if p.KindV1() != "document.comment_posted" {
			t.Fatal("original event kind changed")
		}
		if _, err := htmlAuditPayloadShapeV1(ctx, p, map[string]any{"side": "sender"}); err != nil {
			t.Fatal(err)
		}
		if _, err := htmlAuditPayloadShapeV1(ctx, p, map[string]any{"body": "private"}); err == nil {
			t.Fatal("comment body added to original evidence schema")
		}
	}
	if !htmlAuditRootKeyV1(HTMLAuditSignerCommentV1, "notice_snapshot") || htmlAuditRootKeyV1(HTMLAuditStaffCommentV1, "notice_snapshot") {
		t.Fatal("public/staff notice scopes widened")
	}
}
