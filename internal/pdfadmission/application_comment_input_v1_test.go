// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func TestCommentInputPrivateSignerBytesAndBorrowLastUseV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	h, err := f.NewSignerCommentHTTPInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseConsumerV1()
	raw, finishRead, err := h.ReadSignerJSONV1(ctx, io.NopCloser(strings.NewReader(`{"body":"Original ÅÄÖ"}`)))
	if err != nil {
		t.Fatal(err)
	}
	var value CommentDeclarationV1
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("actual typed declaration unavailable")
	}
	// A returned validation view cannot rewrite the original private source.
	copyRaw := append([]byte(nil), raw...)
	copy(raw, bytes.Repeat([]byte("x"), len(raw)))
	if err := h.CaptureSignerBodyV1(ctx, value.Body); err != nil {
		t.Fatal("validation view changed the private original", err)
	}
	if !bytes.Equal(copyRaw, []byte(`{"body":"Original ÅÄÖ"}`)) {
		t.Fatal("unexpected original bytes")
	}
	finishRead()
	if _, _, err := f.bindCommentBodyV1(ctx, uuid.New(), h, commentSignerInputProfileV1); !errors.Is(err, ErrCommentInputV1) {
		t.Fatal("foreign org bound unconsumed private input")
	}
	foreign, _ := htmlInputFactoryTestV1(t, 64<<20)
	if _, _, err := foreign.bindCommentBodyV1(ctx, org, h, commentSignerInputProfileV1); !errors.Is(err, ErrCommentInputV1) {
		t.Fatal("foreign factory bound private input")
	}
	body, finishBody, err := f.bindCommentBodyV1(ctx, org, h, commentSignerInputProfileV1)
	if err != nil || body != "Original ÅÄÖ" {
		t.Fatal("native private body differs", err)
	}
	if _, _, err := f.bindCommentBodyV1(ctx, org, h, commentSignerInputProfileV1); !errors.Is(err, ErrCommentInputV1) {
		t.Fatal("input rebound")
	}
	if _, _, err := f.bindCommentBodyV1(ctx, uuid.New(), h, commentSignerInputProfileV1); !errors.Is(err, ErrCommentInputV1) {
		t.Fatal("foreign org bound input")
	}
	before := c.SnapshotV1(org)
	if before.GlobalGrants != 2 || before.Global.ParentBytes <= 2<<20 {
		t.Fatal("actual raw/parser debts absent", before)
	}
	copyHandle := *h
	copyHandle.CloseConsumerV1()
	cancel()
	if got := c.SnapshotV1(org); got.Global != before.Global || got.GlobalGrants != before.GlobalGrants || f.PendingV1().HTMLInputProducers != 1 {
		t.Fatal("close/cancel refunded live native body", got)
	}
	if body != "Original ÅÄÖ" {
		t.Fatal("live body changed on close")
	}
	finishBody()
	finishBody()
	h.CloseConsumerV1()
	if c.SnapshotV1(org).Global != (workguard.VectorV1{}) || f.PendingV1().HTMLInputProducers != 0 {
		t.Fatal("joined actual input retained debt")
	}
}

func TestCommentInputStaffKeepsOriginalStreamingGrammarV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	for _, tail := range []string{"", " trailing malformed", strings.Repeat("x", 2<<20)} {
		h, err := f.NewStaffCommentHTTPInputV1(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		value, finishDecode, err := h.DecodeStaffJSONV1(ctx, io.NopCloser(strings.NewReader(`{"body":"Staff ÅÄÖ"}`+tail)))
		if err != nil || value.Body != "Staff ÅÄÖ" {
			t.Fatal("original single Decode changed", err)
		}
		value.Body = "Caller replacement"
		if _, _, err := f.bindCommentBodyV1(ctx, org, h, commentSignerInputProfileV1); !errors.Is(err, ErrCommentInputV1) {
			t.Fatal("staff decoder supplied public declaration")
		}
		body, finishBody, err := f.bindCommentBodyV1(ctx, org, h, commentStaffInputProfileV1)
		if err != nil || body != "Staff ÅÄÖ" {
			t.Fatal("caller replaced native body", err)
		}
		h.CloseConsumerV1()
		finishDecode()
		if c.SnapshotV1(org).GlobalGrants != 1 || f.PendingV1().HTMLInputProducers != 1 {
			t.Fatal("body last use refunded after decoder joined")
		}
		finishBody()
		if c.SnapshotV1(org).GlobalGrants != 0 {
			t.Fatal("actual body did not drain")
		}
	}
	for _, raw := range []string{`{"unknown":1}`, `{"body":"` + strings.Repeat("x", 1<<20) + `"}`} {
		h, err := f.NewStaffCommentHTTPInputV1(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		_, release, err := h.DecodeStaffJSONV1(ctx, io.NopCloser(strings.NewReader(raw)))
		if err == nil || release != nil {
			t.Fatal("original unknown/size refusal lost")
		}
		if strings.HasPrefix(raw, `{"body"`) {
			var tooLarge *http.MaxBytesError
			if !errors.As(err, &tooLarge) || tooLarge.Limit != 1<<20 {
				t.Fatal("original1MiB ceiling changed", err)
			}
		}
		h.CloseConsumerV1()
	}
	if f.PendingV1().HTMLInputProducers != 0 || c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("failed decoder retained input")
	}
}

func TestCommentInputDenialPrecedesIOAndPrivateSourceMismatchV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	cost, err := commentInputReadCostV1(commentSignerInputProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	f, c := htmlInputFactoryTestV1(t, cost-1)
	if h, err := f.NewSignerCommentHTTPInputV1(ctx, org); h != nil || !errors.Is(err, ErrCommentInputV1) {
		t.Fatal("raw reader constructed before original budget", err)
	}
	if c.SnapshotV1(org).Global != (workguard.VectorV1{}) || f.PendingV1().HTMLInputProducers != 0 {
		t.Fatal("refused constructor leaked")
	}
	f, c = htmlInputFactoryTestV1(t, 64<<20)
	h, err := f.NewSignerCommentHTTPInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	raw, finish, err := h.ReadSignerJSONV1(ctx, io.NopCloser(strings.NewReader(`{"body":"Original"}`)))
	if err != nil {
		t.Fatal(err)
	}
	copy(raw, []byte(`{"body":"Changed!"}`))
	if err = h.CaptureSignerBodyV1(ctx, "Changed!"); !errors.Is(err, ErrCommentInputV1) {
		t.Fatal("replacement raw/typed declaration accepted", err)
	}
	if _, _, err = f.bindCommentBodyV1(ctx, org, h, commentSignerInputProfileV1); !errors.Is(err, ErrCommentInputV1) {
		t.Fatal("failed declaration supplied body")
	}
	h.CloseConsumerV1()
	finish()
	// Unregistered public/private shells provide no positive native authority.
	for _, shell := range []*ApplicationCommentInputV1{nil, {}, {state: &applicationHTMLAuthoringInputStateV1{}}, {state: &applicationHTMLAuthoringInputStateV1{factory: f.state, org: org, profile: commentSignerInputProfileV1, ready: true}}} {
		if _, _, err = f.bindCommentBodyV1(ctx, org, shell, commentSignerInputProfileV1); !errors.Is(err, ErrCommentInputV1) {
			t.Fatal("unregistered input shell bound")
		}
	}
	if c.SnapshotV1(org).GlobalGrants != 0 || f.PendingV1().HTMLInputProducers != 0 {
		t.Fatal("negative input controls acquired authority")
	}
}

func TestCommentInputBlockedReadKeepsRealFactoryDebtV1(t *testing.T) {
	for _, staff := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		f, c := htmlInputFactoryTestV1(t, 64<<20)
		org := uuid.New()
		var h *ApplicationCommentInputV1
		var err error
		if staff {
			h, err = f.NewStaffCommentHTTPInputV1(ctx, org)
		} else {
			h, err = f.NewSignerCommentHTTPInputV1(ctx, org)
		}
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		body := &htmlInputBlockedBodyV1{started: make(chan struct{}), finish: make(chan struct{})}
		done := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(body.finish) }) }
		t.Cleanup(func() {
			cancel()
			unblock()
			select {
			case <-done:
				h.CloseConsumerV1()
			case <-time.After(2 * time.Second):
				t.Error("actual comment decoder did not join")
			}
		})
		go func() {
			defer close(done)
			if staff {
				_, release, _ := h.DecodeStaffJSONV1(ctx, body)
				if release != nil {
					release()
				}
			} else {
				_, release, _ := h.ReadSignerJSONV1(ctx, body)
				if release != nil {
					release()
				}
			}
		}()
		select {
		case <-body.started:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		before := c.SnapshotV1(org)
		copyHandle := *h
		copyHandle.CloseConsumerV1()
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		if err = f.CloseV1(cleanup); !errors.Is(err, ErrApplicationSessionUnknownV1) {
			stop()
			t.Fatal("factory invented blocked input retirement", err)
		}
		if got := c.SnapshotV1(org); got.Global != before.Global || got.GlobalGrants != 1 || f.PendingV1().HTMLInputProducers != 1 {
			stop()
			t.Fatal("blocked read refunded", got)
		}
		unblock()
		select {
		case <-done:
		case <-cleanup.Done():
			stop()
			t.Fatal("actual blocked read did not join")
		}
		stop()
		h.CloseConsumerV1()
		if c.SnapshotV1(org).GlobalGrants != 0 || f.PendingV1().HTMLInputProducers != 0 {
			t.Fatal("joined blocked read retained native debt")
		}
	}
}
