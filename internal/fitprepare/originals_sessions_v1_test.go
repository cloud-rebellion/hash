// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type originalCloserFixtureV1 struct {
	closed  bool
	cleanup chan struct{}
	err     error
}

func (c *originalCloserFixtureV1) Close(context.Context) error  { c.closed = true; return c.err }
func (c *originalCloserFixtureV1) IsClosed() bool               { return c.closed }
func (c *originalCloserFixtureV1) CleanupDone() <-chan struct{} { return c.cleanup }

func TestOriginalPhysicalCloseWaitsForCleanupV1(t *testing.T) {
	c := &originalCloserFixtureV1{cleanup: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	closed, err := originalClosePhysicalV1(ctx, c)
	if closed || !errors.Is(err, ErrOriginalSQLUnknownV1) || !c.closed {
		t.Fatal("logical closure was mistaken for physical cleanup")
	}
	close(c.cleanup)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	closed, err = originalClosePhysicalV1(ctx2, c)
	if !closed || err != nil {
		t.Fatal("positive cleanup witness did not reconcile")
	}
}

func TestOriginalPhysicalCloseRetainsUnknownResultV1(t *testing.T) {
	c := &originalCloserFixtureV1{cleanup: make(chan struct{}), err: errors.New("private transport detail")}
	close(c.cleanup)
	closed, err := originalClosePhysicalV1(context.Background(), c)
	if !closed || !errors.Is(err, ErrOriginalSQLUnknownV1) || err.Error() != ErrOriginalSQLUnknownV1.Error() {
		t.Fatal("physical cleanup must not convert an uncertain transport result into acknowledged SQL")
	}
}

func TestOriginalResourceOwnerAndPhysicalJoinV1(t *testing.T) {
	for _, ownerFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "owner_first", false: "physical_first"}[ownerFirst], func(t *testing.T) {
			var releases atomic.Int32
			body := []byte("private original bytes")
			l := &originalResourceLeaseV1{releases: []func(){func() { releases.Add(1) }}}
			l.ownBody(body)
			l.hold()
			if ownerFirst {
				l.releaseOwner()
			} else {
				l.releasePhysical()
			}
			if releases.Load() != 0 || !bytes.Equal(body, []byte("private original bytes")) {
				t.Fatal("original body or admission released before consumer and backend joined")
			}
			if ownerFirst {
				l.releasePhysical()
			} else {
				l.releaseOwner()
			}
			if releases.Load() != 1 || !bytes.Equal(body, make([]byte, len(body))) {
				t.Fatal("joined release failed to clear the original and return admission")
			}
			l.releaseOwner()
			l.releasePhysical()
			if releases.Load() != 1 {
				t.Fatal("duplicate resource release")
			}
		})
	}
}

func TestOriginalMetadataAndBodyAdmissionsJoinV1(t *testing.T) {
	var releases atomic.Int32
	l := &originalResourceLeaseV1{releases: []func(){func() { releases.Add(1) }}}
	l.hold()
	l.addRelease(func() { releases.Add(1) })
	l.releasePhysical()
	if releases.Load() != 0 {
		t.Fatal("metadata-first body admission released before its consumer")
	}
	l.releaseOwner()
	if releases.Load() != 2 {
		t.Fatal("metadata and original-body admission did not retire together")
	}
}
