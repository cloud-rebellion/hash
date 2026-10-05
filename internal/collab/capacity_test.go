// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package collab

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"sync"
	"testing"
)

func TestCollabUserCapacityAndRelease(t *testing.T) {
	h := NewHub(nil)
	defer h.Shutdown(context.Background())
	org, doc, user := uuid.New(), uuid.New(), uuid.New()
	for i := 0; i < MaxUserPeers; i++ {
		p := newFakePeer(fmt.Sprint(i))
		p.userID = user
		if _, err := h.Join(context.Background(), doc, org, p); err != nil {
			t.Fatal(err)
		}
	}
	p := newFakePeer("overflow")
	p.userID = user
	if _, err := h.Join(context.Background(), uuid.New(), org, p); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow=%v", err)
	}
	if len(h.rooms) != 1 {
		t.Fatal("rejected join allocated room")
	}
	h.Leave(context.Background(), doc, "0")
	if _, err := h.Join(context.Background(), doc, org, p); err != nil {
		t.Fatalf("released capacity: %v", err)
	}
}

func TestCollabRoomPeerCapacity(t *testing.T) {
	h := NewHub(nil)
	defer h.Shutdown(context.Background())
	org, doc := uuid.New(), uuid.New()
	for i := 0; i < MaxRoomPeers; i++ {
		if _, err := h.Join(context.Background(), doc, org, newFakePeer(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Join(context.Background(), doc, org, newFakePeer("overflow")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow=%v", err)
	}
}

func TestCollabOrgRoomCapacityPreservesOtherTenant(t *testing.T) {
	h := NewHub(nil)
	defer h.Shutdown(context.Background())
	org := uuid.New()
	for i := 0; i < MaxOrgRooms; i++ {
		if _, err := h.Join(context.Background(), uuid.New(), org, newFakePeer(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Join(context.Background(), uuid.New(), org, newFakePeer("overflow")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow=%v", err)
	}
	if len(h.rooms) != MaxOrgRooms {
		t.Fatal("rejected join allocated room")
	}
	if _, err := h.Join(context.Background(), uuid.New(), uuid.New(), newFakePeer("other tenant")); err != nil {
		t.Fatalf("other tenant=%v", err)
	}
}

func TestCollabDuplicatePeerCannotReplaceConnection(t *testing.T) {
	h := NewHub(nil)
	defer h.Shutdown(context.Background())
	org, doc := uuid.New(), uuid.New()
	first := newFakePeer("same")
	result, err := h.Join(context.Background(), doc, org, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Join(context.Background(), doc, org, newFakePeer("same")); err == nil {
		t.Fatal("duplicate replaced peer")
	}
	if result.Room.peers["same"] != first {
		t.Fatal("original peer lost")
	}
}

func TestCollabGlobalRoomCapacity(t *testing.T) {
	h := NewHub(nil)
	defer h.Shutdown(context.Background())
	for i := 0; i < MaxActiveRooms; i++ {
		if _, err := h.Join(context.Background(), uuid.New(), uuid.New(), newFakePeer(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Join(context.Background(), uuid.New(), uuid.New(), newFakePeer("overflow")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow=%v", err)
	}
	if len(h.rooms) != MaxActiveRooms {
		t.Fatal("rejected join allocated room")
	}
}

func TestCollabOrgPeerCapacity(t *testing.T) {
	h := NewHub(nil)
	defer h.Shutdown(context.Background())
	org := uuid.New()
	docs := make([]uuid.UUID, MaxOrgPeers/MaxRoomPeers)
	for i := range docs {
		docs[i] = uuid.New()
	}
	for i := 0; i < MaxOrgPeers; i++ {
		if _, err := h.Join(context.Background(), docs[i/MaxRoomPeers], org, newFakePeer(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Join(context.Background(), uuid.New(), org, newFakePeer("overflow")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow=%v", err)
	}
	if len(h.rooms) != len(docs) {
		t.Fatal("rejected join allocated room")
	}
}

func TestCollabConcurrentUserAdmissionCannotExceedLimit(t *testing.T) {
	h := NewHub(nil)
	defer h.Shutdown(context.Background())
	org, doc, user := uuid.New(), uuid.New(), uuid.New()
	results := make(chan error, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := newFakePeer(fmt.Sprint(i))
			p.userID = user
			_, err := h.Join(context.Background(), doc, org, p)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrCapacity) {
			t.Fatalf("unexpected error=%v", err)
		}
	}
	if accepted != MaxUserPeers {
		t.Fatalf("accepted=%d", accepted)
	}
}
