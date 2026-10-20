// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package audit

import (
	"context"
	"github.com/google/uuid"
	"sync"
	"testing"
	"time"
)

func TestPublishDetachesActualAsyncIdentityStorageV1(t *testing.T) {
	type sourceModel struct {
		ID   uuid.UUID
		Body []byte
	}
	doc, recipient, actor := sourceModel{ID: uuid.New(), Body: make([]byte, 8192)}, sourceModel{ID: uuid.New(), Body: make([]byte, 8192)}, sourceModel{ID: uuid.New(), Body: make([]byte, 8192)}
	wantDoc, wantRecipient, wantActor := doc.ID, recipient.ID, actor.ID
	eventID := uuid.New()
	org := uuid.New()
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(finish)
	type observed struct {
		id    uuid.UUID
		entry Entry
	}
	done := make(chan observed, 1)
	logger := &Logger{}
	logger.Subscribe(func(_ context.Context, id uuid.UUID, e Entry) { close(started); <-release; done <- observed{id, e} })
	payload := map[string]any{"stable": "actual event payload"}
	logger.Publish(PendingEvent{ID: eventID, Entry: Entry{OrgID: org, DocumentID: &doc.ID, RecipientID: &recipient.ID, ActorUserID: &actor.ID, Kind: KindDocumentFieldFill, Payload: payload}})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("actual asynchronous hook did not start")
	}
	// This happens after Publish returns and before the hook reads its values.
	// The original model storage may now be reused/disposed by its own consumer.
	doc.ID, recipient.ID, actor.ID = uuid.New(), uuid.New(), uuid.New()
	finish()
	var got observed
	select {
	case got = <-done:
	case <-time.After(time.Second):
		t.Fatal("actual hook did not join")
	}
	if got.id != eventID || got.entry.OrgID != org || got.entry.DocumentID == nil || *got.entry.DocumentID != wantDoc || got.entry.RecipientID == nil || *got.entry.RecipientID != wantRecipient || got.entry.ActorUserID == nil || *got.entry.ActorUserID != wantActor {
		t.Fatal("async event adopted reused original identity storage")
	}
	if got.entry.DocumentID == &doc.ID || got.entry.RecipientID == &recipient.ID || got.entry.ActorUserID == &actor.ID {
		t.Fatal("async hook retained full original model through interior identity pointer")
	}
	if got.entry.Kind != KindDocumentFieldFill || got.entry.Payload["stable"] != "actual event payload" {
		t.Fatal("detaching scalar ownership changed legal event payload")
	}
}
func TestPublishPreservesAbsentOptionalIdentityV1(t *testing.T) {
	done := make(chan Entry, 1)
	logger := &Logger{}
	logger.Subscribe(func(_ context.Context, _ uuid.UUID, e Entry) { done <- e })
	logger.Publish(PendingEvent{ID: uuid.New(), Entry: Entry{OrgID: uuid.New(), Kind: KindDocumentFieldFill}})
	select {
	case e := <-done:
		if e.DocumentID != nil || e.RecipientID != nil || e.ActorUserID != nil {
			t.Fatal("detachment fabricated absent identity")
		}
	case <-time.After(time.Second):
		t.Fatal("hook did not join")
	}
}
