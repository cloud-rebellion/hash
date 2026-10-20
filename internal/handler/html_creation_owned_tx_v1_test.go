// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestHTMLCreationPolicyTxV1RefusesTransactionControls(t *testing.T) {
	tx := &htmlCreationPolicyTxV1{}
	ctx := context.Background()
	if _, err := tx.Begin(ctx); !errors.Is(err, errHTMLCreationPolicyControlV1) {
		t.Fatal("nested transaction exposed")
	}
	if err := tx.Commit(ctx); !errors.Is(err, errHTMLCreationPolicyControlV1) {
		t.Fatal("commit exposed")
	}
	if err := tx.Rollback(ctx); !errors.Is(err, errHTMLCreationPolicyControlV1) {
		t.Fatal("rollback exposed")
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"documents"}, nil, nil); !errors.Is(err, errHTMLCreationPolicyControlV1) {
		t.Fatal("copy transport exposed")
	}
	if _, err := tx.Prepare(ctx, "x", "SELECT 1"); !errors.Is(err, errHTMLCreationPolicyControlV1) {
		t.Fatal("raw prepare exposed")
	}
	if tx.Conn() != nil {
		t.Fatal("raw connection exposed")
	}
	b := tx.SendBatch(ctx, &pgx.Batch{})
	if _, err := b.Exec(); !errors.Is(err, errHTMLCreationPolicyControlV1) {
		t.Fatal("batch Exec exposed")
	}
	if _, err := b.Query(); !errors.Is(err, errHTMLCreationPolicyControlV1) {
		t.Fatal("batch Query exposed")
	}
	if err := b.QueryRow().Scan(); !errors.Is(err, errHTMLCreationPolicyControlV1) {
		t.Fatal("batch row exposed")
	}
	if err := b.Close(); !errors.Is(err, errHTMLCreationPolicyControlV1) {
		t.Fatal("batch completion exposed")
	}
}

func TestHTMLCreationEventIDsDetachParentBufferAliasesV1(t *testing.T) {
	parent := struct {
		document, recipient, actor uuid.UUID
		source                     []byte
	}{uuid.New(), uuid.New(), uuid.New(), []byte("retained large HTML producer")}
	original := audit.PendingEvent{ID: uuid.New(), Entry: audit.Entry{
		DocumentID: &parent.document, RecipientID: &parent.recipient, ActorUserID: &parent.actor,
		Kind: "document.created", Payload: map[string]any{"unchanged": "approved source commitment"},
	}}
	copied := detachHTMLCreationEventIDsV1(original)
	if copied.ID != original.ID || copied.Entry.Kind != original.Entry.Kind ||
		copied.Entry.DocumentID == original.Entry.DocumentID || copied.Entry.RecipientID == original.Entry.RecipientID || copied.Entry.ActorUserID == original.Entry.ActorUserID {
		t.Fatal("event identity changed or retained parent interior pointer")
	}
	doc, rec, actor := parent.document, parent.recipient, parent.actor
	if *copied.Entry.DocumentID != doc || *copied.Entry.RecipientID != rec || *copied.Entry.ActorUserID != actor {
		t.Fatal("UUID values changed")
	}
	parent.document, parent.recipient, parent.actor = uuid.New(), uuid.New(), uuid.New()
	if *copied.Entry.DocumentID != doc || *copied.Entry.RecipientID != rec || *copied.Entry.ActorUserID != actor {
		t.Fatal("captured IDs still alias mutable parent")
	}
	original.Entry.Payload["unchanged"] = "same existing payload object"
	if copied.Entry.Payload["unchanged"] != "same existing payload object" {
		t.Fatal("legal payload object was replaced")
	}
	absent := detachHTMLCreationEventIDsV1(audit.PendingEvent{})
	if absent.Entry.DocumentID != nil || absent.Entry.RecipientID != nil || absent.Entry.ActorUserID != nil {
		t.Fatal("absent identity invented")
	}
}
