// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"

	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
)

// WithStaffPreSignPDFV1 consumes only the immutable relation loaded by THIS
// actual work. The genuine SDK body, original model loans and HTTP consumer
// join before close can credit any retained resources. No caller pin is used.
func (w *ApplicationHTMLSendWorkV1) WithStaffPreSignPDFV1(call context.Context, client *storage.Client, consume func([]byte) error) error {
	if w == nil || w.self != w || client == nil || consume == nil {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if w.closed || w.resourcesClosed || w.stage == nil || w.stage.purpose != HTMLPreSignReadV1 || w.presignRetained == nil || !preSignKnownCommitV1(w.session) || call.Err() != nil {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	r := *w.presignRetained
	if r.Publication().State != "published" && r.Publication().State != "expired" {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	pin := r.Execution().Snapshot().VisiblePDF.Artifact
	org := w.session.state.org
	factory := w.stage.operation.factory.state
	factory.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !factory.closing && factory.work != nil {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if coordinator == nil {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	w.sourceBorrowers++
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.sourceBorrowers--
		closes, actor := w.retireSourcesLockedV1()
		w.mu.Unlock()
		htmlSendCloseSourceResourcesV1(closes, actor)
	}()
	digest, err := hex.DecodeString(pin.SHA256)
	if err != nil || len(digest) != 32 {
		return ErrHTMLSendWorkV1
	}
	body, _, err := client.ReadPackagePDFLocalOwnedV1(call, pin.StorageKey, pin.VersionID, digest, pin.Bytes, coordinator, org)
	if body != nil {
		defer body.CloseConsumerV1()
	}
	if err != nil {
		return err
	}
	if body == nil {
		return ErrHTMLSendWorkV1
	}
	return body.WithPDFV1(consume)
}
