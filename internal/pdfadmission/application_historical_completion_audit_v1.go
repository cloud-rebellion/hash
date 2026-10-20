// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"github.com/google/uuid"
	"strings"
	"time"
	"unsafe"
)

type historicalCompletionPayloadV1 struct {
	document uuid.UUID
	payload  map[string]any
	owner    *ApplicationHTMLAuditEventConsumerV1
}

// This exact payload is constructed only for the actual fresh terminal root
// and returned completed children. Native original source/intent sizes fund
// maps, hex encoding and detached pending/hook control before allocation.
func (w *ApplicationHTMLSendWorkV1) HistoricalCompletionPayloadV1(call context.Context, document uuid.UUID) (map[string]any, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return nil, err
	}
	if document == uuid.Nil || p.deleted {
		return nil, ErrHTMLSendWorkV1
	}
	found := document == p.completed.ID
	for _, child := range p.children {
		if child != nil && child.ID == document {
			found = true
		}
	}
	if !found {
		return nil, ErrHTMLSendWorkV1
	}
	for _, event := range p.payloads {
		if event.document == document {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if p.payloads == nil {
		n := int64(len(p.children) + 1)
		intentRaw, e := historicalFinalizationIntentRawV1(state.intent)
		if e != nil {
			return nil, e
		}
		raw := int64(0)
		if !htmlInputAddV1(&raw, n, 2*int64(unsafe.Sizeof(historicalCompletionPayloadV1{}))+4*int64(unsafe.Sizeof(map[string]any{}))+2*18*(int64(unsafe.Sizeof(""))+int64(unsafe.Sizeof(any(nil)))+2*int64(unsafe.Sizeof(uintptr(0))))+4*64+2*128) || !htmlInputAddV1(&raw, intentRaw, n) {
			return nil, ErrHTMLSendWorkV1
		}
		closePayloads, e := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
		if e != nil {
			return nil, e
		}
		w.closes = append(w.closes, closePayloads)
		p.payloads = make([]historicalCompletionPayloadV1, 0, len(p.children)+1)
	}
	i := state.intent
	if i == nil || !applicationStampV1(i.CompletionEffectiveAt) || !applicationStampV1(i.RetainUntil) || len(i.FinalPdfSha256) != 32 || len(i.AuditCertSha256) != 32 || len(i.AuditPayloadSha256) != 32 || len(i.AuditSignatureSha256) != 32 {
		return nil, ErrHTMLSendWorkV1
	}
	payload := map[string]any{"mode": i.Mode, "completion_effective_at_bound": true, "completion_effective_at": i.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano), "retain_until": i.RetainUntil.Time.UTC().Format(time.RFC3339), "final_pdf_key": i.FinalPdfKey, "final_pdf_sha256": hex.EncodeToString(i.FinalPdfSha256), "final_pdf_version_id": i.FinalPdfVersionID.String, "audit_cert_key": i.AuditCertKey, "audit_cert_sha256": hex.EncodeToString(i.AuditCertSha256), "audit_cert_version_id": i.AuditCertVersionID.String, "audit_payload_key": i.AuditPayloadKey, "audit_payload_sha256": hex.EncodeToString(i.AuditPayloadSha256), "audit_payload_version_id": i.AuditPayloadVersionID.String, "audit_signature_key": i.AuditSignatureKey, "audit_signature_sha256": hex.EncodeToString(i.AuditSignatureSha256), "audit_signature_version_id": i.AuditSignatureVersionID.String}
	if document != p.completed.ID {
		payload["envelope_id"] = p.completed.ID.String()
		payload["propagated"] = true
	}
	private := make(map[string]any, len(payload))
	for key, value := range payload {
		if text, ok := value.(string); ok {
			private[key] = strings.Clone(text)
		} else {
			private[key] = value
		}
	}
	p.payloads = append(p.payloads, historicalCompletionPayloadV1{document: document, payload: private})
	return payload, nil
}

// A UUID, payload or application boolean is never an audit receipt. The exact
// real native consumer must have appended and intrinsically measured THIS
// event in THIS session before the durable completion intent can be deleted.
func (w *ApplicationHTMLSendWorkV1) BindHistoricalCompletionAuditV1(call context.Context, document uuid.UUID, owner *ApplicationHTMLAuditEventConsumerV1) error {
	if w == nil || w.self != w || owner == nil || owner.self != owner {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.session != w.session || owner.org != p.completed.OrgID || owner.document != document || owner.purpose != HTMLAuditHistoricalCompletedV1 || owner.recipient.Valid || owner.actor.Valid || owner.kind != "document.completed" || owner.ip != "" || owner.ua != "" || owner.closed || !owner.used || !owner.attempted || owner.eventID == uuid.Nil {
		return ErrHTMLSendWorkV1
	}
	for index := range p.payloads {
		event := &p.payloads[index]
		if event.document == document {
			if event.owner != nil || !historicalCompletionPayloadEqualV1(event.payload, owner.payload) {
				return ErrHTMLSendWorkV1
			}
			event.owner = owner
			return nil
		}
	}
	return ErrHTMLSendWorkV1
}
func historicalCompletionPayloadEqualV1(expected, actual map[string]any) bool {
	if len(expected) != len(actual) {
		return false
	}
	for key, value := range expected {
		other, ok := actual[key]
		if !ok {
			return false
		}
		switch v := value.(type) {
		case string:
			text, ok := other.(string)
			if !ok || v != text {
				return false
			}
		case bool:
			flag, ok := other.(bool)
			if !ok || v != flag {
				return false
			}
		default:
			return false
		}
	}
	return true
}
