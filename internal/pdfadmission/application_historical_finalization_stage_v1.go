// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"path"
	"strings"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

func historicalFinalizationIntentParamsRawV1(p generated.CreateDocumentFinalizationIntentParams) (int64, error) {
	return htmlAuthoringSumV1(int64(len(p.Mode)), int64(len(p.FinalPdfKey)), int64(len(p.FinalPdfSha256)), int64(len(p.FinalPdfVersionID.String)), int64(len(p.AuditCertKey)), int64(len(p.AuditCertSha256)), int64(len(p.AuditCertVersionID.String)), int64(len(p.AuditPayloadKey)), int64(len(p.AuditPayloadSha256)), int64(len(p.AuditPayloadVersionID.String)), int64(len(p.AuditSignatureKey)), int64(len(p.AuditSignatureSha256)), int64(len(p.AuditSignatureVersionID.String)))
}
func historicalFinalizationTimestampEqualV1(a, b pgtype.Timestamptz) bool {
	return a.Valid && b.Valid && !a.Time.IsZero() && !b.Time.IsZero() && a.Time.Equal(b.Time)
}
func historicalFinalizationIntentMatchesV1(i *generated.DocumentFinalizationIntent, p generated.CreateDocumentFinalizationIntentParams) bool {
	return i != nil && i.DocumentID == p.DocumentID && i.OrgID == p.OrgID && i.Mode == p.Mode && historicalFinalizationTimestampEqualV1(i.CompletionEffectiveAt, p.CompletionEffectiveAt) && historicalFinalizationTimestampEqualV1(i.RetainUntil, p.RetainUntil) && i.FinalPdfKey == p.FinalPdfKey && subtle.ConstantTimeCompare(i.FinalPdfSha256, p.FinalPdfSha256) == 1 && i.FinalPdfVersionID == p.FinalPdfVersionID && i.AuditCertKey == p.AuditCertKey && subtle.ConstantTimeCompare(i.AuditCertSha256, p.AuditCertSha256) == 1 && i.AuditCertVersionID == p.AuditCertVersionID && i.AuditPayloadKey == p.AuditPayloadKey && subtle.ConstantTimeCompare(i.AuditPayloadSha256, p.AuditPayloadSha256) == 1 && i.AuditPayloadVersionID == p.AuditPayloadVersionID && i.AuditSignatureKey == p.AuditSignatureKey && subtle.ConstantTimeCompare(i.AuditSignatureSha256, p.AuditSignatureSha256) == 1 && i.AuditSignatureVersionID == p.AuditSignatureVersionID && i.EvidenceVersionPinsRequired
}
func historicalFinalizationIntentArtifactV1(key, prefix, suffix string, digest []byte, version string, valid bool) bool {
	return strings.TrimSpace(key) != "" && len(digest) == sha256.Size && valid && strings.TrimSpace(version) != "" && path.Base(key) == prefix+hex.EncodeToString(digest)+suffix
}

// Create consumes only this fixed actual locked root and the privately observed
// absent intent. Caller keys/digests are values, never counts or source authority.
// Driver args, all RETURNING columns and retained private/exposed rows are funded
// before copying digests or dispatching the actual existing INSERT.
func (w *ApplicationHTMLSendWorkV1) CreateHistoricalFinalizationIntentV1(call context.Context, p generated.CreateDocumentFinalizationIntentParams) (*generated.DocumentFinalizationIntent, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		return nil, err
	}
	d := w.sourceDocument
	if w.stage.purpose != HTMLHistoricalFinalizationStageV1 || w.familyRoot != nil || s.stageAttempted || !s.intentRead || s.intent != nil || d.Status != "finalizing" || !d.CompletionEffectiveAtBound || !d.CompletionEffectiveAt.Valid || !d.FinalizationRetainUntil.Valid || p.DocumentID != d.ID || p.OrgID != d.OrgID || !historicalFinalizationTimestampEqualV1(p.CompletionEffectiveAt, d.CompletionEffectiveAt) || !historicalFinalizationTimestampEqualV1(p.RetainUntil, d.FinalizationRetainUntil) || (p.Mode != "signature" && p.Mode != "acknowledgement") || (p.Mode == "signature") != d.RequiresSignature {
		return nil, ErrHTMLSendWorkV1
	}
	s.stageAttempted = true
	if !historicalFinalizationIntentArtifactV1(p.FinalPdfKey, "final-", ".pdf", p.FinalPdfSha256, p.FinalPdfVersionID.String, p.FinalPdfVersionID.Valid) || !historicalFinalizationIntentArtifactV1(p.AuditCertKey, "audit-", ".pdf", p.AuditCertSha256, p.AuditCertVersionID.String, p.AuditCertVersionID.Valid) || !historicalFinalizationIntentArtifactV1(p.AuditPayloadKey, "audit-payload-", ".txt", p.AuditPayloadSha256, p.AuditPayloadVersionID.String, p.AuditPayloadVersionID.Valid) || !historicalFinalizationIntentArtifactV1(p.AuditSignatureKey, "audit-signature-", ".txt", p.AuditSignatureSha256, p.AuditSignatureVersionID.String, p.AuditSignatureVersionID.Valid) {
		return nil, ErrHTMLSendWorkV1
	}
	if p.FinalPdfKey == p.AuditCertKey || p.FinalPdfKey == p.AuditPayloadKey || p.FinalPdfKey == p.AuditSignatureKey || p.AuditCertKey == p.AuditPayloadKey || p.AuditCertKey == p.AuditSignatureKey || p.AuditPayloadKey == p.AuditSignatureKey {
		return nil, ErrHTMLSendWorkV1
	}
	raw, err := historicalFinalizationIntentParamsRawV1(p)
	if err != nil {
		return nil, err
	}
	wire := raw
	if !htmlInputAddV1(&raw, 1, 5*int64(unsafe.Sizeof(generated.DocumentFinalizationIntent{}))+3*int64(unsafe.Sizeof(generated.CreateDocumentFinalizationIntentParams{}))+4*int64(unsafe.Sizeof(uintptr(0)))) {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeBody)
	p.FinalPdfSha256 = bytes.Clone(p.FinalPdfSha256)
	p.AuditCertSha256 = bytes.Clone(p.AuditCertSha256)
	p.AuditPayloadSha256 = bytes.Clone(p.AuditPayloadSha256)
	p.AuditSignatureSha256 = bytes.Clone(p.AuditSignatureSha256)
	row, err := w.queries.CreateDocumentFinalizationIntent(call, p)
	if err != nil {
		return nil, err
	}
	// Existing schema defaults are fixed on a new historical four-artifact tuple;
	// scalable or fitted values cannot hide in a RETURNING column after admission.
	if !historicalFinalizationIntentMatchesV1(row, p) || row.RetentionStartedAt.Valid || row.RetentionCompletedAt.Valid || row.Attempts != 0 || row.LastError.Valid || row.FittedPreparationID.Valid || row.FitsIndexStorageKey.Valid || row.FitsIndexVersionID.Valid || len(row.FitsIndexSha256) != 0 || row.FitsIndexBytes.Valid {
		return nil, ErrHTMLSendWorkV1
	}
	s.intent = historicalFinalizationCloneIntentV1(row)
	s.intentView = row
	return row, nil
}
