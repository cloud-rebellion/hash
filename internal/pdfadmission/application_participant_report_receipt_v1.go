// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Persist requires the actual retained certificate producer, never caller
// claims, hashes, report JSON or a successful callback boolean. Its original
// WithStored borrower remains live through Stage's acknowledged SQL COMMIT.
func (w *ApplicationHTMLSendWorkV1) PersistHistoricalParticipantReportV1(call context.Context, c *ApplicationHistoricalAuditCertificateV1) error {
	if w == nil || w.self != w || c == nil || c.self != c || !c.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer c.unlockV1()
	if c.closeRequested.Load() || c.grant == nil || !c.stored || c.metadataBorrowers == 0 || c.report.cutoff.Time.IsZero() {
		return ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		return err
	}
	if w.stage.purpose != HTMLHistoricalFinalizationStageV1 || s.intent == nil || c.factory != w.stage.operation.factory || c.org != w.session.state.org || c.document != w.logicalDocumentV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	i := s.intent
	if i.AuditCertKey != c.keys[0] || i.AuditPayloadKey != c.keys[1] || i.AuditSignatureKey != c.keys[2] || i.AuditCertVersionID.String != c.versions[0] || i.AuditPayloadVersionID.String != c.versions[1] || i.AuditSignatureVersionID.String != c.versions[2] || !bytes.Equal(i.AuditCertSha256, c.sums[0][:]) || !bytes.Equal(i.AuditPayloadSha256, c.sums[1][:]) || !bytes.Equal(i.AuditSignatureSha256, c.sums[2][:]) || !bytes.Equal(i.FinalPdfSha256, c.finalPDFSHA[:]) {
		return ErrHistoricalFinalizationSourceV1
	}
	raw := int64(16384) + 8*int64(unsafe.Sizeof(generated.InsertParticipantReportReceiptV1Params{})) + 8*int64(unsafe.Sizeof(generated.ParticipantReportReceiptMatchesV1Params{}))
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeBody)
	p := generated.InsertParticipantReportReceiptV1Params{ReportSchema: c.report.schema, DocumentID: i.DocumentID, OrgID: i.OrgID, CompletionEffectiveAt: i.CompletionEffectiveAt, Cutoff: c.report.cutoff, HistoryRows: c.report.rows, ReportSha256: bytes.Clone(c.report.sha[:]), FinalPdfSha256: bytes.Clone(c.finalPDFSHA[:]), AuditCertSha256: bytes.Clone(c.sums[0][:]), AuditPayloadSha256: bytes.Clone(c.sums[1][:]), AuditSignatureSha256: bytes.Clone(c.sums[2][:])}
	n, err := w.queries.InsertParticipantReportReceiptV1(call, p)
	if err != nil {
		return err
	}
	if n < 0 || n > 1 {
		return ErrHistoricalFinalizationSourceV1
	}
	ok, err := w.queries.ParticipantReportReceiptMatchesV1(call, generated.ParticipantReportReceiptMatchesV1Params{ReportSchema: p.ReportSchema, DocumentID: p.DocumentID, OrgID: p.OrgID, CompletionEffectiveAt: p.CompletionEffectiveAt, Cutoff: p.Cutoff, HistoryRows: p.HistoryRows, ReportSha256: p.ReportSha256, FinalPdfSha256: p.FinalPdfSha256, AuditCertSha256: p.AuditCertSha256, AuditPayloadSha256: p.AuditPayloadSha256, AuditSignatureSha256: p.AuditSignatureSha256})
	if err != nil {
		return err
	}
	if !ok {
		return ErrHistoricalFinalizationSourceV1
	}
	return nil
}

func participantReportFinalPDFSHAFromV1(value string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != sha256.Size {
		return sum, ErrHistoricalFinalizationSourceV1
	}
	copy(sum[:], raw)
	return sum, nil
}
