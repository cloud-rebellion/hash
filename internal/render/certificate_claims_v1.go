// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"sort"
	"strings"
	"time"
)

type CertificateEvidenceClaimsV1 struct {
	ParticipantReportSchema    string
	ParticipantReportSHA256    string
	ParticipantReportCutoff    string
	ParticipantReportRows      int64
	ParticipantReportHTML      string
	DocumentID                 string
	OrgID                      string
	DocumentNameSHA256         string
	FinalPDFSHA256             string
	CompletionEffectiveAt      string
	PreFinalChainHeadSHA256    string
	PreFinalChainHeadCreatedAt string
	PreFinalChainScope         string
	DocumentEventsSHA256       string
	DocumentEventsCount        int
	DocumentEventsScope        string
	FitsIndexSchema            string
	FitsIndexSHA256            string
	FitsIndexObjectSHA256      string
	EvidenceRetainUntil        string
}

const MaxCertificateDocumentEventsV1 = 10000
const (
	preFinalChainScopeOrganization  = "organization"
	documentEventsScopeCeremonyRoot = "ceremony-root"
)

func certificateCanonicalCompletionEffectiveAtV1(value pgtype.Timestamptz) (string, error) {
	if !value.Valid || value.Time.IsZero() {
		return "", errors.New("completion-effective timestamp is unavailable")
	}
	return value.Time.UTC().Format(time.RFC3339Nano), nil
}
func certificateEscapeV1(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(value)
}
func NewCertificateEvidenceClaimsV1(doc *generated.Document, finalPDFSHA []byte, head *generated.LatestEventChainHeadForOrgRow, events []*generated.Event) (CertificateEvidenceClaimsV1, error) {
	if doc == nil || doc.ID == [16]byte{} || doc.OrgID == [16]byte{} || doc.Name == "" {
		return CertificateEvidenceClaimsV1{}, errors.New("audit certificate: document identity unavailable")
	}
	if len(finalPDFSHA) != 32 {
		return CertificateEvidenceClaimsV1{}, errors.New("audit certificate: final PDF digest must be 32 bytes")
	}
	if !doc.CompletionEffectiveAtBound {
		return CertificateEvidenceClaimsV1{}, errors.New("audit certificate: completion-effective timestamp is not bound for this ceremony")
	}
	completionEffectiveAt, err := certificateCanonicalCompletionEffectiveAtV1(doc.CompletionEffectiveAt)
	if err != nil {
		return CertificateEvidenceClaimsV1{}, fmt.Errorf("audit certificate: %w", err)
	}
	if head == nil || len(head.RowHash) != 32 || !head.CreatedAt.Valid || head.CreatedAt.Time.IsZero() {
		return CertificateEvidenceClaimsV1{}, errors.New("audit certificate: pre-final audit chain head unavailable")
	}
	for i, event := range events {
		if event == nil || event.OrgID != doc.OrgID || !event.DocumentID.Valid || event.DocumentID.Bytes != doc.ID {
			return CertificateEvidenceClaimsV1{}, fmt.Errorf("audit certificate: pre-final event %d does not belong to the document", i)
		}
	}
	eventsSHA, eventsCount, err := CertificateDocumentEventsCommitmentV1(events)
	if err != nil {
		return CertificateEvidenceClaimsV1{}, err
	}
	return CertificateEvidenceClaimsV1{
		DocumentID:                 doc.ID.String(),
		OrgID:                      doc.OrgID.String(),
		DocumentNameSHA256:         fmt.Sprintf("%x", sha256.Sum256([]byte(doc.Name))),
		FinalPDFSHA256:             hex.EncodeToString(finalPDFSHA),
		CompletionEffectiveAt:      completionEffectiveAt,
		PreFinalChainHeadSHA256:    hex.EncodeToString(head.RowHash),
		PreFinalChainHeadCreatedAt: head.CreatedAt.Time.UTC().Format(time.RFC3339Nano),
		PreFinalChainScope:         preFinalChainScopeOrganization,
		DocumentEventsSHA256:       eventsSHA,
		DocumentEventsCount:        eventsCount,
		DocumentEventsScope:        documentEventsScopeCeremonyRoot,
	}, nil
}

// CertificateDocumentEventsCommitmentV1 binds the exact pre-final document-event set while
// avoiding a false claim that a document-only export is a contiguous proof of
// the interleaved org chain. Ordering is chronological by created_at then UUID.
func CertificateDocumentEventsCommitmentV1(events []*generated.Event) (string, int, error) {
	if len(events) == 0 {
		return "", 0, errors.New("audit certificate: document has no pre-final events")
	}
	if len(events) > MaxCertificateDocumentEventsV1 {
		return "", 0, fmt.Errorf("audit certificate: document has more than %d pre-final events", MaxCertificateDocumentEventsV1)
	}
	ordered := append([]*generated.Event(nil), events...)
	for i, event := range ordered {
		if event == nil || event.ID == [16]byte{} || len(event.RowHash) != 32 || !event.CreatedAt.Valid || event.CreatedAt.Time.IsZero() {
			return "", 0, fmt.Errorf("audit certificate: invalid pre-final event at index %d", i)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if !a.CreatedAt.Time.Equal(b.CreatedAt.Time) {
			return a.CreatedAt.Time.Before(b.CreatedAt.Time)
		}
		return bytes.Compare(a.ID[:], b.ID[:]) < 0
	})
	for _, event := range ordered {
		recomputed, err := audit.RecomputeEventRowHash(event)
		if err != nil {
			return "", 0, fmt.Errorf("audit certificate: recompute pre-final event %s: %w", event.ID, err)
		}
		if subtle.ConstantTimeCompare(recomputed, event.RowHash) != 1 {
			return "", 0, fmt.Errorf("audit certificate: pre-final event %s row hash is invalid", event.ID)
		}
	}
	digest, err := audit.DocumentEventSetDigest(ordered)
	if err != nil {
		return "", 0, fmt.Errorf("audit certificate: document-event set: %w", err)
	}
	return hex.EncodeToString(digest[:]), len(ordered), nil
}

// HTML uses stable data attributes so offline verifiers can extract the
// commitments from the signed payload without scraping human prose.
func (c CertificateEvidenceClaimsV1) HTML() string {
	// Keep historical certificate payload bytes identical when the fitted
	// index is absent. New certificates add one inseparable index commitment.
	fittedAttributes := ""
	if c.ParticipantReportSchema != "" {
		fittedAttributes = fmt.Sprintf(` data-hash-participant-report-schema="%s" data-hash-participant-report-sha256="%s" data-hash-participant-report-cutoff="%s" data-hash-participant-report-rows="%d"`, certificateEscapeV1(c.ParticipantReportSchema), certificateEscapeV1(c.ParticipantReportSHA256), certificateEscapeV1(c.ParticipantReportCutoff), c.ParticipantReportRows)
	}
	if c.FitsIndexSchema != "" || c.FitsIndexSHA256 != "" || c.FitsIndexObjectSHA256 != "" || c.EvidenceRetainUntil != "" {
		fittedAttributes += fmt.Sprintf(` data-hash-fits-index-schema="%s" data-hash-fits-index-sha256="%s" data-hash-fits-index-object-sha256="%s" data-hash-evidence-retain-until="%s"`,
			certificateEscapeV1(c.FitsIndexSchema), certificateEscapeV1(c.FitsIndexSHA256), certificateEscapeV1(c.FitsIndexObjectSHA256), certificateEscapeV1(c.EvidenceRetainUntil))
	}
	return fmt.Sprintf(`<section class="hash-evidence-claims" data-hash-document-id="%s" data-hash-org-id="%s" data-hash-document-name-sha256="%s" data-hash-final-pdf-sha256="%s" data-hash-completion-effective-at="%s" data-hash-pre-final-chain-head-sha256="%s" data-hash-pre-final-chain-head-created-at="%s" data-hash-pre-final-chain-scope="%s" data-hash-document-events-sha256="%s" data-hash-document-events-count="%d" data-hash-document-events-scope="%s"%s><h3>Cryptographic commitments</h3><p><strong>Document ID:</strong> <code>%s</code></p><p><strong>Organization ID:</strong> <code>%s</code></p><p><strong>Document name SHA-256:</strong> <code>%s</code></p><p><strong>Final PDF SHA-256:</strong> <code>%s</code></p><p><strong>Completion effective at:</strong> %s</p><p><strong>Pre-final organization audit-chain head SHA-256:</strong> <code>%s</code></p><p><strong>Pre-final audit-chain head timestamp:</strong> %s</p><p><strong>Ceremony-root document-event set SHA-256:</strong> <code>%s</code> (%d events)</p><p>The event-set attachment is scoped to this ceremony root. For an envelope, child content and identity are bound by the signed envelope manifest; child lifecycle rows remain in the organization audit chain committed by the pre-final head.</p></section>`,
		certificateEscapeV1(c.DocumentID),
		certificateEscapeV1(c.OrgID),
		certificateEscapeV1(c.DocumentNameSHA256),
		certificateEscapeV1(c.FinalPDFSHA256),
		certificateEscapeV1(c.CompletionEffectiveAt),
		certificateEscapeV1(c.PreFinalChainHeadSHA256),
		certificateEscapeV1(c.PreFinalChainHeadCreatedAt),
		certificateEscapeV1(c.PreFinalChainScope),
		certificateEscapeV1(c.DocumentEventsSHA256),
		c.DocumentEventsCount,
		certificateEscapeV1(c.DocumentEventsScope),
		fittedAttributes,
		certificateEscapeV1(c.DocumentID),
		certificateEscapeV1(c.OrgID),
		certificateEscapeV1(c.DocumentNameSHA256),
		certificateEscapeV1(c.FinalPDFSHA256),
		certificateEscapeV1(c.CompletionEffectiveAt),
		certificateEscapeV1(c.PreFinalChainHeadSHA256),
		certificateEscapeV1(c.PreFinalChainHeadCreatedAt),
		certificateEscapeV1(c.DocumentEventsSHA256),
		c.DocumentEventsCount,
	)
}
