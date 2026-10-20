// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"time"
)

type certificateEvidenceClaims render.CertificateEvidenceClaimsV1

const maxCertificateDocumentEvents = render.MaxCertificateDocumentEventsV1
const (
	preFinalChainScopeOrganization  = "organization"
	documentEventsScopeCeremonyRoot = "ceremony-root"
)

// bindFitsIndexV1 is used only after the final/index output journal has exact
// positive versions. A content digest alone cannot replace an opaque object
// identity, and a different document/completion/final PDF cannot borrow a seal.
func (c certificateEvidenceClaims) bindFitsIndexV1(doc *generated.Document, signer *CertSigner, index *manualfit.SignedFitsIndexV1, pin manualfit.ObjectPinV1, operationID uuid.UUID) (certificateEvidenceClaims, error) {
	if doc == nil || doc.Status != "finalizing" || !doc.CompletionEffectiveAtBound || !doc.SentAt.Valid ||
		!doc.CompletionEffectiveAt.Valid || !doc.FinalizationRetainUntil.Valid || signer == nil || index == nil || operationID == uuid.Nil {
		return certificateEvidenceClaims{}, manualfit.ErrFitsIndexV1
	}
	frozen := index.Index()
	if frozen == nil || !bytes.Equal(index.PublicKey(), signer.pub) {
		return certificateEvidenceClaims{}, manualfit.ErrFitsIndexV1
	}
	binding := frozen.Binding()
	if binding.DocumentID.String() != c.DocumentID || binding.OrgID.String() != c.OrgID ||
		binding.DocumentID != doc.ID || binding.OrgID != doc.OrgID || !binding.CeremonyEpoch.Equal(doc.SentAt.Time) ||
		!binding.CompletionEffectiveAt.Equal(doc.CompletionEffectiveAt.Time) || !binding.RetainUntil.Equal(doc.FinalizationRetainUntil.Time) ||
		binding.FinalPDF.SHA256 != c.FinalPDFSHA256 || binding.CompletionEffectiveAt.UTC().Format(time.RFC3339Nano) != c.CompletionEffectiveAt ||
		fmt.Sprintf("%x", sha256.Sum256([]byte(frozen.OriginalDocumentName()))) != c.DocumentNameSHA256 ||
		pin.Key != manualfit.IndexStorageKeyV1(binding.OrgID, binding.DocumentID, operationID) ||
		pin.SHA256 != index.SHA256() || pin.Bytes != int64(len(index.Bytes())) {
		return certificateEvidenceClaims{}, manualfit.ErrFitsIndexV1
	}
	objectSHA256, err := manualfit.ObjectPinSHA256V1(pin)
	if err != nil {
		return certificateEvidenceClaims{}, err
	}
	c.FitsIndexSchema = manualfit.FitsIndexSchemaV1
	c.FitsIndexSHA256 = pin.SHA256
	c.FitsIndexObjectSHA256 = objectSHA256
	c.EvidenceRetainUntil = binding.RetainUntil.UTC().Format(time.RFC3339)
	return c, nil
}

func newCertificateEvidenceClaims(doc *generated.Document, finalPDFSHA []byte, head *generated.LatestEventChainHeadForOrgRow, events []*generated.Event) (certificateEvidenceClaims, error) {
	claims, err := render.NewCertificateEvidenceClaimsV1(doc, finalPDFSHA, head, events)
	return certificateEvidenceClaims(claims), err
}
func documentEventsCommitment(events []*generated.Event) (string, int, error) {
	return render.CertificateDocumentEventsCommitmentV1(events)
}
func (c certificateEvidenceClaims) HTML() string { return render.CertificateEvidenceClaimsV1(c).HTML() }
