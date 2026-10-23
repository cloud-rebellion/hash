// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

var ErrDelegatedFittedUnsupportedV1 = errors.Join(ErrSigningAdmissionUnavailableV1, errors.New("delegated documents do not support fitted signature requests"))

// PreSignContextV1 is public disclosure of an already committed execution.
// Neither this projection nor a valid digest grants new delegated authority.
// Private object locators, versions and executor credentials are never exposed.
type PreSignContextV1 struct {
	SchemaVersion     int       `json:"schema_version"`
	DocumentID        uuid.UUID `json:"document_id"`
	ExecutionID       uuid.UUID `json:"execution_id"`
	ExecutionSHA256   string    `json:"execution_sha256"`
	VisiblePDFSHA256  string    `json:"visible_pdf_sha256"`
	DisclosureVersion int64     `json:"disclosure_version"`
	DisclosureSHA256  string    `json:"disclosure_sha256"`
	DisclosureText    string    `json:"disclosure_text"`
	ProviderName      string    `json:"provider_name"`
	ExecutedAt        string    `json:"executed_at"`
}

type delegatedSignerEvidenceV1 struct {
	public                          PreSignContextV1
	visible                         presign.ArtifactPin
	assetsSHA256                    string
	customer                        uuid.UUID
	epoch, publishedAt, retainUntil time.Time
}

func cloneDelegatedSignerEvidenceV1(v *delegatedSignerEvidenceV1) *delegatedSignerEvidenceV1 {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}
func sameDelegatedSignerEvidenceV1(a, b *delegatedSignerEvidenceV1) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func bindDelegatedSignerEvidenceV1(rc *RecipientContext, retained *presignexecute.RetainedAssetsV1) error {
	if rc == nil || rc.Document == nil || rc.Recipient == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	if retained == nil {
		rc.delegated = nil
		return nil
	}
	e := retained.Execution().Snapshot()
	g := retained.Grant().Snapshot()
	a := retained.Assets().Snapshot()
	p := retained.Publication()
	d, r := rc.Document, rc.Recipient
	copy := presignregistry.Disclosure()
	commitment, err := htmlsource.Commitment(d)
	if err != nil || d.ID != e.Document.ID || d.OrgID != e.OrgID || d.SenderID != e.Document.SenderID ||
		d.SourceKind != "pdf" || !d.RequiresSignature || d.IsEnvelope || d.ParentEnvelopeID.Valid ||
		!d.PdfStorageKey.Valid || d.PdfStorageKey.String != e.Document.BasePDF.Artifact.StorageKey ||
		!d.PdfStorageVersionID.Valid || d.PdfStorageVersionID.String != e.Document.BasePDF.Artifact.VersionID ||
		len(d.PdfSha256) != 32 || hex.EncodeToString(d.PdfSha256) != e.Document.BasePDF.Artifact.SHA256 ||
		commitment != e.Document.Materialization.SourceCommitment ||
		!d.HtmlCurrentMaterializationID.Valid || uuid.UUID(d.HtmlCurrentMaterializationID.Bytes) != e.Document.Materialization.ID ||
		!d.HtmlCurrentMaterializationSequence.Valid || int64(d.HtmlCurrentMaterializationSequence.Int32) != e.Document.Materialization.Revision ||
		!d.HtmlCurrentPageCount.Valid || int(d.HtmlCurrentPageCount.Int32) != e.VisiblePDF.Pages ||
		!d.Article13NoticeEpochAt.Valid || !d.Article13NoticeEpochAt.Time.Equal(e.CeremonyEpoch) ||
		r.ID != e.Document.Parties[0].ID || r.ID != p.CustomerRecipientID || r.Role != e.Document.Parties[0].Role ||
		p.State != "published" || p.PublishedAt.IsZero() || p.RetentionStartedAt.IsZero() || p.RetentionCompletedAt.IsZero() ||
		p.RetentionCompletedAt.Before(p.RetentionStartedAt) || p.PublishedAt.Before(p.RetentionCompletedAt) ||
		!p.RetainUntil.After(p.PublishedAt) || !time.Now().Before(p.RetainUntil) ||
		g.Disclosure.Version != copy.Version || g.Disclosure.SHA256 != copy.SHA256 ||
		a.Objects[7].Object != e.VisiblePDF.Artifact || a.Objects[7].Role != presignexecute.AssetVisiblePDFV1 {
		return ErrSigningAdmissionUnavailableV1
	}
	rc.delegated = &delegatedSignerEvidenceV1{public: PreSignContextV1{
		SchemaVersion: 1, DocumentID: d.ID, ExecutionID: e.ID,
		ExecutionSHA256: retained.Execution().Commitment(), VisiblePDFSHA256: e.VisiblePDF.Artifact.SHA256,
		DisclosureVersion: copy.Version, DisclosureSHA256: copy.SHA256, DisclosureText: copy.Text,
		ProviderName: g.Grantor.Name, ExecutedAt: e.ExecutedAt.UTC().Format(time.RFC3339Nano)},
		visible: e.VisiblePDF.Artifact, assetsSHA256: retained.Assets().Commitment(), customer: r.ID,
		epoch: e.CeremonyEpoch, publishedAt: p.PublishedAt, retainUntil: p.RetainUntil}
	return nil
}

func (rc *RecipientContext) PreSignContextV1() *PreSignContextV1 {
	if rc == nil || rc.delegated == nil {
		return nil
	}
	out := rc.delegated.public
	return &out
}

// The handler uses the same original lease and exact private native asset set.
// Its final callback performs the ordinary fresh credential/source/privacy
// recheck before any headers or bytes are delivered. Explicit presign failures
// never enter the original/base PDF branch.
func (e *Engine) WithSignerPresignPDFV1(ctx context.Context, rc *RecipientContext, consume func([]byte) error) error {
	if e == nil || ctx == nil || rc == nil || rc.readLease == nil || consume == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return ErrSigningAdmissionUnavailableV1
	}
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	original, _, finish, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return err
	}
	defer finish()
	if original.delegated == nil || !time.Now().Before(original.delegated.retainUntil) {
		return ErrSigningAdmissionUnavailableV1
	}
	return rc.readLease.reader.WithPresignPDFV1(ctx, client, consume)
}
