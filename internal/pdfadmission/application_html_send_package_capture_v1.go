// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
)

var ErrHTMLSendPackageCaptureV1 = errors.New("pdfadmission: owned Send package capture unavailable")

// A copied observation of this transaction's tentative append, not COMMIT,
// replay permission, a durable Send binding, consent or signature authority.
type HTMLSendPackageCaptureMetadataV1 struct {
	Present                                     bool
	OrgID, DocumentID, PackageID, CreatedBy     uuid.UUID
	Revision, PreviousRevision, DraftGeneration int64
	RootUpdatedAt, CreatedAt                    time.Time
	ManifestBytes                               int32
	MemberCount                                 int16
	PDFBytes                                    int64
	PDFPages                                    int32
	CanonicalSHA256, CommitmentSHA256           [sha256.Size]byte
}
type applicationHTMLSendPackageCaptureStateV1 struct {
	metadata     HTMLSendPackageCaptureMetadataV1
	subjects     [documentpackage.MaxAnnexesV1 + 2]uuid.UUID
	subjectCount int
}

// AppendDocumentPackageCaptureV1 consumes one same-operation original measured
// owner in a fresh genuine Admission callback. The fixed application policy must
// authorize the original credential again through the later native COMMIT.
// This adapter appends only; package Send stays disabled until durable binding,
// retention/recovery, recipient presentation/consent/signature/report qualify.
func (w *ApplicationHTMLSendWorkV1) AppendDocumentPackageCaptureV1(call context.Context, prior *ApplicationHTMLSendPackageDraftV1) (out HTMLSendPackageCaptureMetadataV1, failure error) {
	defer func() {
		if failure != nil {
			out = HTMLSendPackageCaptureMetadataV1{}
			if !errors.Is(failure, ErrHTMLSendPackageCaptureV1) {
				failure = errors.Join(ErrHTMLSendPackageCaptureV1, failure)
			}
		}
	}()
	if w == nil || w.self != w || prior == nil || prior.state == nil {
		return out, ErrHTMLSendPackageCaptureV1
	}
	w.mu.Lock()
	valid := w.valid(call) && w.stage != nil && w.stage.purpose == HTMLSendAdmissionV1 && w.familyRoot == nil && w.sourceState != nil && w.sourceOwner != nil && w.sourceActor != nil && w.sourceDocument != nil && !w.intentCreated && !w.packageCaptureAttempted && !w.packageDraftAttempted
	if valid {
		w.packageCaptureAttempted = true
	}
	freshSource, freshOwner, stage := w.sourceState, w.sourceOwner, w.stage
	actorID := uuid.Nil
	if w.sourceActor != nil {
		actorID = w.sourceActor.ID
	}
	w.mu.Unlock()
	p := prior.state
	if !valid || !p.lockV1() {
		return out, ErrHTMLSendPackageCaptureV1
	}
	defer p.unlockV1()
	if p.closeRequested.Load() || p.ctx == nil || p.ctx.Err() != nil || p.work == nil || p.work == w || p.source == nil || p.sourceOwner == nil || p.root == nil || p.draft == nil || !p.measuredOK || p.captureAttempted || p.head < 0 || p.head == math.MaxInt64 {
		return out, ErrHTMLSendPackageCaptureV1
	}
	oldWork := p.work
	oldWork.mu.Lock()
	oldStage := oldWork.stage
	valid = !oldWork.closed && !oldWork.resourcesClosed && oldWork.sourceState == p.source && oldWork.sourceOwner == p.sourceOwner && oldWork.packageDraft == p && oldWork.sourceActor != nil && oldWork.sourceActor.ID == actorID && oldStage != nil && oldStage.purpose == HTMLSendPreparationV1 && oldWork.session != nil
	oldSession := oldWork.session
	oldWork.mu.Unlock()
	if !valid || oldSession == nil || !oldSession.RetiredV1() || oldSession.CommitUnknownV1() || stage == nil || stage.operation == nil || oldStage.operation != stage.operation {
		return out, ErrHTMLSendPackageCaptureV1
	}
	op := stage.operation
	op.mu.Lock()
	valid = op.self == op && !op.closed && op.original.Err() == nil && op.org == p.root.OrgID && op.document == p.root.ID && oldStage.self == oldStage && oldStage.used && !oldStage.active && !oldStage.opening && oldStage.work == oldWork && oldStage.session == oldSession && stage.self == stage && stage.used && stage.active && !stage.opening && stage.work == w && stage.session == w.session
	op.mu.Unlock()
	if !valid || !p.source.lockV1() {
		return out, ErrHTMLSendPackageCaptureV1
	}
	defer p.source.unlockV1()
	if p.source.closeRequested.Load() || p.source.owner != p.sourceOwner || p.source.work != oldWork {
		return out, ErrHTMLSendPackageCaptureV1
	}
	if err := p.sourceOwner.beginV1(); err != nil {
		return out, err
	}
	defer p.sourceOwner.finishV1()
	if p.sourceOwner.snapshot == nil || p.sourceOwner.snapshot.document != p.root {
		return out, ErrHTMLSendPackageCaptureV1
	}
	// A foreign operation cannot consume this original owner's one attempt.
	p.captureAttempted = true
	expected := DocumentPackageDraftExpectedV1{}
	if p.draft.present {
		expected = DocumentPackageDraftExpectedV1{PackageID: p.draft.header.ID, Generation: p.draft.header.DraftGeneration}
	}
	fresh, err := w.ReadDocumentPackageDraftV1(call, &ApplicationHTMLSendSourceV1{state: freshSource}, expected)
	if err != nil {
		return out, err
	}
	if fresh == nil || fresh.state == nil || !fresh.state.lockV1() {
		return out, ErrHTMLSendPackageCaptureV1
	}
	f := fresh.state
	defer f.unlockV1()
	if f.closeRequested.Load() || f.sourceOwner != freshOwner || f.source != freshSource || f.draft == nil || !freshSource.lockV1() {
		return out, ErrHTMLSendPackageCaptureV1
	}
	defer freshSource.unlockV1()
	if freshSource.closeRequested.Load() || freshSource.owner != freshOwner || freshOwner == nil {
		return out, ErrHTMLSendPackageCaptureV1
	}
	if err = freshOwner.beginV1(); err != nil {
		return out, err
	}
	defer freshOwner.finishV1()
	if freshOwner.snapshot == nil || !htmlSendDocumentExactTupleEqualV1(p.root, f.root) || !reflect.DeepEqual(p.root, f.root) || !reflect.DeepEqual(p.sourceOwner.snapshot.current, freshOwner.snapshot.current) || !reflect.DeepEqual(p.draft, f.draft) || p.head != f.head {
		return out, ErrDocumentPackageSourceChangedV1
	}
	// This frame also owns the copied result and eventual private Work state.
	fixed := 4*int64(unsafe.Sizeof(applicationHTMLSendPackageCaptureStateV1{})) + 4*int64(unsafe.Sizeof(HTMLSendPackageCaptureMetadataV1{})) + 4096
	if err = freshOwner.holdV1(htmlRevisionSourceStateV1, 0, fixed); err != nil {
		return out, err
	}
	if !f.draft.present {
		w.mu.Lock()
		defer w.mu.Unlock()
		if !w.valid(call) || p.closeRequested.Load() || f.closeRequested.Load() {
			return out, ErrHTMLSendPackageCaptureV1
		}
		w.packageCapture = &applicationHTMLSendPackageCaptureStateV1{}
		return out, nil
	}
	construction, err := htmlSendPackageCaptureConstructionV1(f.root, f.draft)
	if err != nil {
		return out, err
	}
	if err = freshOwner.holdV1(htmlRevisionSourceStateV1, 0, construction); err != nil {
		return out, err
	}
	manifest, err := p.constructCaptureV1(freshOwner)
	if err != nil {
		return out, err
	}
	header := manifest.Header()
	raw := manifest.Manifest().CanonicalJSON()
	parent, db, err := htmlSendPackageCaptureStatementV1(f.root, f.draft, len(raw))
	if err != nil {
		return out, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceOwner != freshOwner || w.sourceState != freshSource || w.packageDraft != f || w.sourceActor == nil || w.sourceActor.ID != actorID || w.sourceActor.OrgID != f.root.OrgID ||
		(w.sourceActor.Role != "owner" && (w.sourceActor.Role != "sender" || f.root.SenderID != actorID)) || w.intentCreated || p.closeRequested.Load() || f.closeRequested.Load() || p.ctx.Err() != nil || call.Err() != nil {
		return out, ErrHTMLSendPackageCaptureV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, parent, db)
	if err != nil {
		return out, err
	}
	w.closes = append(w.closes, closeBody)
	objectSHA := sha256.Sum256(raw)
	legalSHA := applicationDigestV1(header.CommitmentSHA256)
	if len(legalSHA) != sha256.Size || hex.EncodeToString(objectSHA[:]) != header.CanonicalSHA256 {
		return out, ErrHTMLSendPackageCaptureV1
	}
	row, err := w.queries.AppendDocumentPackageCaptureV1(call, generated.AppendDocumentPackageCaptureV1Params{PackageID: header.Binding.PackageID, OrgID: header.Binding.OrgID, DocumentID: header.Binding.DocumentID, Revision: header.Binding.Revision, ExpectedPreviousRevision: header.Guard.PreviousRevision, ExpectedUpdatedAt: f.root.UpdatedAt, ExpectedGeneration: header.Guard.DraftGeneration, Manifest: raw, ManifestSha256: objectSHA[:], LegalCommitmentSha256: legalSHA, CreatedBy: actorID})
	// SQLC returns a nonnil zero-row pointer even when Scan fails.
	if err != nil {
		return out, err
	}
	if row == nil || row.PackageID != header.Binding.PackageID || row.OrgID != header.Binding.OrgID || row.DocumentID != header.Binding.DocumentID || row.Revision != header.Binding.Revision || row.PreviousRevision != header.Guard.PreviousRevision || !applicationStampEqualV1(row.CapturedRootUpdatedAt, f.root.UpdatedAt) || row.CapturedDraftGeneration != header.Guard.DraftGeneration || !bytes.Equal(row.Manifest, raw) || !bytes.Equal(row.ManifestSha256, objectSHA[:]) || !bytes.Equal(row.LegalCommitmentSha256, legalSHA) || len(row.Manifest) != int(header.ManifestBytes) || row.MemberCount != header.MemberCount || row.PdfBytes != header.PDFBytes || row.PdfPages != header.PDFPages || row.CreatedBy != actorID || !applicationStampV1(row.CreatedAt) || p.closeRequested.Load() || f.closeRequested.Load() || call.Err() != nil {
		return out, ErrHTMLSendPackageCaptureV1
	}
	out = HTMLSendPackageCaptureMetadataV1{Present: true, OrgID: row.OrgID, DocumentID: row.DocumentID, PackageID: row.PackageID, CreatedBy: row.CreatedBy, Revision: row.Revision, PreviousRevision: row.PreviousRevision, DraftGeneration: row.CapturedDraftGeneration, RootUpdatedAt: row.CapturedRootUpdatedAt.Time, CreatedAt: row.CreatedAt.Time, ManifestBytes: int32(len(row.Manifest)), MemberCount: row.MemberCount, PDFBytes: row.PdfBytes, PDFPages: row.PdfPages, CanonicalSHA256: objectSHA}
	copy(out.CommitmentSHA256[:], legalSHA)
	w.packageCapture = &applicationHTMLSendPackageCaptureStateV1{metadata: out, subjectCount: f.draft.count + 1}
	w.packageCapture.subjects[0] = out.DocumentID
	for i := 0; i < f.draft.count; i++ {
		w.packageCapture.subjects[i+1] = f.draft.rows[i].MemberDocumentID
	}
	return out, nil
}

// The original owner is locked and measured; fresh source/root equality was
// established by the caller. No caller model, pin, digest or cost enters here.
func (p *applicationHTMLSendPackageDraftStateV1) constructCaptureV1(freshOwner *applicationHTMLRevisionSourceOwnerV1) (*documentpackage.CaptureV1, error) {
	var members [documentpackage.MaxAnnexesV1 + 1]documentpackage.MemberV1
	var materializations [documentpackage.MaxAnnexesV1 + 1]documentpackage.MaterializationPinV1
	root := p.root
	members[0] = documentpackage.MemberV1{DocumentID: root.ID, Title: root.Name, PDF: documentpackage.PDFPinV1{Key: root.PdfStorageKey.String, VersionID: root.PdfStorageVersionID.String, SHA256: hex.EncodeToString(root.PdfSha256), Bytes: p.measured[0].Bytes, Pages: p.measured[0].Pages}, Source: documentpackage.SourcePinV1{Kind: documentpackage.SourcePDFImportV1}}
	if p.measured[0].DocumentID != root.ID {
		return nil, ErrHTMLSendPackageCaptureV1
	}
	if len(root.HtmlSourceJson) > 0 {
		if freshOwner.validation == nil {
			return nil, ErrHTMLSendPackageCaptureV1
		}
		current, err := freshOwner.validation.CommitmentV1()
		if err != nil {
			return nil, err
		}
		origin, err := freshOwner.validation.OriginCommitmentV1()
		if err != nil {
			return nil, err
		}
		members[0].Source = documentpackage.SourcePinV1{Kind: documentpackage.SourceHTMLOriginV1, CommitmentSHA256: current, OriginCommitmentSHA256: origin}
		if root.HtmlCurrentMaterializationID.Valid {
			materializations[0] = documentpackage.MaterializationPinV1{ID: root.HtmlCurrentMaterializationID.Bytes, Sequence: root.HtmlCurrentMaterializationSequence.Int32}
			members[0].Source.Kind = documentpackage.SourceHTMLRevisionV1
			members[0].Source.Materialization = &materializations[0]
		}
	}
	for i := 0; i < p.draft.count; i++ {
		a := &p.draft.rows[i]
		measured := p.measured[i+1]
		if measured.DocumentID != a.MemberDocumentID || measured.Bytes != a.PdfBytes || measured.Pages != a.PdfPages {
			return nil, ErrHTMLSendPackageCaptureV1
		}
		member := documentpackage.MemberV1{DocumentID: a.MemberDocumentID, Title: a.Title, Category: a.Category, PDF: documentpackage.PDFPinV1{Key: a.PdfKey, VersionID: a.PdfVersionID, SHA256: hex.EncodeToString(a.PdfSha256), Bytes: measured.Bytes, Pages: measured.Pages}, Source: documentpackage.SourcePinV1{Kind: a.SourceKind}}
		if len(a.SourceCommitment) > 0 {
			member.Source.CommitmentSHA256 = hex.EncodeToString(a.SourceCommitment)
		}
		if len(a.OriginCommitment) > 0 {
			member.Source.OriginCommitmentSHA256 = hex.EncodeToString(a.OriginCommitment)
		}
		if a.MaterializationID.Valid {
			materializations[i+1] = documentpackage.MaterializationPinV1{ID: a.MaterializationID.Bytes, Sequence: a.MaterializationSequence.Int32}
			member.Source.Materialization = &materializations[i+1]
		}
		members[i+1] = member
	}
	m, err := documentpackage.NewManifestV1(documentpackage.InputV1{Binding: documentpackage.BindingV1{OrgID: root.OrgID, DocumentID: root.ID, PackageID: p.draft.header.ID, Revision: p.head + 1}, Main: members[0], Annexes: members[1 : p.draft.count+1]})
	if err != nil {
		return nil, err
	}
	return documentpackage.NewCaptureV1(m, documentpackage.CaptureGuardV1{RootUpdatedAt: root.UpdatedAt.Time, DraftGeneration: p.draft.header.DraftGeneration, PreviousRevision: p.head})
}
