// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrHTMLSendPackagePathRequiredV1 = errors.New("pdfadmission: exact package Send path required")
var ErrHTMLSendPackageIntentV1 = errors.New("pdfadmission: owned package Send intent unavailable")

// Copied tentative observation, never COMMIT acknowledgement, replay permission
// or authority to supply an attempt/capture to another operation.
type HTMLSendPackageIntentMetadataV1 struct {
	AttemptID                                      uuid.UUID
	Capture                                        HTMLSendPackageCaptureMetadataV1
	Article13NoticeEpochAt, RetainUntil, CreatedAt time.Time
}

// PackageSendAttemptIDV1 preserves the one minted identity through Work/SQL
// retirement and uncertain COMMIT. Even a closed genuine operation can report
// this scalar observation. It cannot authorize replay or prove persistence.
func (o *ApplicationHTMLSendOperationV1) PackageSendAttemptIDV1() (uuid.UUID, bool) {
	if o == nil || o.self != o {
		return uuid.Nil, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.packageSendAttemptID, o.packageSendAttemptID != uuid.Nil
}

// Construction/statement frames cover both exact scalar SQL results, binary
// backing/copies, actor text, private observations and repeated bounded main
// JSON extraction in immediate/deferred guards. No manifest/report body is
// selected by the new queries/triggers.
func htmlSendPackageIntentCostV1(d *generated.Document, a HTMLSendIntentActorV1, email string) (int64, int64, error) {
	if d == nil {
		return 0, 0, ErrHTMLSendPackageIntentV1
	}
	typed := int64(unsafe.Sizeof(generated.CreateDocumentPackageSendAttemptV1Params{})) + int64(unsafe.Sizeof(generated.CreateDocumentPackageSealingIntentV1Params{})) + int64(unsafe.Sizeof(generated.DocumentPackageSendAttemptsV1{})) + int64(unsafe.Sizeof(generated.SendSealingIntent{})) + int64(unsafe.Sizeof(HTMLSendPackageIntentMetadataV1{})) + int64(unsafe.Sizeof(applicationHTMLSendPackageCaptureStateV1{}))
	text, err := htmlAuthoringSumV1(int64(len(email)), int64(len(a.IP)), int64(len(a.Via)), int64(len(a.Tool)), int64(len(d.Name)), int64(len(d.PdfStorageKey.String)), int64(len(d.PdfStorageVersionID.String)))
	if err != nil {
		return 0, 0, err
	}
	raw, err := htmlAuthoringSumV1(16384, 8*typed, 16*text, 4096)
	if err != nil {
		return 0, 0, err
	}
	json, err := htmlAuthoringSumV1(int64(len(d.HtmlSourceJson)), int64(len(d.HtmlCurrentSourceJson)))
	if err != nil {
		return 0, 0, err
	}
	db, err := htmlAuthoringSumV1(16384, 8*raw, 16*json)
	if err != nil {
		return 0, 0, err
	}
	return raw, db, nil
}

// The same native transaction must still begin sealing, reauthorize the original
// credential and acknowledge COMMIT. M99 remains closed for nonempty packages.
func (w *ApplicationHTMLSendWorkV1) CreatePackageIntentV1(call context.Context, a HTMLSendIntentActorV1) (out HTMLSendPackageIntentMetadataV1, failure error) {
	defer func() {
		if failure != nil {
			out = HTMLSendPackageIntentMetadataV1{}
			if !errors.Is(failure, ErrHTMLSendPackageIntentV1) {
				failure = errors.Join(ErrHTMLSendPackageIntentV1, failure)
			}
		}
	}()
	if w == nil || w.self != w {
		return out, ErrHTMLSendPackageIntentV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLSendAdmissionV1 || w.stage.operation == nil || w.familyRoot != nil || w.sourceActor == nil || w.sourceDocument == nil || w.sourceOwner == nil || w.packageCapture == nil || !w.packageCapture.metadata.Present || w.packageIntentAttempted || w.intentCreated {
		return out, ErrHTMLSendPackageIntentV1
	}
	c := &w.packageCapture.metadata
	d := w.sourceDocument
	op := w.stage.operation
	if c.OrgID != w.session.state.org || c.DocumentID != w.session.state.document || c.OrgID != d.OrgID || c.DocumentID != d.ID || c.CreatedBy != w.sourceActor.ID || !c.RootUpdatedAt.Equal(d.UpdatedAt.Time) || c.Revision <= 0 || c.DraftGeneration <= 0 || c.PackageID == uuid.Nil {
		return out, ErrHTMLSendPackageIntentV1
	}
	w.packageIntentAttempted = true
	raw, db, err := htmlSendPackageIntentCostV1(d, a, w.sourceActor.Email)
	if err != nil {
		return out, err
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, db)
	if err != nil {
		return out, err
	}
	w.closes = append(w.closes, closeBody)
	reference, err := w.newPackageSendAttemptReferenceV1(call)
	if err != nil {
		return out, err
	}
	boundReference := false
	defer func() {
		if !boundReference {
			reference.closeV1()
		}
	}()
	// Mint exactly once, after pricing and before any mutating SQL. Register on
	// the genuine original operation so cancellation cannot invite a new identity.
	id, err := uuid.NewRandom()
	if err != nil {
		return out, err
	}
	op.mu.Lock()
	if op.closed || op.original == nil || op.original.Err() != nil || op.org != c.OrgID || op.document != c.DocumentID || op.packageSendAttemptID != uuid.Nil || w.stage.session != w.session || w.stage.work != w || !w.stage.active {
		op.mu.Unlock()
		return out, ErrHTMLSendPackageIntentV1
	}
	reference.attemptID = id
	op.packageSendReference = reference
	boundReference = true
	op.packageSendAttemptID = id
	op.mu.Unlock()
	row, err := w.queries.CreateDocumentPackageSendAttemptV1(call, generated.CreateDocumentPackageSendAttemptV1Params{AttemptID: id, PackageID: c.PackageID, CaptureRevision: c.Revision, OrgID: c.OrgID, DocumentID: c.DocumentID, ExpectedRootUpdatedAt: pgtype.Timestamptz{Time: c.RootUpdatedAt, Valid: true}, ExpectedDraftGeneration: c.DraftGeneration, ExpectedPreviousRevision: c.PreviousRevision, ExpectedManifestBytes: c.ManifestBytes, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], ExpectedMemberCount: c.MemberCount, ExpectedPdfBytes: c.PDFBytes, ExpectedPdfPages: c.PDFPages, ActorUserID: w.sourceActor.ID})
	if err != nil {
		return out, err
	}
	if row == nil || row.AttemptID != id || row.OrgID != c.OrgID || row.DocumentID != c.DocumentID || row.PackageID != c.PackageID || row.CaptureRevision != c.Revision || row.PreviousRevision != c.PreviousRevision || row.CapturedDraftGeneration != c.DraftGeneration || !applicationStampEqualV1(row.CapturedRootUpdatedAt, d.UpdatedAt) || row.ManifestBytes != c.ManifestBytes || row.MemberCount != c.MemberCount || row.PdfBytes != c.PDFBytes || row.PdfPages != c.PDFPages || !bytes.Equal(row.ManifestSha256, c.CanonicalSHA256[:]) || !bytes.Equal(row.LegalCommitmentSha256, c.CommitmentSHA256[:]) || row.ActorUserID != w.sourceActor.ID || row.TerminalOutcome.Valid || row.TerminalAt.Valid || row.RetentionStartedAt.Valid || row.RetentionCompletedAt.Valid || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.Article13NoticeEpochAt) || !applicationStampV1(row.RetainUntil) || !row.RetainUntil.Time.Equal(storage.EvidenceRetentionDeadline(row.Article13NoticeEpochAt.Time, article13.RetentionYearsV1)) {
		return out, ErrHTMLSendPackageIntentV1
	}
	intent, err := w.queries.CreateDocumentPackageSealingIntentV1(call, generated.CreateDocumentPackageSealingIntentV1Params{AttemptID: id, OrgID: c.OrgID, DocumentID: c.DocumentID, ActorIp: a.IP, Via: a.Via, Tool: a.Tool})
	if err != nil {
		return out, err
	}
	if intent == nil || intent.DocumentID != c.DocumentID || intent.OrgID != c.OrgID || !intent.PackageSendAttemptID.Valid || uuid.UUID(intent.PackageSendAttemptID.Bytes) != id || !intent.ActorUserID.Valid || uuid.UUID(intent.ActorUserID.Bytes) != w.sourceActor.ID || intent.ActorEmail != w.sourceActor.Email || intent.ActorIp != a.IP || intent.Via != a.Via || intent.Tool != a.Tool || intent.PresignExecutionID.Valid || intent.RetentionStartedAt.Valid || intent.RetentionCompletedAt.Valid || intent.Attempts != 0 || intent.LastError.Valid || !applicationStampEqualV1(intent.Article13NoticeEpochAt, row.Article13NoticeEpochAt) || !applicationStampEqualV1(intent.RetainUntil, row.RetainUntil) || !applicationStampV1(intent.CreatedAt) || !applicationStampV1(intent.UpdatedAt) || call.Err() != nil {
		return out, ErrHTMLSendPackageIntentV1
	}
	w.intentCreated = true
	out = HTMLSendPackageIntentMetadataV1{AttemptID: id, Capture: *c, Article13NoticeEpochAt: row.Article13NoticeEpochAt.Time.UTC(), RetainUntil: row.RetainUntil.Time.UTC(), CreatedAt: row.CreatedAt.Time.UTC()}
	return out, nil
}
