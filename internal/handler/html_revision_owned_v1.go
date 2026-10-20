// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
)

// Every source/PDF/provider/credential stage belongs to this one original
// request. SQL cleanup is detached and bounded; it never creates another
// read/mutation operation or retries an uncertain commit.
func revisionCleanupContextV1(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}
func closeRevisionSQLV1(ctx context.Context, stage *pdfadmission.ApplicationHTMLRevisionSQLV1) error {
	if stage == nil {
		return nil
	}
	cleanup, stop := revisionCleanupContextV1(ctx)
	defer stop()
	return stage.CloseSQLV1(cleanup)
}

type htmlRevisionLoadedV1 struct {
	source      *pdfadmission.ApplicationHTMLRevisionSourceV1
	document    *generated.Document
	collections *pdfadmission.ApplicationHTMLRevisionCollectionsV1
	guard       *htmlRevisionPolicyGuardV1
}

// All original decisions run inside the actual tracked native callback. The
// scalar parent/real User stages preserve auth before cache/body failures;
// source commitment and CAS still precede Current and fresh signing state.
func readOwnedHTMLRevisionV1(call context.Context, db generated.DBTX, reader *pdfadmission.ApplicationHTMLRevisionReaderV1, stage *pdfadmission.ApplicationHTMLRevisionSQLV1, actor authoring.Actor, id uuid.UUID, in htmlDocumentRevisionInput, expected time.Time) (*htmlRevisionLoadedV1, error) {
	models, guard, err := htmlRevisionPolicyReadV1(call, db, reader, actor, id, expected)
	if err != nil {
		return nil, err
	}
	source, err := stage.NewSourceV1(call)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			source.CloseConsumerV1()
		}
	}()
	if err = source.ValidateV1(); err != nil {
		return nil, err
	}
	commitment, err := source.CommitmentV1()
	if err != nil {
		return nil, err
	}
	if !models.Document.UpdatedAt.Time.Equal(expected) || commitment != in.ExpectedHTMLSourceCommitment {
		return nil, errHTMLDocumentRevisionConflict
	}
	if err = source.ValidateCurrentV1(); err != nil {
		return nil, err
	}
	collections, err := reader.NewCollectionsV1(call)
	if err != nil {
		return nil, err
	}
	keepCollection := false
	defer func() {
		if !keepCollection {
			collections.CloseConsumerV1()
		}
	}()
	if err = source.ValidateSigningPageStateV1(call, collections, 0); err != nil {
		return nil, err
	}
	keep = true
	keepCollection = true
	return &htmlRevisionLoadedV1{source: source, document: models.Document, collections: collections, guard: guard}, nil
}
func loadOwnedHTMLRevisionV1(ctx context.Context, op *pdfadmission.ApplicationHTMLRevisionOperationV1, purpose pdfadmission.HTMLRevisionSQLPurposeV1, actor authoring.Actor, id uuid.UUID, in htmlDocumentRevisionInput, expected time.Time) (*htmlRevisionLoadedV1, error) {
	stage, err := op.OpenSQLV1(purpose)
	if err != nil {
		return nil, err
	}
	var loaded *htmlRevisionLoadedV1
	err = stage.WithTxV1(func(call context.Context, db generated.DBTX, reader *pdfadmission.ApplicationHTMLRevisionReaderV1) error {
		var e error
		loaded, e = readOwnedHTMLRevisionV1(call, db, reader, stage, actor, id, in, expected)
		if e != nil {
			return e
		}
		return loaded.guard.Recheck(call)
	})
	// The source borrower owns the actual loaded body beyond SQL retirement.
	// Header/collection consumers are signalled after their last SQL/model use.
	if loaded != nil {
		loaded.collections.CloseConsumerV1()
	}
	stage.CloseConsumerV1()
	cleanupErr := closeRevisionSQLV1(ctx, stage)
	if err != nil || cleanupErr != nil {
		if loaded != nil {
			loaded.source.CloseConsumerV1()
		}
		return nil, errors.Join(err, cleanupErr)
	}
	return loaded, nil
}

func (s *Server) composeOwnedRevisionSigningPageV1(ctx context.Context, page *pdfadmission.HTMLRevisionSigningPageV1, bodyPDF []byte) (sanitize.PDFCompositionResult, error) {
	if page == nil || page.Policy == nil {
		return sanitize.PDFCompositionResult{}, htmlmaster.ErrInvalid
	}
	var fonts []render.FontAsset
	for _, font := range render.FontAssets() {
		if font.Filename == "Inter.woff2" {
			digest := sha256.Sum256(font.Bytes)
			if hex.EncodeToString(digest[:]) != page.Policy.FontSHA256 {
				return sanitize.PDFCompositionResult{}, htmlmaster.ErrInvalid
			}
			fonts = append(fonts, font)
		}
	}
	if len(fonts) != 1 {
		return sanitize.PDFCompositionResult{}, htmlmaster.ErrInvalid
	}
	pagePDF, err := s.Sign.PDF.HTMLToPDF(ctx, page.HTML, render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms", Assets: fonts})
	if err != nil {
		return sanitize.PDFCompositionResult{}, errHTMLDocumentRevisionRenderUnavailable
	}
	return sanitize.ComposeSigningPageWithContext(ctx, "html-branded-signing-page", bodyPDF, pagePDF)
}

// The caller retains release until the actual HTTP response writer returns.
// The result is a defensive value projection, never a new mutation authority.
func (s *Server) reviseHTMLDocumentOwnedV1(parent context.Context, actor authoring.Actor, id uuid.UUID, in htmlDocumentRevisionInput, expected time.Time, inputOwner *pdfadmission.ApplicationHTMLAuthoringInputV1) (result *pdfadmission.HTMLRevisionResultModelsV1, release func(), failure error) {
	if s.HTMLCreationSessions == nil || inputOwner == nil {
		return nil, nil, pdfadmission.ErrHTMLRevisionOperationV1
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	op, err := s.HTMLCreationSessions.NewHTMLRevisionOperationV1(ctx, actor.OrgID, id, actor.UserID, inputOwner)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			cancel()
			cleanup, stop := revisionCleanupContextV1(parent)
			defer stop()
			failure = errors.Join(failure, op.CloseV1(cleanup))
		}
	}()
	initial, err := loadOwnedHTMLRevisionV1(ctx, op, pdfadmission.HTMLRevisionInitialReadV1, actor, id, in, expected)
	if err != nil {
		return nil, nil, err
	}
	defer initial.source.CloseConsumerV1()
	if err = initial.source.MaterializeRevisionV1(); err != nil {
		return nil, nil, err
	}
	prepared, finishPrepared, err := initial.source.BorrowPreparedV1()
	if err != nil {
		return nil, nil, err
	}
	// This borrow spans scanner/render and the later event's unchanged changed-
	// section values. It is joined by actual return, never by ctx cancellation.
	defer finishPrepared()
	if err = scanHTMLMaster(ctx, prepared.Input.MasterJSON); err != nil {
		return nil, nil, err
	}
	previousPages := initial.document.HtmlCurrentPageCount.Int32
	if !initial.document.HtmlCurrentMaterializationID.Valid {
		previous, e := s.Storage.GetVerifiedVersion(ctx, initial.document.PdfStorageKey.String, initial.document.PdfStorageVersionID.String, initial.document.PdfSha256)
		if e != nil {
			return nil, nil, e
		}
		count, e := sanitize.PageCountWithContext(ctx, previous)
		if e != nil || count < 1 || count > sanitize.MaxPDFPages {
			return nil, nil, errHTMLDocumentRevisionConflict
		}
		previousPages = int32(count)
	}
	checked, err := loadOwnedHTMLRevisionV1(ctx, op, pdfadmission.HTMLRevisionBeforeRenderReadV1, actor, id, in, expected)
	if err != nil {
		return nil, nil, err
	}
	checked.source.CloseConsumerV1()
	processing, stopProcessing := context.WithTimeout(ctx, htmlTemplatePreviewTimeout)
	pdf, err := s.Sign.PDF.HTMLToPDF(processing, prepared.Rendered.HTML, render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms"})
	if err != nil {
		stopProcessing()
		return nil, nil, errHTMLDocumentRevisionRenderUnavailable
	}
	if len(pdf) == 0 || len(pdf) > sanitize.MaxPDFBytes {
		stopProcessing()
		return nil, nil, errHTMLDocumentRevisionConflict
	}
	page, finishPage, err := initial.source.BorrowSigningPageV1()
	if err != nil {
		stopProcessing()
		return nil, nil, err
	}
	var cleaned sanitize.Result
	var composition sanitize.PDFCompositionManifest
	pages := 0
	if page.Policy != nil {
		composed, e := s.composeOwnedRevisionSigningPageV1(processing, page, pdf)
		if e != nil {
			finishPage()
			stopProcessing()
			return nil, nil, e
		}
		cleaned = composed.Result
		composition = composed.Composition
		pages = composition.FinalPages
	} else {
		cleaned, err = sanitize.CleanWithContext(processing, "html-document-revision", "application/pdf", pdf)
		if err == nil {
			pages, err = sanitize.PageCountWithContext(processing, cleaned.Bytes)
		}
	}
	finishPage()
	stopProcessing()
	if err != nil {
		return nil, nil, err
	}
	if cleaned.Report.UnsupportedT || pages < 1 || pages > sanitize.MaxPDFPages || len(cleaned.Bytes) == 0 || len(cleaned.Bytes) > sanitize.MaxPDFBytes {
		return nil, nil, errHTMLDocumentRevisionConflict
	}
	report, err := sanitize.MergeReports(nil, cleaned.Report)
	if err != nil {
		return nil, nil, err
	}
	checked, err = loadOwnedHTMLRevisionV1(ctx, op, pdfadmission.HTMLRevisionBeforeStoreReadV1, actor, id, in, expected)
	if err != nil {
		return nil, nil, err
	}
	checked.source.CloseConsumerV1()
	key := path.Join("org", actor.OrgID.String(), "documents", uuid.NewString()+".pdf")
	stored, err := s.Storage.PutVersioned(ctx, key, "application/pdf", cleaned.Bytes)
	if err != nil {
		return nil, nil, err
	}
	owned := cleanupObjectVersion{Key: key, VersionID: stored.VersionID, SHA256: bytes.Clone(stored.SHA256[:])}
	var mutation *pdfadmission.ApplicationHTMLRevisionSQLV1
	defer func() {
		if failure != nil && (mutation == nil || !mutation.CommitDispatchedV1()) {
			failure = errors.Join(failure, deleteObjectDetached(parent, s.Storage, owned))
		}
	}()
	candidate, err := initial.source.NewCandidateV1(pdfadmission.HTMLRevisionPDFOutputV1{Key: key, VersionID: stored.VersionID, SHA256: stored.SHA256[:], PageCount: int32(pages), PreviousPageCount: previousPages, MetadataRedactionReport: report, Composition: composition})
	if err != nil {
		return nil, nil, err
	}
	defer candidate.CloseConsumerV1()
	mutation, err = op.OpenSQLV1(pdfadmission.HTMLRevisionMutationV1)
	if err != nil {
		return nil, nil, err
	}
	var pending audit.PendingEvent
	var eventConsumer *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	var finishResult func()
	err = mutation.WithTxV1(func(call context.Context, db generated.DBTX, reader *pdfadmission.ApplicationHTMLRevisionReaderV1) error {
		final, e := readOwnedHTMLRevisionV1(call, db, reader, mutation, actor, id, in, expected)
		if e != nil {
			return e
		}
		defer final.source.CloseConsumerV1()
		defer final.collections.CloseConsumerV1()
		writer, e := mutation.NewWriterV1(call, final.source, candidate, final.collections)
		if e != nil {
			return e
		}
		defer writer.CloseConsumerV1()
		if e = writer.AppendV1(call); e != nil {
			return e
		}
		changed, e := writer.UpdatePartiesAndFieldsV1(call)
		if e != nil {
			return e
		}
		if e = writer.SnapshotVersionV1(call); e != nil {
			return e
		}
		if e = writer.MeasureFreshPolicyV1(call); e != nil {
			return e
		}
		result, finishResult, e = writer.BorrowResultV1(call)
		if e != nil {
			return e
		}
		session, e := mutation.AuditSessionV1(call)
		if e != nil {
			return e
		}
		pending, eventConsumer, e = ownedaudit.LogV1(s.Audit, call, session, pdfadmission.HTMLAuditHTMLRevisionV1, audit.Entry{
			OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &id, Kind: audit.KindDocumentUpdated,
			Payload: map[string]any{"html_materialization_revision": result.MaterializationRevision, "html_source_commitment": result.Document.HtmlEffectiveSourceCommitment.String, "review_required": true, "placement_reset": true, "changed_sections": prepared.Rendered.ChangedSections, "contract_party_identities_updated": changed},
		})
		if e != nil {
			return e
		}
		return final.guard.Recheck(call)
	})
	if err != nil {
		if eventConsumer != nil {
			eventConsumer.CloseConsumerV1()
		}
		if finishResult != nil {
			finishResult()
		}
		return nil, nil, err
	}
	if err = mutation.CommitV1(); err != nil {
		if eventConsumer != nil {
			eventConsumer.CloseConsumerV1()
		}
		if finishResult != nil {
			finishResult()
		}
		return nil, nil, err
	}
	// Actual acknowledged commit precedes publication. The event's own
	// consumer remains retained through every hook's actual last use.
	if err = ownedaudit.PublishV1(s.Audit, pending, eventConsumer); err != nil {
		eventConsumer.CloseConsumerV1()
		if finishResult != nil {
			finishResult()
		}
		return nil, nil, err
	}
	transferred = true
	release = func() {
		finishResult()
		cancel()
		cleanup, stop := revisionCleanupContextV1(parent)
		defer stop()
		_ = op.CloseV1(cleanup)
	}
	return result, release, nil
}

func writeOwnedHTMLRevisionUnavailableV1(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusServiceUnavailable, "HTML document revision capacity is temporarily unavailable")
}
