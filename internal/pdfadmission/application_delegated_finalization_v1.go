// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Caller owns w.mu inside its genuine native callback. This fixed read funds
// the complete canonical descriptors before decoding and keeps its actual SQL
// borrower through all repository reads. Missing execution alone is ordinary.
func (w *ApplicationHTMLSendWorkV1) loadDelegatedFinalizationLockedV1(call context.Context) (*presignexecute.RetainedAssetsV1, error) {
	if !w.valid(call) || w.state == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	var sizes [6]int64
	err := db.QueryRow(call, `SELECT octet_length(e.canonical_execution)::bigint,octet_length(e.command_canonical)::bigint,
 octet_length(e.admission_canonical)::bigint,octet_length(p.canonical_policy)::bigint,octet_length(g.canonical_grant)::bigint,
 COALESCE(octet_length(a.canonical_assets),0)::bigint FROM presign_executions e
 LEFT JOIN presign_workflow_revisions p ON p.org_id=e.org_id AND p.policy_id=e.policy_id AND p.revision=e.policy_revision
 LEFT JOIN presign_grant_revisions g ON g.org_id=e.org_id AND g.grant_id=e.grant_id AND g.revision=e.grant_revision
 LEFT JOIN presign_execution_assets_v1 a ON a.org_id=e.org_id AND a.execution_id=e.id AND a.document_id=e.document_id
 WHERE e.org_id=$1 AND e.document_id=$2`, w.session.state.org, w.logicalDocumentV1()).
		Scan(&sizes[0], &sizes[1], &sizes[2], &sizes[3], &sizes[4], &sizes[5])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	raw := int64(32768 + 8*(2048+256))
	for _, size := range sizes {
		if size < 1 || size > 64*1024 {
			return nil, ErrHistoricalFinalizationSourceV1
		}
		var err error
		raw, err = htmlAuthoringSumV1(raw, size)
		if err != nil {
			return nil, ErrHistoricalFinalizationSourceV1
		}
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeBody)
	owned, tx, done, err := applicationSessionSQLBorrowV1(call, w.session.state, true)
	if err != nil {
		return nil, err
	}
	defer done()
	r, err := presignexecute.LoadRetainedAssetsV1(owned, tx, w.session.state.org, w.logicalDocumentV1())
	if err != nil {
		return nil, errors.Join(ErrHistoricalFinalizationSourceV1, err)
	}
	return &r, nil
}

func delegatedFinalizationDocumentV1(d *generated.Document, r *presignexecute.RetainedAssetsV1) bool {
	if d == nil || r == nil {
		return false
	}
	e, p := r.Execution().Snapshot(), r.Publication()
	commitment, err := htmlsource.Commitment(d)
	return err == nil && d.ID == e.Document.ID && d.OrgID == e.OrgID && d.SenderID == e.Document.SenderID &&
		d.SourceKind == "pdf" && d.SigningAdmissionPolicy == "historical" && d.RequiresSignature && !d.IsEnvelope && !d.ParentEnvelopeID.Valid &&
		d.PdfStorageKey.Valid && d.PdfStorageKey.String == e.Document.BasePDF.Artifact.StorageKey &&
		d.PdfStorageVersionID.Valid && d.PdfStorageVersionID.String == e.Document.BasePDF.Artifact.VersionID &&
		hex.EncodeToString(d.PdfSha256) == e.Document.BasePDF.Artifact.SHA256 && commitment == e.Document.Materialization.SourceCommitment &&
		d.HtmlCurrentMaterializationID.Valid && uuid.UUID(d.HtmlCurrentMaterializationID.Bytes) == e.Document.Materialization.ID &&
		d.HtmlCurrentMaterializationSequence.Valid && int64(d.HtmlCurrentMaterializationSequence.Int32) == e.Document.Materialization.Revision &&
		d.HtmlCurrentPageCount.Valid && int(d.HtmlCurrentPageCount.Int32) == e.VisiblePDF.Pages &&
		d.Article13NoticeEpochAt.Valid && d.Article13NoticeEpochAt.Time.Equal(e.CeremonyEpoch) &&
		p.State == "published" && p.CustomerRecipientID == e.Document.Parties[0].ID && !p.PublishedAt.IsZero() &&
		!p.RetentionStartedAt.IsZero() && !p.RetentionCompletedAt.Before(p.RetentionStartedAt) &&
		!p.PublishedAt.Before(p.RetentionCompletedAt) && p.RetainUntil.After(p.PublishedAt)
}

// The Source24 owner captures the immutable execution once, verifies every
// actual archived version, and never substitutes a base PDF for failed proof.
// Caller holds the existing source activity mutex.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) captureDelegatedFinalizationV1(call context.Context) (failure error) {
	if e.delegatedAttempted {
		return e.delegatedError
	}
	e.delegatedAttempted = true
	stage := "delegated_load"
	defer func() { failure = historicalSourceDiagnosticV1(stage, failure); e.delegatedError = failure }()
	w := e.work
	w.mu.Lock()
	r, err := w.loadDelegatedFinalizationLockedV1(call)
	w.mu.Unlock()
	if err != nil {
		return err
	}
	if r == nil {
		return nil
	}
	stage = "delegated_document"
	if !delegatedFinalizationDocumentV1(e.document, r) {
		return ErrHistoricalFinalizationSourceV1
	}
	stage = "delegated_assets"
	for _, a := range r.Assets().Snapshot().Objects {
		stage = "delegated_asset_shape"
		digest, err := hex.DecodeString(a.Object.SHA256)
		if err != nil || len(digest) != 32 {
			return ErrHistoricalFinalizationSourceV1
		}
		stage = "delegated_asset_read"
		_, err = e.readV1(a.Object.StorageKey, a.Object.VersionID, digest, false, func(raw []byte) error {
			if int64(len(raw)) != a.Object.Bytes || (a.ContentType == "application/pdf" && (len(raw) < 5 || string(raw[:5]) != "%PDF-")) {
				return ErrHistoricalFinalizationSourceV1
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	e.delegated = r
	return nil
}

// Inspect the actual immutable base, then release its SDK body before reading
// the visible derivative. Only the independent bounded geometry owner remains.
// Both isolated worker inspections and every response consumer join the same
// existing source lifetime; no alternate request or replacement PDF is made.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) withManualCompositionPDFV1(consume func([]byte, *sanitize.PDFManualGeometry) error) error {
	if e == nil || consume == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	if !e.validV1() || !e.sourceChecked || !e.beginBodyBorrowLockedV1() {
		e.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	r := e.delegated
	e.unlockV1()
	defer e.finishBodyBorrowV1()
	if r == nil {
		return e.WithSourcePDFV1(func(raw []byte) error { return consume(raw, nil) })
	}
	coordinator, err := historicalManualCoordinatorV1(e.work)
	if err != nil {
		return err
	}
	var geometry sanitize.PDFManualGeometry
	var geometryGrant *workguard.GrantV1
	defer func() {
		geometry = sanitize.PDFManualGeometry{}
		if geometryGrant != nil {
			geometryGrant.Close()
		}
	}()
	err = e.WithSourcePDFV1(func(raw []byte) error {
		work, retained, err := sanitize.ManualPDFInspectionParentWorkV1(int64(len(raw)))
		if err != nil {
			return err
		}
		geometryGrant, err = coordinator.TryAcquireV1(e.ctx, e.document.OrgID, workguard.VectorV1{ParentBytes: retained})
		if err != nil {
			return err
		}
		grant, err := coordinator.TryAcquireV1(e.ctx, e.document.OrgID, workguard.VectorV1{ParentBytes: work})
		if err != nil {
			return err
		}
		defer grant.Close()
		geometry, err = sanitize.InspectManualPDFWithContext(e.ctx, raw)
		return err
	})
	if err != nil {
		return err
	}
	s := r.Execution().Snapshot()
	if geometry.SourceSHA256 != s.Document.BasePDF.Artifact.SHA256 || geometry.SourceBytes != s.Document.BasePDF.Artifact.Bytes ||
		geometry.GeometrySHA256 != r.Assets().Snapshot().Overlay.GeometrySHA256 || len(geometry.Pages) != s.VisiblePDF.Pages {
		return ErrHistoricalFinalizationSourceV1
	}
	digest, err := hex.DecodeString(s.VisiblePDF.Artifact.SHA256)
	if err != nil {
		return ErrHistoricalFinalizationSourceV1
	}
	_, err = e.readV1(s.VisiblePDF.Artifact.StorageKey, s.VisiblePDF.Artifact.VersionID, digest, false, func(raw []byte) error {
		if int64(len(raw)) != s.VisiblePDF.Artifact.Bytes {
			return ErrHistoricalFinalizationSourceV1
		}
		return consume(raw, &geometry)
	})
	return err
}

func delegatedNumericMatchesV1(n pgtype.Numeric, want int64) bool {
	if !n.Valid || n.NaN || n.InfinityModifier != pgtype.Finite || n.Int == nil || n.Int.BitLen() > 256 || n.Exp < -32 || n.Exp > 32 {
		return false
	}
	v, err := n.Value()
	text, ok := v.(string)
	if err != nil || !ok || len(text) > 128 {
		return false
	}
	rat, ok := new(big.Rat).SetString(text)
	return ok && new(big.Rat).Mul(rat, big.NewRat(10000, 1)).Cmp(big.NewRat(want, 1)) == 0
}

// Final all-party validation remains mandatory before this helper. This check
// identifies the ONE provider row already painted in the immutable derivative;
// no kind/prefix/status alone can excuse a missing or foreign provider mark.
func delegatedProviderRecipientV1(r *presignexecute.RetainedAssetsV1, fields []*generated.DocumentField, signatures []*generated.Signature) (uuid.UUID, error) {
	if r == nil {
		return uuid.Nil, nil
	}
	return delegatedProviderRecipientForExecutionV1(r.Execution(), fields, signatures)
}

func delegatedProviderRecipientForExecutionV1(execution presign.Execution, fields []*generated.DocumentField, signatures []*generated.Signature) (uuid.UUID, error) {
	e := execution.Snapshot()
	if len(fields) != 2 || len(signatures) != 2 {
		return uuid.Nil, ErrHistoricalFinalizationSourceV1
	}
	for _, expected := range e.Document.Fields {
		found := false
		for _, f := range fields {
			if f != nil && f.ID == expected.ID {
				if found || f.DocumentID != e.Document.ID || !f.RecipientID.Valid || uuid.UUID(f.RecipientID.Bytes) != expected.RecipientID ||
					f.Type != expected.Type || f.Required != expected.Required || int(f.Page) != expected.Page ||
					!delegatedNumericMatchesV1(f.XPct, expected.X) || !delegatedNumericMatchesV1(f.YPct, expected.Y) ||
					!delegatedNumericMatchesV1(f.WPct, expected.W) || !delegatedNumericMatchesV1(f.HPct, expected.H) {
					return uuid.Nil, ErrHistoricalFinalizationSourceV1
				}
				found = true
			}
		}
		if !found {
			return uuid.Nil, ErrHistoricalFinalizationSourceV1
		}
	}
	found := false
	for _, s := range signatures {
		if s == nil {
			return uuid.Nil, ErrHistoricalFinalizationSourceV1
		}
		if s.RecipientID != e.Signature.RecipientID {
			if s.DocumentID != e.Document.ID || s.RecipientID != e.Document.Parties[0].ID || s.SignatureKind != "manual" || s.PresignExecutionID.Valid || !s.SignedAt.Valid || s.SignedAt.Time.Before(e.ExecutedAt) {
				return uuid.Nil, ErrHistoricalFinalizationSourceV1
			}
			continue
		}
		if found || s.ID != e.Signature.ID || s.DocumentID != e.Document.ID || s.FieldID != e.Signature.FieldID ||
			s.SignatureKind != presignexecute.SignatureKind || !s.PresignExecutionID.Valid || uuid.UUID(s.PresignExecutionID.Bytes) != e.ID ||
			s.TypedName != e.Signature.TypedName || s.Font != e.Signature.Style.Font || s.ImageStorageKey != e.Signature.Image.StorageKey ||
			!s.ImageVersionPinRequired || !s.ImageVersionID.Valid || s.ImageVersionID.String != e.Signature.Image.VersionID ||
			hex.EncodeToString(s.ImageSha256) != e.Signature.Image.SHA256 || !s.SignedAt.Valid || !s.SignedAt.Time.Equal(e.ExecutedAt) {
			return uuid.Nil, ErrHistoricalFinalizationSourceV1
		}
		found = true
	}
	if !found {
		return uuid.Nil, ErrHistoricalFinalizationSourceV1
	}
	return e.Signature.RecipientID, nil
}

func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) retainDelegatedAssetsV1(call context.Context, until time.Time) error {
	if err := e.captureDelegatedFinalizationV1(call); err != nil {
		return err
	}
	if e.delegated == nil {
		return nil
	}
	// The immutable original base and all eight archived derivative inputs
	// share the exact final intent deadline; the base is outside the asset set.
	pins := [9]presign.ArtifactPin{e.delegated.Execution().Snapshot().Document.BasePDF.Artifact}
	for i, a := range e.delegated.Assets().Snapshot().Objects {
		pins[i+1] = a.Object
	}
	for _, pin := range pins {
		digest, err := hex.DecodeString(pin.SHA256)
		if err != nil || strings.TrimSpace(pin.VersionID) == "" {
			return ErrHistoricalFinalizationSourceV1
		}
		body, stream, err := e.providerV1()
		if err != nil {
			return err
		}
		err = e.client.RetainEvidenceVersionForSendV1(e.ctx, pin.StorageKey, pin.VersionID, digest, until)
		stream.Close()
		body.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Geometry equality permits different committed source bytes, never changed pages.
func sameDelegatedManualGeometryV1(visible, original sanitize.PDFManualGeometry, pin presign.ArtifactPin) bool {
	return visible.SourceSHA256 == pin.SHA256 && visible.SourceBytes == pin.Bytes && visible.GeometrySHA256 == original.GeometrySHA256 && reflect.DeepEqual(visible.Pages, original.Pages)
}
