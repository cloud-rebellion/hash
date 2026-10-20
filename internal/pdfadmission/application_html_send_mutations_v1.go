// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
)

// ReadActorV1 is the ORIGINAL full user read under its actual same-reader
// actor+org scalar header loan. A detached private copy is retained before the
// policy layer receives its mutable view. Authorization itself stays in Send.
func (w *ApplicationHTMLSendWorkV1) ReadActorV1(call context.Context, id uuid.UUID) (*generated.User, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceActor != nil || id == uuid.Nil {
		return nil, ErrHTMLSendWorkV1
	}
	if err := w.actor.AcquireActorV1(call, w.session.state.org, id, true); err != nil {
		return nil, err
	}
	user, err := w.queries.GetUserForShare(call, generated.GetUserForShareParams{ID: id, OrgID: w.session.state.org})
	if err != nil {
		return nil, err
	}
	if user == nil || user.ID != id || user.OrgID != w.session.state.org {
		return nil, ErrHTMLSendWorkV1
	}
	copy := *user
	copy.Email = strings.Clone(user.Email)
	copy.Name = strings.Clone(user.Name)
	copy.Role = strings.Clone(user.Role)
	copy.ZitadelSub.String = strings.Clone(user.ZitadelSub.String)
	w.sourceActor = &copy
	return user, nil
}
func (w *ApplicationHTMLSendWorkV1) ConfirmLawfulBasisV1(call context.Context, lawfulBasis, via string) (*generated.DocumentLawfulBasisConfirmation, error) {
	return w.confirmLawfulBasisV1(call, lawfulBasis, via, false)
}

// The package path records the same explicit controller instruction without
// rewriting the already measured original document clock. Legacy Send keeps its
// original mutation; this method grants neither capture nor sealing authority.
func (w *ApplicationHTMLSendWorkV1) ConfirmPackageLawfulBasisV1(call context.Context, lawfulBasis, via string) (*generated.DocumentLawfulBasisConfirmation, error) {
	return w.confirmLawfulBasisV1(call, lawfulBasis, via, true)
}
func (w *ApplicationHTMLSendWorkV1) confirmLawfulBasisV1(call context.Context, lawfulBasis, via string, packageOnly bool) (*generated.DocumentLawfulBasisConfirmation, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceActor == nil || w.sourceDocument == nil || w.confirmed {
		return nil, ErrHTMLSendWorkV1
	}
	if packageOnly && (w.stage == nil || w.stage.purpose != HTMLSendAdmissionV1 || !w.packageInitialSelectionChecked || lawfulBasis != "contract" || w.sourceDocument.LawfulBasis != lawfulBasis) {
		return nil, ErrHTMLSendWorkV1
	}
	w.confirmed = true
	s := w.session.state
	// The genuine owner header includes full Org3+User4 raw strings. The actual
	// INSERT/RETURNING projects controller name/contact from those SAME locked
	// rows; no guessed identity length or subsequent caller model funds it.
	h, err := w.queries.GetHTMLAuthoringOwnerHeaderV1(call, generated.GetHTMLAuthoringOwnerHeaderV1Params{UserID: w.sourceActor.ID, OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.UserID != w.sourceActor.ID || h.OrgID != s.org || h.RawTextBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	raw, err := htmlAuthoringSumV1(h.RawTextBytes, int64(len(lawfulBasis)), int64(len(via)))
	if err != nil {
		return nil, err
	}
	db := int64(0)
	if packageOnly {
		db = 16384
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, db)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	var row *generated.DocumentLawfulBasisConfirmation
	if packageOnly {
		row, err = w.queries.ConfirmDocumentPackageLawfulBasisV1(call, generated.ConfirmDocumentPackageLawfulBasisV1Params{DocumentID: s.document, OrgID: s.org, LawfulBasis: lawfulBasis, ConfirmedBy: pgtype.UUID{Bytes: w.sourceActor.ID, Valid: true}, Via: via, ExpectedUpdatedAt: w.sourceDocument.UpdatedAt})
	} else {
		row, err = w.queries.ConfirmDocumentLawfulBasis(call, generated.ConfirmDocumentLawfulBasisParams{DocumentID: s.document, OrgID: s.org, LawfulBasis: lawfulBasis, ConfirmedBy: pgtype.UUID{Bytes: w.sourceActor.ID, Valid: true}, Via: via})
	}
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != s.document || row.OrgID != s.org || int64(len(row.LawfulBasis)+len(row.Via)+len(row.ControllerName)+len(row.ControllerContact)) > raw {
		return nil, ErrHTMLSendWorkV1
	}
	w.confirmedBasis = strings.Clone(row.LawfulBasis)
	w.confirmedBasisValid = true
	return row, nil
}

type HTMLSendIntentActorV1 struct{ IP, Via, Tool string }

func (w *ApplicationHTMLSendWorkV1) CreateIntentV1(call context.Context, a HTMLSendIntentActorV1) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceActor == nil || w.sourceDocument == nil || w.intentCreated || (w.packageCapture != nil && w.packageCapture.metadata.Present) {
		return ErrHTMLSendWorkV1
	}
	present, err := w.selectedPackageMembersLockedV1(call)
	if err != nil {
		return err
	}
	if present {
		return ErrPackageSendSelectionRequiredV1
	}
	w.intentCreated = true
	s := w.session.state
	raw, err := htmlAuthoringSumV1(int64(len(w.sourceActor.Email)), int64(len(a.IP)), int64(len(a.Via)), int64(len(a.Tool)))
	if err != nil {
		return err
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.CreateSendSealingIntent(call, generated.CreateSendSealingIntentParams{DocumentID: s.document, OrgID: s.org, ActorUserID: pgtype.UUID{Bytes: w.sourceActor.ID, Valid: true}, ActorEmail: w.sourceActor.Email, ActorIp: a.IP, Via: a.Via, Tool: a.Tool})
	if err != nil {
		return err
	}
	if row == nil || row.DocumentID != s.document || row.OrgID != s.org || int64(len(row.ActorEmail)+len(row.ActorIp)+len(row.Via)+len(row.Tool)+len(row.LastError.String)) > raw {
		return ErrHTMLSendWorkV1
	}
	return nil
}

// Internal only: every caller below is a fixed native mutation with unchanged
// JSON and a finite literal/data-derived text delta. This owns ACTUAL current
// row bytes plus ACTUAL SQL input strings before expanding a full RETURNING.
func (w *ApplicationHTMLSendWorkV1) admitDocumentReturnV1(call context.Context, extraRaw int64) (raw, wire int64, err error) {
	if !w.valid(call) || w.sourceDocument == nil || extraRaw < 0 {
		return 0, 0, ErrHTMLSendWorkV1
	}
	d := w.sourceDocument
	basisRaw := int64(0)
	if w.confirmedBasisValid {
		basisRaw = int64(len(w.confirmedBasis))
	}
	raw, err = htmlAuthoringSumV1(signerDocumentRawBytesV1(d), extraRaw, basisRaw)
	if err != nil {
		return 0, 0, err
	}
	wire, err = htmlAuthoringSumV1(int64(len(d.HtmlSourceJson)), int64(len(d.HtmlCurrentSourceJson)), int64(len(d.VariablesJson)), int64(len(d.BlocksJson)), int64(len(d.Metadata)), int64(len(d.MetadataRedactionReport)))
	if err != nil {
		return 0, 0, err
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return 0, 0, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	return raw, wire, nil
}
func (w *ApplicationHTMLSendWorkV1) verifyDocumentReturnV1(row *generated.Document, raw int64) bool {
	d := w.sourceDocument
	return row != nil && d != nil && row.ID == d.ID && row.OrgID == d.OrgID && signerDocumentRawBytesV1(row) <= raw && bytes.Equal(row.HtmlSourceJson, d.HtmlSourceJson) && bytes.Equal(row.HtmlCurrentSourceJson, d.HtmlCurrentSourceJson) && bytes.Equal(row.VariablesJson, d.VariablesJson) && bytes.Equal(row.BlocksJson, d.BlocksJson) && bytes.Equal(row.Metadata, d.Metadata) && bytes.Equal(row.MetadataRedactionReport, d.MetadataRedactionReport)
}
func (w *ApplicationHTMLSendWorkV1) BeginSendSealingV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.beginSealingAttempted || !w.intentCreated {
		return ErrHTMLSendWorkV1
	}
	w.beginSealingAttempted = true
	raw, _, err := w.admitDocumentReturnV1(call, int64(len("sealing")))
	if err != nil {
		return err
	}
	s := w.session.state
	row, err := w.queries.BeginDocumentSendSealing(call, generated.BeginDocumentSendSealingParams{ID: s.document, OrgID: s.org})
	if err != nil {
		return err
	}
	if !w.verifyDocumentReturnV1(row, raw) || row.Status != "sealing" {
		return ErrHTMLSendWorkV1
	}
	before, after := *w.sourceDocument, *row
	before.Status = after.Status
	before.UpdatedAt = after.UpdatedAt
	if w.confirmedBasisValid {
		before.LawfulBasis = w.confirmedBasis
	}
	if !htmlSendDocumentExactTupleEqualV1(&before, &after) {
		return ErrHTMLSendWorkV1
	}
	return nil
}
