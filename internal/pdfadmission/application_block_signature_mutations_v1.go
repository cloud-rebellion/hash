// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"math/big"
	"net/netip"
	"sort"
	"unsafe"
)

type applicationBlockSignatureMutationV1 struct {
	request                                                 *applicationBlockSignatureRequestV1
	recipient                                               *generated.Recipient
	field                                                   *generated.DocumentField
	signature                                               *generated.Signature
	roles                                                   []string
	recipientReads                                          int
	rolesAttempted, fieldAttempted, insertAttempted, marked bool
}

func (w *ApplicationHTMLSendWorkV1) BeginBlockSignatureMutationV1(call context.Context, h *ApplicationBlockSignatureRequestV1) error {
	if w == nil || w.self != w || h == nil || h.state == nil {
		return ErrBlockSignatureRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.blockSignature != nil || w.stage == nil || w.stage.purpose != HTMLBlockSignMutationV1 || w.familyRoot != nil || w.sourceDocument == nil || s.self != s || s.closed || !s.prepared || s.snapshot == nil || s.snapshot.document != w.sourceDocument.ID || s.snapshot.org != w.sourceDocument.OrgID || w.stage.operation.factory != s.reader.factory {
		return ErrBlockSignatureRequestV1
	}
	raw := int64(0)
	for _, part := range [][2]int64{{int64(len(s.typedName) + len(s.font) + len(s.ip) + len(s.userAgent)), 4}, {int64(len("org//documents//signatures/-")) + 3*36 + 64 + 5, 4}, {1, 2*int64(unsafe.Sizeof(applicationBlockSignatureMutationV1{})) + 2*int64(unsafe.Sizeof(generated.Signature{})) + int64(unsafe.Sizeof(generated.InsertSignatureParams{})) + 3*int64(unsafe.Sizeof(generated.DocumentField{})) + int64(unsafe.Sizeof(generated.CreateFieldParams{})) + int64(unsafe.Sizeof(generated.MeasureSignatureFitHTMLPolicyFieldV1Params{})) + 4*int64(unsafe.Sizeof(big.Int{})) + 8*int64(unsafe.Sizeof(uintptr(0)))}} {
		if !htmlInputAddV1(&raw, part[0], part[1]) {
			return ErrBlockSignatureRequestV1
		}
	}
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return errors.Join(ErrBlockSignatureRequestV1, err)
	}
	w.closes = append(w.closes, closeRows)
	w.blockSignature = &applicationBlockSignatureMutationV1{request: s}
	return nil
}
func (w *ApplicationHTMLSendWorkV1) blockSignatureRequestV1() *applicationBlockSignatureRequestV1 {
	if w == nil || w.self != w {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.blockSignature == nil {
		return nil
	}
	return w.blockSignature.request
}

// The original GetRecipient runs at its original policy point. The genuine
// scalar collection aggregate/pins fund this one full row without demanding
// unrelated field-option bodies or first materializing the party collection.
func (w *ApplicationHTMLSendWorkV1) ReadBlockSignatureRecipientV1(call context.Context) (*generated.Recipient, error) {
	s := w.blockSignatureRequestV1()
	if s == nil {
		return nil, ErrBlockSignatureRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.blockSignature
	if !w.valid(call) || s.closed || s.snapshot == nil || m == nil || m.request != s || m.recipientReads >= 2 {
		return nil, ErrBlockSignatureRequestV1
	}
	m.recipientReads++
	if _, err := w.collectionHeaderAndPinsV1(call, htmlSendRecipientCollectionV1); err != nil {
		return nil, err
	}
	row, err := w.queries.GetRecipient(call, generated.GetRecipientParams{ID: s.snapshot.recipient, OrgID: s.snapshot.org})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != s.snapshot.recipient || row.DocumentID != s.snapshot.document {
		return nil, ErrBlockSignatureRequestV1
	}
	m.recipient = htmlSendCloneRecipientV1(row)
	return row, nil
}
func (w *ApplicationHTMLSendWorkV1) CountBlockSignatureUnfilledV1(call context.Context) (int64, error) {
	s := w.blockSignatureRequestV1()
	if s == nil {
		return 0, ErrBlockSignatureRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || s.closed || s.snapshot == nil || w.blockSignature == nil || w.blockSignature.recipient == nil {
		return 0, ErrBlockSignatureRequestV1
	}
	return w.queries.CountUnfilledRequiredForRecipient(call, generated.CountUnfilledRequiredForRecipientParams{DocumentID: s.snapshot.document, RecipientID: pgtype.UUID{Bytes: s.snapshot.recipient, Valid: true}})
}
func (w *ApplicationHTMLSendWorkV1) RequiredBlockSignatureRolesV1(call context.Context) ([]string, error) {
	s := w.blockSignatureRequestV1()
	if s == nil {
		return nil, ErrBlockSignatureRequestV1
	}
	s.mu.Lock()
	if s.closed || s.snapshot == nil {
		s.mu.Unlock()
		return nil, ErrBlockSignatureRequestV1
	}
	s.mu.Unlock()
	w.mu.Lock()
	if !w.valid(call) || w.blockSignature == nil || w.blockSignature.request != s || w.blockSignature.rolesAttempted || w.sourceDocument == nil {
		w.mu.Unlock()
		return nil, ErrBlockSignatureRequestV1
	}
	w.blockSignature.rolesAttempted = true
	doc := w.sourceDocument
	w.mu.Unlock()
	if doc.SourceKind == "pdf" && !doc.IsEnvelope {
		return w.historicalPDFSignatureRolesV1(call)
	}
	if !doc.IsEnvelope {
		source, err := w.NewSourceV1(call)
		if err != nil {
			return nil, err
		}
		roles, err := source.BlockRolesForSigningV1()
		if err != nil {
			return nil, err
		}
		w.mu.Lock()
		w.blockSignature.roles = append([]string(nil), roles...)
		w.mu.Unlock()
		return roles, nil
	}
	members, err := w.ReadEnvelopeMembersV1(call)
	if err != nil {
		return nil, fmt.Errorf("resolve signer roles: list envelope children: %w", err)
	}
	if len(members) == 0 {
		return nil, errors.New("resolve signer roles: envelope has no children")
	}
	// Root union map/slices and propagated role strings are priced from the
	// actual privately retained member bodies before any aggregate allocation.
	work := int64(0)
	for _, member := range members {
		if member == nil {
			return nil, ErrBlockSignatureRequestV1
		}
		if _, err := member.ReadModelsV1(call); err != nil {
			return nil, err
		}
		member.mu.Lock()
		d := member.sourceDocument
		if d == nil {
			member.mu.Unlock()
			return nil, ErrBlockSignatureRequestV1
		}
		n := int64(len(d.BlocksJson)) + int64(len(d.VariablesJson))
		member.mu.Unlock()
		if !htmlInputAddV1(&work, n, 64) {
			return nil, ErrBlockSignatureRequestV1
		}
	}
	w.mu.Lock()
	closeUnion, err := w.actor.acquireOwnedRetainedBodyV1(call, work, 0)
	if err == nil {
		w.closes = append(w.closes, closeUnion)
	}
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	roleSet := make(map[string]struct{})
	for i, member := range members {
		if member == nil {
			return nil, fmt.Errorf("resolve signer roles: child %d is nil", i+1)
		}
		member.mu.Lock()
		d := member.sourceDocument
		member.mu.Unlock()
		if d == nil {
			return nil, fmt.Errorf("resolve signer roles: child %d is nil", i+1)
		}
		if !d.ParentEnvelopeID.Valid || uuid.UUID(d.ParentEnvelopeID.Bytes) != doc.ID {
			return nil, fmt.Errorf("resolve signer roles: child %s is not attached", d.ID)
		}
		if d.IsEnvelope {
			return nil, fmt.Errorf("resolve signer roles: child %s is itself an envelope", d.ID)
		}
		if (doc.Status == "sent" || doc.Status == "in_progress") && (d.Status != "sent" && d.Status != "in_progress") {
			return nil, fmt.Errorf("resolve signer roles: child %s status %s does not match envelope status %s", d.ID, d.Status, doc.Status)
		}
		if d.SourceKind != "blocks" {
			return nil, fmt.Errorf("resolve signer roles: child %s is not a blocks document", d.ID)
		}
		source, err := member.NewSourceV1(call)
		if err != nil {
			return nil, err
		}
		roles, err := source.BlockRolesForSigningV1()
		if err != nil {
			return nil, fmt.Errorf("resolve signer roles: child %s: %w", d.ID, err)
		}
		for _, role := range roles {
			roleSet[role] = struct{}{}
		}
	}
	if len(roleSet) == 0 {
		return nil, errors.New("resolve signer roles: envelope children contain no signature fields")
	}
	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	w.mu.Lock()
	w.blockSignature.roles = append([]string(nil), roles...)
	w.mu.Unlock()
	return roles, nil
}
func blockSignatureZeroV1(n pgtype.Numeric) bool {
	return n.Valid && n.Int != nil && n.Int.Sign() == 0 && !n.NaN && n.InfinityModifier == pgtype.Finite
}
func (w *ApplicationHTMLSendWorkV1) FindOrCreateBlockSignatureFieldV1(call context.Context) (*generated.DocumentField, error) {
	s := w.blockSignatureRequestV1()
	if s == nil {
		return nil, ErrBlockSignatureRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.blockSignature
	if !w.valid(call) || s.closed || s.snapshot == nil || m == nil || !w.fieldsRead || m.fieldAttempted {
		return nil, ErrBlockSignatureRequestV1
	}
	m.fieldAttempted = true
	for _, row := range w.sourceFields {
		if row != nil && row.RecipientID.Valid && uuid.UUID(row.RecipientID.Bytes) == s.snapshot.recipient && row.Type == "signature" {
			m.field = htmlSendCloneFieldV1(row)
			return htmlSendCloneFieldV1(row), nil
		}
	}
	if w.sourceDocument.SourceKind != "blocks" {
		return nil, errors.New("PDF signature field is missing; sender must place and assign a visible signature field before send")
	}
	zero := pgtype.Numeric{Int: big.NewInt(0), Valid: true}
	row, err := w.queries.CreateField(call, generated.CreateFieldParams{DocumentID: s.snapshot.document, RecipientID: pgtype.UUID{Bytes: s.snapshot.recipient, Valid: true}, Type: "signature", Page: 1, XPct: zero, YPct: zero, WPct: zero, HPct: zero, Required: true, Label: pgtype.Text{String: "Signature", Valid: true}, OptionsJson: []byte("{}")})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID == uuid.Nil || row.DocumentID != s.snapshot.document || !row.RecipientID.Valid || uuid.UUID(row.RecipientID.Bytes) != s.snapshot.recipient || row.Type != "signature" || row.Page != 1 || !row.Required || row.Label != (pgtype.Text{String: "Signature", Valid: true}) || !bytes.Equal(row.OptionsJson, []byte("{}")) || !blockSignatureZeroV1(row.XPct) || !blockSignatureZeroV1(row.YPct) || !blockSignatureZeroV1(row.WPct) || !blockSignatureZeroV1(row.HPct) {
		return nil, ErrBlockSignatureRequestV1
	}
	measured, err := w.queries.MeasureSignatureFitHTMLPolicyFieldV1(call, generated.MeasureSignatureFitHTMLPolicyFieldV1Params{DocumentID: s.snapshot.document, OrgID: s.snapshot.org, FieldID: row.ID})
	if err != nil {
		return nil, err
	}
	if measured == nil || measured.FieldID != row.ID || measured.DocumentID != s.snapshot.document || measured.OrgID != s.snapshot.org || measured.OptionsWireBytes != 2 || measured.MeasurementServerVersionNum != w.sourceServerVersion {
		return nil, ErrBlockSignatureRequestV1
	}
	m.field = htmlSendCloneFieldV1(row)
	return row, nil
}
func (w *ApplicationHTMLSendWorkV1) InsertBlockSignatureV1(call context.Context) (*generated.Signature, error) {
	s := w.blockSignatureRequestV1()
	if s == nil {
		return nil, ErrBlockSignatureRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.blockSignature
	if !w.valid(call) || s.closed || s.snapshot == nil || !s.stored || m == nil || m.field == nil || m.insertAttempted {
		return nil, ErrBlockSignatureRequestV1
	}
	m.insertAttempted = true
	var ip *netip.Addr
	if parsed, err := netip.ParseAddr(s.ip); err == nil {
		ip = &parsed
	}
	ua := pgtype.Text{}
	if s.userAgent != "" {
		ua = pgtype.Text{String: s.userAgent, Valid: true}
	}
	row, err := w.queries.InsertSignature(call, generated.InsertSignatureParams{DocumentID: s.snapshot.document, RecipientID: s.snapshot.recipient, FieldID: m.field.ID, Font: s.font, TypedName: s.typedName, ImageStorageKey: s.imageKey, ImageSha256: s.digest[:], ImageVersionID: pgtype.Text{String: s.imageVersion, Valid: true}, SignerIp: ip, SignerUa: ua})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID == uuid.Nil || row.DocumentID != s.snapshot.document || row.RecipientID != s.snapshot.recipient || row.FieldID != m.field.ID || row.Font != s.font || row.TypedName != s.typedName || row.ImageStorageKey != s.imageKey || row.ImageVersionID != (pgtype.Text{String: s.imageVersion, Valid: true}) || !bytes.Equal(row.ImageSha256, s.digest[:]) || row.SignerUa != ua || row.SignatureKind != "manual" || row.PresignExecutionID.Valid || !row.SignedAt.Valid || row.SignedAt.Time.IsZero() || ((ip == nil) != (row.SignerIp == nil)) || (ip != nil && *ip != *row.SignerIp) {
		return nil, ErrBlockSignatureRequestV1
	}
	copy := *row
	copy.ImageSha256 = bytes.Clone(row.ImageSha256)
	m.signature = &copy
	return row, nil
}
func (w *ApplicationHTMLSendWorkV1) MarkBlockSignatureSignedV1(call context.Context) error {
	s := w.blockSignatureRequestV1()
	if s == nil {
		return ErrBlockSignatureRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.blockSignature
	if !w.valid(call) || s.closed || s.snapshot == nil || m == nil || m.signature == nil || m.marked {
		return ErrBlockSignatureRequestV1
	}
	m.marked = true
	if err := w.queries.SetRecipientStatus(call, generated.SetRecipientStatusParams{ID: s.snapshot.recipient, DocumentID: s.snapshot.document, Status: "signed"}); err != nil {
		return err
	}
	if w.sourceDocument.Status != "sent" {
		return nil
	}
	raw, _, err := w.admitDocumentReturnV1(call, int64(len("in_progress")))
	if err != nil {
		return err
	}
	row, err := w.queries.SetDocumentStatus(call, generated.SetDocumentStatusParams{ID: s.snapshot.document, OrgID: s.snapshot.org, Status: "in_progress"})
	if err != nil {
		return err
	}
	if !w.verifyDocumentReturnV1(row, raw) || row.Status != "in_progress" {
		return ErrBlockSignatureRequestV1
	}
	before := *w.sourceDocument
	before.Status = row.Status
	before.UpdatedAt = row.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&before, row) {
		return ErrBlockSignatureRequestV1
	}
	w.sourceDocument = htmlSendCloneDocumentV1(row)
	return nil
}
func (w *ApplicationHTMLSendWorkV1) CountBlockSignatureRemainingV1(call context.Context) (int64, error) {
	s := w.blockSignatureRequestV1()
	if s == nil {
		return 0, ErrBlockSignatureRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.blockSignature
	if !w.valid(call) || s.closed || s.snapshot == nil || m == nil || !m.marked || m.roles == nil {
		return 0, ErrBlockSignatureRequestV1
	}
	return w.queries.CountUnsignedSignersByRoles(call, generated.CountUnsignedSignersByRolesParams{DocumentID: s.snapshot.document, Roles: m.roles})
}
