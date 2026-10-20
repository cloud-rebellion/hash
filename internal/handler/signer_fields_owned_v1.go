// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type signerFieldsResponseErrorV1 struct {
	status  int
	message string
}

func (e *signerFieldsResponseErrorV1) Error() string { return e.message }
func signerFieldsResponseV1(status int, message string) error {
	return &signerFieldsResponseErrorV1{status: status, message: message}
}

func writeSignerFieldsFailureV1(w http.ResponseWriter, err error) {
	if errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) {
		writeSignerReadError(w, err)
		return
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		writeInternalError(w, err)
		return
	}
	var response *signerFieldsResponseErrorV1
	if errors.As(err, &response) {
		writeError(w, response.status, response.message)
		return
	}
	if errors.Is(err, errSignerReadChanged) {
		writeSignerReadError(w, err)
		return
	}
	writeInternalError(w, err)
}

func (s *Server) handleSignerSubmitFieldsOwnedV1(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	notice, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	originalPDF, err := signerPDFObservationFor(rc)
	if err != nil {
		writeSignerReadError(w, err)
		return
	}
	if rc.Document.Status != "sent" && rc.Document.Status != "in_progress" {
		writeError(w, http.StatusConflict, "document is not accepting field updates")
		return
	}
	request, err := s.Sign.NewSignerFieldsRequestV1(ctx, rc, sign.ParticipantResponseEvidence{Notice: notice, IP: clientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		writeSignerReadError(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, pdfadmission.SignerFieldsBodyLimitV1)
	var in submitFieldsInput
	if err = decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(in.Values) == 0 {
		writeError(w, http.StatusBadRequest, "values required")
		return
	}
	if err = request.CaptureValuesV1(ctx, in.Values); err != nil {
		writeSignerReadError(w, errors.Join(sign.ErrSigningAdmissionUnavailableV1, err))
		return
	}
	in.Values, err = request.ValuesV1()
	if err != nil {
		writeSignerReadError(w, errors.Join(sign.ErrSigningAdmissionUnavailableV1, err))
		return
	}
	var updated []map[string]any
	var lockedPDF *signerPDFObservation
	err = s.Sign.WithSignerFieldsMutationV1(ctx, rc, request, func(actual context.Context, original *sign.RecipientContext, lockedDoc *generated.Document, work *pdfadmission.ApplicationHTMLSendWorkV1, appendAudit func(audit.Entry) error) error {
		if err := sign.ValidateLockedNoticeEvidence(original, lockedDoc, notice); err != nil {
			return signerFieldsResponseV1(http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		}
		if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" {
			return signerFieldsResponseV1(http.StatusConflict, "document is not accepting field updates")
		}
		fresh, err := work.ReadSignerFieldsRecipientV1(actual)
		if errors.Is(err, pgx.ErrNoRows) {
			return signerFieldsResponseV1(http.StatusUnauthorized, "signing link is no longer valid")
		}
		if err != nil {
			return err
		}
		if err = sign.ValidateLockedRecipientCredential(original, fresh, lockedDoc, time.Now()); err != nil {
			return signerFieldsResponseV1(http.StatusUnauthorized, "signing link is no longer valid")
		}
		if original.Recipient.Name != fresh.Name || original.Recipient.Email != fresh.Email || original.Recipient.Role != fresh.Role || original.Recipient.Locale != fresh.Locale || original.Recipient.OrderIndex != fresh.OrderIndex {
			return errSignerReadChanged
		}
		lockedContext := *original
		lockedContext.Document = lockedDoc
		lockedPDF, err = signerPDFObservationFor(&lockedContext)
		if err != nil || !sameSignerDocumentSource(original.Document, lockedDoc) || !sameSignerPDFObservation(originalPDF, lockedPDF) {
			return errSignerReadChanged
		}
		if err = work.ValidateSignerFieldsMaterializationV1(actual); err != nil {
			return errors.Join(errSignerReadChanged, err)
		}
		if lockedDoc.SourceKind == "pdf" {
			frozen, err := work.SignerFieldsFrozenV1(actual)
			if err != nil {
				return err
			}
			if frozen {
				return signerFieldsResponseV1(http.StatusConflict, "PDF content is frozen after the first signature; create a new revision to change it")
			}
		}
		if fresh.DocumentID != lockedDoc.ID || !recipientCanFillFields(fresh.Status) {
			return signerFieldsResponseV1(http.StatusConflict, "recipient has already completed or declined this ceremony")
		}
		rows, err := work.ReadFieldsV1(actual)
		if err != nil {
			return err
		}
		if err = work.AdmitSignerFieldsPreparationV1(actual); err != nil {
			return err
		}
		allowed := make([]*generated.DocumentField, 0, len(rows))
		for _, f := range rows {
			if !f.RecipientID.Valid || uuid.UUID(f.RecipientID.Bytes) == original.Recipient.ID {
				allowed = append(allowed, f)
			}
		}
		prepared, invalid := prepareSignerFieldValues(allowed, in.Values)
		if invalid != nil {
			return signerFieldsResponseV1(invalid.status, invalid.message)
		}
		updated = make([]map[string]any, 0, len(prepared))
		for _, item := range prepared {
			row, err := work.UpdateSignerFieldValueV1(actual, item.field.ID, item.value)
			if errors.Is(err, pgx.ErrNoRows) {
				return signerFieldsResponseV1(http.StatusConflict, "document is not accepting field updates")
			}
			if err != nil {
				return err
			}
			payload, err := bindSignerNoticeAuditPayload(notice, map[string]any{"field_id": item.field.ID.String(), "type": item.field.Type, "label": item.field.Label.String, "value_len": len(item.value), "value_hash": hashFieldValueForAudit(item.value)})
			if err != nil {
				return err
			}
			ip, ua, err := request.MetadataV1()
			if err != nil {
				return err
			}
			if err = appendAudit(audit.Entry{OrgID: original.Document.OrgID, DocumentID: &original.Document.ID, RecipientID: &original.Recipient.ID, Kind: audit.KindDocumentFieldFill, IP: ip, UserAgent: ua, Payload: payload}); err != nil {
				return err
			}
			updated = append(updated, fieldToDTO(row))
		}
		if err = sign.ValidateLockedRecipientCredential(original, fresh, lockedDoc, time.Now()); err != nil {
			return signerFieldsResponseV1(http.StatusUnauthorized, "signing link is no longer valid")
		}
		return nil
	})
	if err != nil {
		writeSignerFieldsFailureV1(w, err)
		return
	}
	setSignerPDFObservationHeaders(w, lockedPDF)
	writeJSON(w, http.StatusOK, map[string]any{"updated": updated, "count": len(updated)})
}
