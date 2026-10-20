// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func preparationEqualV1(p *generated.SignatureFitPreparation, op uuid.UUID, a *manualfit.AuthorityV1, ceiling int64) bool {
	if p == nil || a == nil {
		return false
	}
	in := a.Input()
	return p.ID == op && p.OrgID == in.OrgID && p.DocumentID == in.DocumentID && p.RecipientID == in.RecipientID && p.CeremonyEpoch.Valid && p.CeremonyEpoch.Time.Equal(in.CeremonyEpoch) &&
		hex.EncodeToString(p.AuthoritySha256) == a.SHA256() && p.SourceStorageKey == in.Source.Key && p.SourceVersionID == in.Source.VersionID && hex.EncodeToString(p.SourceSha256) == in.Source.SHA256 && p.SourceBytes == in.Source.Bytes &&
		hex.EncodeToString(p.GeometrySha256) == a.Geometry().GeometrySHA256 && hex.EncodeToString(p.SpanSha256) == in.SpanSHA256 && p.ReservedBytes == ceiling && p.ExpectedObjects == int32(len(a.Pages())+2) && p.Attempts >= 1 && p.Attempts <= 8
}
func versionV1(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(value) < 1 || len(value) > 1024 || !utf8.ValidString(value) || trimmed == "" || trimmed == "null" || trimmed == storage.DevelopmentVersionID {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func objectLayoutV1(id ObjectIDV1, prefix string) (string, string, int64, bool) {
	switch id.Kind {
	case "span":
		return prefix + "span.html", "text/html", manualfit.MaxSpanBytesV1, id.Page == 0
	case "manifest":
		return prefix + "manifest.json", "application/json", manualfit.MaxManifestBytesV1, id.Page == 0
	case "page":
		return prefix + "page-" + strconv.Itoa(int(id.Page)) + ".fit", signaturefit.MediaType, int64(signaturefit.MaxPackageBytes), id.Page >= 1 && id.Page <= 500
	}
	return "", "", 0, false
}
func validObjectV1(o *generated.SignatureFitObject, p *generated.SignatureFitPreparation) bool {
	if o == nil || p == nil {
		return false
	}
	key, mime, cap, ok := objectLayoutV1(ObjectIDV1{o.Kind, o.Page}, manualfit.ObjectPrefixV1(p.ID, p.OrgID, p.DocumentID))
	if !ok || o.PreparationID != p.ID || o.StorageKey != key || o.ContentType != mime || o.Bytes < 1 || o.Bytes > cap || len(o.Sha256) != sha256.Size || bytes.Equal(o.Sha256, make([]byte, sha256.Size)) || o.CleanupCompletedAt.Valid {
		return false
	}
	if o.UploadAttemptedAt.Valid != o.UploadOwnerID.Valid || o.UploadOwnerID.Valid && o.UploadOwnerID.Bytes == [16]byte{} {
		return false
	}
	if o.VersionID.Valid && (!o.UploadAttemptedAt.Valid || !versionV1(o.VersionID.String)) {
		return false
	}
	if o.ReadbackVerifiedAt.Valid && (!o.VersionID.Valid || o.ReadbackVerifiedAt.Time.Before(o.UploadAttemptedAt.Time)) {
		return false
	}
	return true
}
func sameObjectV1(a, b *generated.SignatureFitObject) bool {
	return a != nil && b != nil && a.PreparationID == b.PreparationID && a.Kind == b.Kind && a.Page == b.Page && a.StorageKey == b.StorageKey && a.Bytes == b.Bytes && a.ContentType == b.ContentType && bytes.Equal(a.Sha256, b.Sha256)
}
func inventoryV1(p *generated.SignatureFitPreparation, a *manualfit.AuthorityV1, objects []*generated.SignatureFitObject) (map[ObjectIDV1]*generated.SignatureFitObject, error) {
	expected := map[ObjectIDV1]bool{{"span", 0}: true, {"manifest", 0}: true}
	for _, plan := range a.Pages() {
		expected[ObjectIDV1{"page", int32(plan.Plan.Page)}] = true
	}
	index := make(map[ObjectIDV1]*generated.SignatureFitObject, len(objects))
	var total int64
	for _, o := range objects {
		if !validObjectV1(o, p) {
			return nil, ErrIdentityV1
		}
		id := ObjectIDV1{o.Kind, o.Page}
		if !expected[id] || index[id] != nil || o.Bytes > p.ReservedBytes-total {
			return nil, ErrIdentityV1
		}
		total += o.Bytes
		copyRow := *o
		copyRow.Sha256 = bytes.Clone(o.Sha256)
		index[id] = &copyRow
	}
	if len(index) > int(p.ExpectedObjects) {
		return nil, ErrIdentityV1
	}
	if p.Status == "prepared" {
		if len(index) != int(p.ExpectedObjects) {
			return nil, ErrIdentityV1
		}
		for _, o := range index {
			if !o.VersionID.Valid || !o.ReadbackVerifiedAt.Valid {
				return nil, ErrIdentityV1
			}
		}
	}
	return index, nil
}
func pinV1(o *generated.SignatureFitObject) manualfit.ObjectPinV1 {
	return manualfit.ObjectPinV1{Key: o.StorageKey, VersionID: o.VersionID.String, SHA256: hex.EncodeToString(o.Sha256), Bytes: o.Bytes, ContentType: o.ContentType}
}
func reservationV1(o *generated.SignatureFitObject) storage.FitTransientReservation {
	var sha [sha256.Size]byte
	copy(sha[:], o.Sha256)
	return storage.FitTransientReservation{Key: o.StorageKey, SHA256: sha, Bytes: o.Bytes, ContentType: o.ContentType}
}

// loadOriginalV1 never treats a missing original as permission to replace an
// existing reservation. The adapter supplies a bounded lease and proves any
// negative observation after physical reconciliation of prior uncertain IO.
func (p *PreparerV1) loadOriginalV1(ctx context.Context, operation *generated.SignatureFitPreparation, id ObjectIDV1, supplied []byte, required bool) (*OriginalPayloadV1, error) {
	if nilV1(p.Originals) || operation == nil {
		return nil, ErrOriginalPayloadV1
	}
	_, _, cap, ok := objectLayoutV1(id, manualfit.ObjectPrefixV1(operation.ID, operation.OrgID, operation.DocumentID))
	if !ok {
		return nil, ErrIdentityV1
	}
	lease, err := p.Originals.Load(ctx, operation, id)
	if err != nil {
		if lease != nil {
			lease.Close()
		}
		if ctx.Err() != nil {
			return nil, safeErrorV1(ctx, err)
		}
		if err == pgx.ErrNoRows && lease == nil {
			if required {
				return nil, ErrOriginalPayloadV1
			}
			return nil, nil
		}
		return nil, safeErrorV1(ctx, err)
	}
	if lease == nil {
		return nil, safeErrorV1(ctx, ErrOriginalPayloadV1)
	}
	raw := lease.Bytes()
	if len(raw) < 1 || int64(len(raw)) > cap || int64(len(raw)) > operation.ReservedBytes ||
		(len(supplied) > 0 && !bytes.Equal(supplied, raw)) {
		lease.Close()
		return nil, safeErrorV1(ctx, ErrOriginalPayloadV1)
	}
	if err := ctx.Err(); err != nil {
		lease.Close()
		return nil, safeErrorV1(ctx, err)
	}
	return lease, nil
}

func (p *PreparerV1) captureOriginalV1(ctx context.Context, operation *generated.SignatureFitPreparation, id ObjectIDV1, key, mime string, raw []byte) error {
	if nilV1(p.Originals) {
		return nil
	}
	if len(raw) == 0 {
		return ErrOriginalPayloadV1
	}
	if err := ctx.Err(); err != nil {
		return safeErrorV1(ctx, err)
	}
	if err := p.Originals.Capture(ctx, operation, id, key, mime, raw); err != nil {
		return uncertainErrorV1(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return uncertainErrorV1(ctx, err)
	}
	return nil
}

// object makes one original upload attempt, or only reads/reconciles an earlier
// attempt. Empty history after attempted=true is never permission to PUT again.
// Every checkpoint call is separate and committed; version pin and readback may
// not be collapsed into the upload-attempt transaction.
func (p *PreparerV1) object(ctx context.Context, operation *generated.SignatureFitPreparation, index map[ObjectIDV1]*generated.SignatureFitObject, id ObjectIDV1, key, mime string, payload []byte) (*generated.SignatureFitObject, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, safeErrorV1(ctx, err)
	}
	o := index[id]
	newReservation := o == nil
	// The exact original manifest can be captured before its 85 metadata row.
	// Reconcile it against the canonical manifest of the original pinned inputs;
	// do not overwrite it or select a newly reconstructed alternative.
	if !nilV1(p.Originals) && id.Kind == "manifest" && (o == nil || !o.UploadAttemptedAt.Valid) {
		lease, err := p.loadOriginalV1(ctx, operation, id, payload, o != nil)
		if err != nil {
			return nil, nil, objectErrorV1(ctx, id, err)
		}
		if lease != nil {
			payload = lease.Bytes()
			defer lease.Close()
		}
	}
	if o == nil {
		if operation.Status != "staging" || len(payload) == 0 {
			return nil, nil, ErrOriginalPayloadV1
		}
		layout, contentType, cap, ok := objectLayoutV1(id, manualfit.ObjectPrefixV1(operation.ID, operation.OrgID, operation.DocumentID))
		if !ok || key != layout || mime != contentType || int64(len(payload)) > cap {
			return nil, nil, ErrIdentityV1
		}
		var used int64
		for _, existing := range index {
			if existing.Bytes > operation.ReservedBytes-used {
				return nil, nil, ErrBudgetV1
			}
			used += existing.Bytes
		}
		if int64(len(payload)) > operation.ReservedBytes-used || len(index) >= int(operation.ExpectedObjects) {
			return nil, nil, ErrBudgetV1
		}
		if err := p.captureOriginalV1(ctx, operation, id, key, mime, payload); err != nil {
			return nil, nil, objectErrorV1(ctx, id, err)
		}
		var err error
		o, err = p.Journal.ReserveObject(ctx, generated.ReserveSignatureFitObjectParams{PreparationID: operation.ID, OrgID: operation.OrgID, OwnerID: operation.OwnerID, Kind: id.Kind, Page: id.Page, StorageKey: key, Sha256: digestBytesV1(digestV1(payload)), Bytes: int64(len(payload)), ContentType: mime})
		if err != nil {
			return nil, nil, objectErrorV1(ctx, id, uncertainErrorV1(ctx, err))
		}
		if !validObjectV1(o, operation) || o.Kind != id.Kind || o.Page != id.Page || o.StorageKey != key || o.ContentType != mime || o.Bytes != int64(len(payload)) || hex.EncodeToString(o.Sha256) != digestV1(payload) || o.UploadAttemptedAt.Valid || o.VersionID.Valid {
			return nil, nil, ErrIdentityV1
		}
		index[id] = o
	}
	if !validObjectV1(o, operation) || o.Kind != id.Kind || o.Page != id.Page || o.StorageKey != key || o.ContentType != mime {
		return nil, nil, ErrIdentityV1
	}
	if len(payload) > 0 && (o.Bytes != int64(len(payload)) || hex.EncodeToString(o.Sha256) != digestV1(payload)) {
		return nil, nil, ErrOriginalPayloadV1
	}
	reservation := reservationV1(o)
	if !o.UploadAttemptedAt.Valid {
		if operation.Status != "staging" || len(payload) == 0 {
			return nil, nil, ErrOriginalPayloadV1
		}
		// Idempotent capture also proves the reserved never-attempted identity.
		// Attempted/prepared recovery never calls Capture or writes originals.
		if !newReservation {
			if err := p.captureOriginalV1(ctx, operation, id, key, mime, payload); err != nil {
				return nil, nil, objectErrorV1(ctx, id, err)
			}
		}
		previous := o
		attempted, err := p.Journal.Attempt(ctx, generated.MarkSignatureFitUploadAttemptedParams{PreparationID: operation.ID, OrgID: operation.OrgID, OwnerID: operation.OwnerID, Kind: id.Kind, Page: id.Page})
		if err != nil {
			return nil, nil, objectErrorV1(ctx, id, uncertainErrorV1(ctx, err))
		}
		if !validObjectV1(attempted, operation) || !sameObjectV1(previous, attempted) || !attempted.UploadAttemptedAt.Valid || !attempted.UploadOwnerID.Valid || attempted.UploadOwnerID.Bytes != [16]byte(operation.OwnerID) || attempted.VersionID.Valid {
			return nil, nil, ErrIdentityV1
		}
		o = attempted
		index[id] = o
		if err := ctx.Err(); err != nil {
			return nil, nil, objectErrorV1(ctx, id, uncertainErrorV1(ctx, err))
		}
		// Failure leaves attempted inventory protected, even if this process knows it
		// was canceled before dispatch. A later restart must not infer terminality.
		stored, err := p.Objects.PutFitTransientReserved(ctx, reservation, payload)
		if err != nil {
			return nil, nil, objectErrorV1(ctx, id, uncertainErrorV1(ctx, err))
		}
		if stored.SHA256 != reservation.SHA256 || !versionV1(stored.VersionID) {
			return nil, nil, ErrUncertainIOV1
		}
		pinned, err := p.Journal.Pin(ctx, generated.PinSignatureFitObjectVersionParams{PreparationID: operation.ID, OrgID: operation.OrgID, OwnerID: operation.OwnerID, Kind: id.Kind, Page: id.Page, VersionID: stored.VersionID})
		if err != nil {
			return nil, nil, objectErrorV1(ctx, id, uncertainErrorV1(ctx, err))
		}
		if !validObjectV1(pinned, operation) || !sameObjectV1(o, pinned) || !pinned.VersionID.Valid || pinned.VersionID.String != stored.VersionID {
			return nil, nil, ErrIdentityV1
		}
		o = pinned
		index[id] = o
	} else if !o.VersionID.Valid {
		if operation.Status != "staging" {
			return nil, nil, ErrIdentityV1
		}
		stored, found, err := p.Objects.ResolveFitTransientVersion(ctx, reservation)
		if err != nil || !found {
			return nil, nil, objectErrorV1(ctx, id, uncertainErrorV1(ctx, err))
		}
		if stored.SHA256 != reservation.SHA256 || !versionV1(stored.VersionID) {
			return nil, nil, ErrIdentityV1
		}
		pinned, err := p.Journal.Pin(ctx, generated.PinSignatureFitObjectVersionParams{PreparationID: operation.ID, OrgID: operation.OrgID, OwnerID: operation.OwnerID, Kind: id.Kind, Page: id.Page, VersionID: stored.VersionID})
		if err != nil {
			return nil, nil, objectErrorV1(ctx, id, uncertainErrorV1(ctx, err))
		}
		if !validObjectV1(pinned, operation) || !sameObjectV1(o, pinned) || !pinned.VersionID.Valid || pinned.VersionID.String != stored.VersionID {
			return nil, nil, ErrIdentityV1
		}
		o = pinned
		index[id] = o
	}
	raw, err := p.Objects.GetVerifiedVersionBounded(ctx, o.StorageKey, o.VersionID.String, o.Sha256, o.Bytes)
	if err != nil {
		return nil, nil, objectErrorV1(ctx, id, err)
	}
	if int64(len(raw)) != o.Bytes || digestV1(raw) != hex.EncodeToString(o.Sha256) || len(payload) > 0 && !bytes.Equal(payload, raw) {
		clear(raw)
		return nil, nil, ErrIdentityV1
	}
	if err := ctx.Err(); err != nil {
		clear(raw)
		return nil, nil, safeErrorV1(ctx, err)
	}
	if !o.ReadbackVerifiedAt.Valid {
		if operation.Status != "staging" {
			clear(raw)
			return nil, nil, ErrIdentityV1
		}
		verified, err := p.Journal.Verified(ctx, generated.MarkSignatureFitObjectReadbackVerifiedParams{PreparationID: operation.ID, OrgID: operation.OrgID, OwnerID: operation.OwnerID, Kind: id.Kind, Page: id.Page, VersionID: o.VersionID.String, Sha256: bytes.Clone(o.Sha256), Bytes: o.Bytes})
		if err != nil {
			clear(raw)
			return nil, nil, objectErrorV1(ctx, id, uncertainErrorV1(ctx, err))
		}
		if !validObjectV1(verified, operation) || !sameObjectV1(o, verified) || verified.VersionID.String != o.VersionID.String || !verified.ReadbackVerifiedAt.Valid {
			clear(raw)
			return nil, nil, ErrIdentityV1
		}
		o = verified
		index[id] = o
	}
	return o, raw, nil
}
