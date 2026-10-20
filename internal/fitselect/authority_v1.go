// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitselect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strings"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// ArchiveEntryLimitV1 reserves a complete non-fit ZIP entry. Bytes is an exact
// size for existing evidence or an enforced upper bound for future final PDF,
// certificate, signed payload/index and detached signature. Merely passing
// these values does not enforce downstream rendering/export limits; those
// producers must reject output above the same committed limits.
type ArchiveEntryLimitV1 struct {
	Name  string
	Bytes int64
}

// ArchiveBudgetV1 includes every live preparation reservation (not merely the
// current selected set), all non-fit entries, ZIP headers, data descriptors and
// end records. Fit reservations are conservative ceilings until safe cleanup.
// Its locked identity prevents reusing a proof after inventory changes.
type ArchiveBudgetV1 struct {
	documentID, orgID uuid.UUID
	reservedBytes     int64
	inventorySHA      [32]byte
	total             int64
	valid             bool
}

func (p ArchiveBudgetV1) UpperBoundBytes() int64 {
	if !p.valid {
		return 0
	}
	return p.total
}

// AdmitArchiveBudgetV1 requires the actual locked state, not a caller-supplied
// fit subtotal. Selected, unpublished and unknown-upload preparations consume
// the same budget. Privacy inventory remains durable even after safe cleanup.
// nonFit must enumerate the ACTUAL schema4 source/final/certificate/index,
// manifest, event/version and issuer-key members, plus retained base/legacy
// evidence. Producers must enforce these exact committed ceilings. Unsigned
// party debt and whole-process/retained storage permits remain caller gates;
// this function checks the locked existing85 inventory and actual ZIP format.
func AdmitArchiveBudgetV1(state LockedStateV1, nonFit []ArchiveEntryLimitV1) (ArchiveBudgetV1, error) {
	if state.Document == nil || state.Document.ID == uuid.Nil || state.Document.OrgID == uuid.Nil || state.Document.SignatureFitReservedBytes < 0 || state.Document.SignatureFitReservedBytes > manualfit.MaxEvidenceBytesV1 {
		return ArchiveBudgetV1{}, ErrAdmissionV1
	}
	if len(nonFit) < 11 || len(nonFit) > manualfit.MaxArchiveEntriesV1 || len(state.Inventory) > 8192 || state.Preparation == nil {
		return ArchiveBudgetV1{}, ErrAdmissionV1
	}
	sourceName := manualfit.SourceArchiveNameV1(state.Document.ID)
	required := map[string]bool{sourceName: false, "final-pdf.pdf": false, "audit-cert.pdf": false, "audit-cert-payload.txt": false, "audit-cert-signature.txt": false, "signature-fit-index.json": false, "manifest.json": false, "events.json": false, "versions.json": false, "manifest-public-key.pem": false, "certificate-public-key.pem": false}
	sizes := make([]manualfit.ArchiveSizeV1, 0, len(nonFit))
	for _, entry := range nonFit {
		// All fit payloads are charged by the live preparation reservation,
		// including packages that have not been produced yet.
		if strings.HasPrefix(entry.Name, "fit-") || (entry.Name == sourceName && entry.Bytes != state.Preparation.SourceBytes) {
			return ArchiveBudgetV1{}, ErrAdmissionV1
		}
		sizes = append(sizes, manualfit.ArchiveSizeV1{Name: entry.Name, Bytes: entry.Bytes})
		if _, ok := required[entry.Name]; ok {
			required[entry.Name] = true
		}
	}
	for _, present := range required {
		if !present {
			return ArchiveBudgetV1{}, ErrAdmissionV1
		}
	}
	total, err := manualfit.StoreZIPSizeV1(sizes)
	if err != nil {
		return ArchiveBudgetV1{}, ErrAdmissionV1
	}
	add := func(n int64) bool {
		if n < 0 || n > manualfit.MaxEvidenceBytesV1-total {
			return false
		}
		total += n
		return true
	}
	// Reserve headers for every expected object, including never-uploaded
	// members, from immutable85 metadata. Do not guess502 for known three-member
	// operations or use ZIP64's65535 limit instead of the producer's10000 cap.
	type preparationBudget struct {
		recipient uuid.UUID
		status    string
		objects   int32
		bytes     int64
	}
	preps := map[uuid.UUID]preparationBudget{}
	var reserved int64
	entries := len(nonFit)
	for _, r := range state.Inventory {
		if r == nil || r.PreparationID == uuid.Nil || r.RecipientID == uuid.Nil || r.ExpectedObjects < 3 || r.ExpectedObjects > 502 || r.ReservedBytes < 3 || r.ReservedBytes > manualfit.MaxArchiveBytesV1 {
			return ArchiveBudgetV1{}, ErrAdmissionV1
		}
		switch r.Status {
		case "staging", "prepared", "abandoned", "cleaning", "cleaned":
		default:
			return ArchiveBudgetV1{}, ErrAdmissionV1
		}
		current := preparationBudget{r.RecipientID, r.Status, r.ExpectedObjects, r.ReservedBytes}
		if prior, ok := preps[r.PreparationID]; ok {
			if prior != current {
				return ArchiveBudgetV1{}, ErrAdmissionV1
			}
			continue
		}
		preps[r.PreparationID] = current
		if r.Status != "cleaned" {
			if r.ReservedBytes > manualfit.MaxArchiveBytesV1-reserved || int(r.ExpectedObjects) > manualfit.MaxArchiveEntriesV1-entries {
				return ArchiveBudgetV1{}, ErrAdmissionV1
			}
			reserved += r.ReservedBytes
			entries += int(r.ExpectedObjects)
		}
	}
	if reserved != state.Document.SignatureFitReservedBytes {
		return ArchiveBudgetV1{}, ErrAdmissionV1
	}
	p, ok := preps[state.Preparation.ID]
	if !ok || p != (preparationBudget{state.Preparation.RecipientID, state.Preparation.Status, state.Preparation.ExpectedObjects, state.Preparation.ReservedBytes}) {
		return ArchiveBudgetV1{}, ErrAdmissionV1
	}
	maxFitName := max(len(manualfit.ManifestArchiveNameV1(state.Document.ID)), len(manualfit.SpanArchiveNameV1(state.Document.ID)), len(manualfit.PageArchiveNameV1(state.Document.ID, 500)))
	if !add(reserved) || !add(int64(entries-len(nonFit))*int64(92+2*maxFitName)) {
		return ArchiveBudgetV1{}, ErrAdmissionV1
	}
	digest, err := inventoryCommitment(state.Inventory)
	if err != nil {
		return ArchiveBudgetV1{}, err
	}
	return ArchiveBudgetV1{state.Document.ID, state.Document.OrgID, state.Document.SignatureFitReservedBytes, digest, total, true}, nil
}
func (p ArchiveBudgetV1) matches(state LockedStateV1) bool {
	if !p.valid || state.Document == nil || p.documentID != state.Document.ID || p.orgID != state.Document.OrgID || p.reservedBytes != state.Document.SignatureFitReservedBytes {
		return false
	}
	d, e := inventoryCommitment(state.Inventory)
	return e == nil && d == p.inventorySHA
}
func inventoryCommitment(rows []*generated.ListSignatureFitInventoryRow) ([32]byte, error) {
	// Canonical row order and exact scalar encodings; opaque versions are kept.
	// Hashing JSON generated rows retains unknown/cleaned checkpoints and counts.
	copied := append([]*generated.ListSignatureFitInventoryRow(nil), rows...)
	for _, r := range copied {
		if r == nil || r.PreparationID == uuid.Nil || r.RecipientID == uuid.Nil {
			return [32]byte{}, ErrAdmissionV1
		}
	}
	sort.Slice(copied, func(i, j int) bool {
		a, b := copied[i], copied[j]
		if a.PreparationID != b.PreparationID {
			return bytes.Compare(a.PreparationID[:], b.PreparationID[:]) < 0
		}
		if a.Kind.String != b.Kind.String {
			return a.Kind.String < b.Kind.String
		}
		return a.Page.Int32 < b.Page.Int32
	})
	h := sha256.New()
	for _, r := range copied {
		raw, err := inventoryJSON(r)
		if err != nil {
			return [32]byte{}, ErrAdmissionV1
		}
		var prefix [8]byte
		for i := 0; i < 8; i++ {
			prefix[7-i] = byte(uint64(len(raw)) >> (i * 8))
		}
		_, _ = h.Write(prefix[:])
		_, _ = h.Write(raw)
	}
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d, nil
}

// ValidateLockedAuthorityV1 rebinds every source page through the frozen
// geometry commitment and every assigned required signature target through
// exact database decimal strings. It is intentionally stricter than checking
// a representative first field or only pages occupied by signature ink.
func ValidateLockedAuthorityV1(state LockedStateV1, m *manualfit.ManifestV1, manifestPin manualfit.ObjectPinV1) error {
	if state.Document == nil || state.Recipient == nil || state.Preparation == nil || m == nil {
		return ErrAuthorityChangedV1
	}
	d, r, p := state.Document, state.Recipient, state.Preparation
	b := m.Binding()
	in := m.Authority().Input()
	g := m.Authority().Geometry()
	if d.ID != b.DocumentID || d.OrgID != b.OrgID || r.ID != b.RecipientID || r.DocumentID != d.ID || d.DeletedAt.Valid || d.IsEnvelope || d.ParentEnvelopeID.Valid || d.SourceKind != "pdf" || !d.RequiresSignature || (d.Status != "sent" && d.Status != "in_progress") || (r.Status != "pending" && r.Status != "sent" && r.Status != "viewed") || !d.Article13NoticeEpochAt.Valid || !d.Article13NoticeEpochAt.Time.Equal(b.CeremonyEpoch) || !d.Article13NoticeEpochV61Committed {
		return ErrAuthorityChangedV1
	}
	if !d.PdfStorageKey.Valid || d.PdfStorageKey.String != in.Source.Key || !d.PdfStorageVersionID.Valid || d.PdfStorageVersionID.String != in.Source.VersionID || hex.EncodeToString(d.PdfSha256) != in.Source.SHA256 {
		return ErrAuthorityChangedV1
	}
	if p.ID != b.OperationID || p.OrgID != b.OrgID || p.DocumentID != b.DocumentID || p.RecipientID != b.RecipientID || !p.CeremonyEpoch.Valid || !p.CeremonyEpoch.Time.Equal(b.CeremonyEpoch) || p.Status != "prepared" || hex.EncodeToString(p.AuthoritySha256) != b.AuthoritySHA256 || p.SourceStorageKey != in.Source.Key || p.SourceVersionID != in.Source.VersionID || hex.EncodeToString(p.SourceSha256) != in.Source.SHA256 || p.SourceBytes != in.Source.Bytes || hex.EncodeToString(p.GeometrySha256) != g.GeometrySHA256 || hex.EncodeToString(p.SpanSha256) != in.SpanSHA256 {
		return ErrAuthorityChangedV1
	}
	if manifestPin.Key != m.ManifestKey() || manifestPin.SHA256 != m.SHA256() || manifestPin.Bytes != int64(len(m.CanonicalJSON())) || manifestPin.ContentType != "application/json" || p.ExpectedObjects != int32(len(m.Pages())+2) || p.ReservedBytes < m.AggregateBytes() || p.ReservedBytes > manualfit.MaxEvidenceBytesV1 {
		return ErrAuthorityChangedV1
	}
	if len(state.AllFields) < 1 || len(state.AllFields) > pdflayout.MaxFields {
		return ErrAuthorityChangedV1
	}
	targets := map[uuid.UUID]manualfit.TargetV1{}
	for _, target := range in.Targets {
		targets[target.ID] = target
	}
	seen := map[uuid.UUID]bool{}
	count := 0
	for _, f := range state.AllFields {
		if f == nil || f.ID == uuid.Nil || f.DocumentID != d.ID || seen[f.ID] {
			return ErrAuthorityChangedV1
		}
		seen[f.ID] = true
		if f.Type != "signature" || !f.RecipientID.Valid || uuid.UUID(f.RecipientID.Bytes) != r.ID {
			continue
		}
		target, ok := targets[f.ID]
		if !ok || !f.Required || target.Page != int(f.Page) || target.Required != f.Required || !pdflayout.ValidPlacement(f, len(g.Pages)) {
			return ErrAuthorityChangedV1
		}
		got := [4]string{}
		for i, n := range []pgtype.Numeric{f.XPct, f.YPct, f.WPct, f.HPct} {
			text, e := decimal(n)
			if e != nil {
				return ErrAuthorityChangedV1
			}
			got[i] = text
		}
		if got != [4]string{target.X, target.Y, target.W, target.H} {
			return ErrAuthorityChangedV1
		}
		count++
	}
	if count != len(in.Targets) {
		return ErrAuthorityChangedV1
	}
	expected := map[string]manualfit.ObjectPinV1{"span:0": m.Span(), "manifest:0": manifestPin}
	for _, page := range m.Pages() {
		expected[objectIdentity("page", int32(page.Page))] = page.Package
	}
	if len(state.Objects) != len(expected) {
		return ErrAuthorityChangedV1
	}
	var total int64
	for _, o := range state.Objects {
		if o == nil || o.PreparationID != b.OperationID || !o.UploadAttemptedAt.Valid || !o.UploadOwnerID.Valid || !o.VersionID.Valid || !o.ReadbackVerifiedAt.Valid || o.CleanupCompletedAt.Valid {
			return ErrAuthorityChangedV1
		}
		id := objectIdentity(o.Kind, o.Page)
		pin, ok := expected[id]
		if !ok || o.StorageKey != pin.Key || o.VersionID.String != pin.VersionID || hex.EncodeToString(o.Sha256) != pin.SHA256 || o.Bytes != pin.Bytes || o.ContentType != pin.ContentType || o.Bytes < 1 || o.Bytes > math.MaxInt64-total {
			return ErrAuthorityChangedV1
		}
		total += o.Bytes
		delete(expected, id)
	}
	if len(expected) != 0 || total != m.AggregateBytes() || total > p.ReservedBytes {
		return ErrAuthorityChangedV1
	}
	return nil
}
func decimal(n pgtype.Numeric) (string, error) {
	if !n.Valid || n.Int == nil || n.NaN || n.InfinityModifier != pgtype.Finite || n.Exp < -32 || n.Exp > 32 || n.Int.BitLen() > 256 {
		return "", errors.New("invalid coordinate")
	}
	v, e := n.Value()
	if e != nil {
		return "", e
	}
	s, ok := v.(string)
	if !ok {
		return "", errors.New("invalid coordinate")
	}
	return s, nil
}
