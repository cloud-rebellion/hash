// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Admission must reserve shared process capacity and check available durable
// staging capacity. SQL87 separately enforces per-document retained body and
// authority limits. This callback is not signer authorization, nor proof of a
// tenant-wide storage quota; the eventual active signing policy must provide it.
// Releases retire transient admission only. Persisted originals remain counted
// by SQL and cannot be deleted just because a lease or request ends.
type OriginalResourceRequestV1 struct {
	OrgID, DocumentID, PreparationID uuid.UUID
	Kind                             string
	Page                             int32
	WorkingBytes, StagingBytes       int64
}
type OriginalAdmissionV1 func(context.Context, OriginalResourceRequestV1) (release func(), err error)

type SQLOriginalJournalV1 struct {
	sessions *originalPostgresV1
	admit    OriginalAdmissionV1
}

// Keep this adapter for the application lifetime and join CloseV1 on shutdown.
// It uses the saved pool configuration without borrowing idle sessions, changing
// credentials, closing the caller pool, uploading, or selecting a signature.
func NewSQLOriginalJournalV1(pool *pgxpool.Pool, admit OriginalAdmissionV1) (*SQLOriginalJournalV1, error) {
	if pool == nil || admit == nil || pool.Config().MaxConns < 1 {
		return nil, ErrOriginalJournalV1
	}
	return &SQLOriginalJournalV1{sessions: newOriginalPostgresV1(pool), admit: admit}, nil
}
func (j *SQLOriginalJournalV1) CloseV1(ctx context.Context) error {
	if j == nil || j.sessions == nil {
		return ErrOriginalJournalV1
	}
	return j.sessions.Drain(ctx, true)
}
func (j *SQLOriginalJournalV1) ReconcileCleanupV1(ctx context.Context) error {
	if j == nil || j.sessions == nil {
		return ErrOriginalJournalV1
	}
	return j.sessions.Drain(ctx, false)
}

func (j *SQLOriginalJournalV1) admission(ctx context.Context, p *generated.SignatureFitPreparation) (*originalResourceLeaseV1, error) {
	if ctx == nil || ctx.Err() != nil || j == nil || j.sessions == nil || j.admit == nil || p == nil ||
		p.ID == uuid.Nil || p.OrgID == uuid.Nil || p.DocumentID == uuid.Nil || p.RecipientID == uuid.Nil || p.OwnerID == uuid.Nil {
		return nil, originalErrorV1(ctx, ErrOriginalResourcesV1)
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, originalErrorV1(ctx, ErrOriginalResourcesV1)
	}
	release, err := j.admit(ctx, OriginalResourceRequestV1{OrgID: p.OrgID, DocumentID: p.DocumentID, PreparationID: p.ID, Kind: "metadata", WorkingBytes: 1 << 20})
	if err != nil || release == nil || ctx.Err() != nil {
		if release != nil {
			release()
		}
		return nil, originalErrorV1(ctx, ErrOriginalResourcesV1)
	}
	return &originalResourceLeaseV1{releases: []func(){release}}, nil
}
func (j *SQLOriginalJournalV1) bodyAdmission(ctx context.Context, lease *originalResourceLeaseV1, p *generated.SignatureFitPreparation, kind string, page int32, n, staging int64) error {
	if n < 1 || n > 17<<20 || staging < 0 || staging > n {
		return ErrOriginalResourcesV1
	}
	// Original/driver/decoding/inspection working copies. The caller's renderer
	// has its own admission; this is only the durable-capture/read phase.
	release, err := j.admit(ctx, OriginalResourceRequestV1{OrgID: p.OrgID, DocumentID: p.DocumentID, PreparationID: p.ID, Kind: kind, Page: page, WorkingBytes: 4*n + 11*(1<<20), StagingBytes: staging})
	if err != nil || release == nil || ctx.Err() != nil {
		if release != nil {
			release()
		}
		return originalErrorV1(ctx, ErrOriginalResourcesV1)
	}
	lease.addRelease(release)
	return nil
}

func originalRollbackV1(tx *originalPostgresTransactionV1) error {
	if tx == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tx.Rollback(ctx)
}
func originalFinishV1(ctx context.Context, tx *originalPostgresTransactionV1, err *error) {
	if originalRollbackV1(tx) != nil {
		*err = originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	if ctx != nil && ctx.Err() != nil {
		*err = errors.Join(*err, originalErrorV1(ctx, ctx.Err()))
	}
}

// Project and validate the post-wait tuple, not the caller's old Get row. A
// current owner/lease permits capture, never a signature or a repeated upload.
func (j *SQLOriginalJournalV1) lock(ctx context.Context, tx *originalPostgresTransactionV1, p *generated.SignatureFitPreparation, write bool) error {
	v, err := tx.q.GetSignatureFitOriginalOperationForUpdate(ctx, generated.GetSignatureFitOriginalOperationForUpdateParams{PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID, OwnerID: p.OwnerID})
	if err != nil || v == nil || v.ID != p.ID || v.OrgID != p.OrgID || v.DocumentID != p.DocumentID || v.RecipientID != p.RecipientID ||
		!v.CeremonyEpoch.Valid || !p.CeremonyEpoch.Valid || !v.CeremonyEpoch.Time.Equal(p.CeremonyEpoch.Time) ||
		!bytes.Equal(v.AuthoritySha256, p.AuthoritySha256) || !bytes.Equal(v.SourceSha256, p.SourceSha256) ||
		!bytes.Equal(v.GeometrySha256, p.GeometrySha256) || !bytes.Equal(v.SpanSha256, p.SpanSha256) ||
		v.SourceStorageKey != p.SourceStorageKey || v.SourceVersionID != p.SourceVersionID || v.SourceBytes != p.SourceBytes ||
		v.ReservedBytes != p.ReservedBytes || v.ExpectedObjects != p.ExpectedObjects || v.OwnerID != p.OwnerID ||
		v.DocumentType != "pdf" || v.DocumentDeleted || !v.NoticeCommitted || !v.NoticeCurrent || !v.SourceCurrent ||
		!v.RequiresSignature || !v.EvidenceVersionPinsRequired || v.IsEnvelope || v.ParentEnvelopeID.Valid ||
		(v.Status != "staging" && v.Status != "prepared") || v.SelectionNotCommittedAt.Valid {
		return originalErrorV1(ctx, ErrIdentityV1)
	}
	if v.DocumentStatus != "sent" && v.DocumentStatus != "in_progress" && v.DocumentStatus != "finalizing" && v.DocumentStatus != "completed" {
		return ErrIdentityV1
	}
	if write && (v.Status != "staging" || !v.LeaseCurrent || v.SelectionCommitAttemptedAt.Valid ||
		(v.DocumentStatus != "sent" && v.DocumentStatus != "in_progress") ||
		(v.RecipientStatus != "pending" && v.RecipientStatus != "sent" && v.RecipientStatus != "viewed") ||
		(v.RecipientRole == "cc" || v.RecipientRole == "viewer")) {
		return originalErrorV1(ctx, ErrLeaseV1)
	}
	return nil
}

func originalAuthorityMetadataV1(m *generated.GetSignatureFitOriginalAuthorityMetadataRow, p *generated.SignatureFitPreparation) bool {
	if m == nil || m.PreparationID != p.ID || m.OrgID != p.OrgID || m.DocumentID != p.DocumentID || m.RecipientID != p.RecipientID ||
		!m.CeremonyEpoch.Valid || !m.CeremonyEpoch.Time.Equal(p.CeremonyEpoch.Time) || !bytes.Equal(m.AuthoritySha256, p.AuthoritySha256) ||
		m.AuthorityBytes < 1 || m.AuthorityBytes > manualfit.MaxAuthorityBytesV1 || len(m.OccupiedPages) < 1 || len(m.OccupiedPages) > 500 || len(m.OccupiedPages)+2 != int(p.ExpectedObjects) {
		return false
	}
	var previous int32
	for _, page := range m.OccupiedPages {
		if page <= previous || page > 500 {
			return false
		}
		previous = page
	}
	return true
}

// Reserve acknowledges one transaction containing the85 preparation, its full
// original authority, and original inert span. No output or object reservation
// exists before this commitment. Any failed commit stops the caller; a future
// fresh locked read reconciles the original ID instead of making a replacement.
func (j *SQLOriginalJournalV1) Reserve(ctx context.Context, arg generated.ReserveSignatureFitPreparationParams, a *manualfit.AuthorityV1, span []byte) (row *generated.SignatureFitPreparation, retErr error) {
	p := &generated.SignatureFitPreparation{ID: arg.ID, OrgID: arg.OrgID, DocumentID: arg.DocumentID, RecipientID: arg.RecipientID, OwnerID: arg.OwnerID}
	lease, err := j.admission(ctx, p)
	if err != nil {
		return nil, err
	}
	defer lease.releaseOwner()
	ctx = lease.context(ctx)
	if a == nil || len(span) < 1 || int64(len(span)) > manualfit.MaxSpanBytesV1 || !futureLeaseV1(arg.LeaseUntil.Time) {
		return nil, ErrOriginalPayloadV1
	}
	if err = j.bodyAdmission(ctx, lease, p, "authority_and_span", 0, manualfit.MaxAuthorityBytesV1+int64(len(span)), manualfit.MaxAuthorityBytesV1+int64(len(span))); err != nil {
		return nil, err
	}
	authority := a.CanonicalJSON()
	lease.ownBody(authority)
	originalSpan := bytes.Clone(span)
	lease.ownBody(originalSpan)
	decoded, err := manualfit.DecodeAuthorityV1(authority)
	if err != nil || decoded.SHA256() != a.SHA256() || digestV1(originalSpan) != a.Input().SpanSHA256 || manualfit.ValidateArchivedSpanV1(originalSpan, a.Input().TypedName, a.Input().Font) != nil {
		return nil, ErrIdentityV1
	}
	var tx *originalPostgresTransactionV1
	tx, err = j.sessions.Begin(ctx)
	if err != nil {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	defer originalFinishV1(ctx, tx, &retErr)
	row, err = tx.q.ReserveSignatureFitPreparation(ctx, arg)
	if err != nil {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	if !preparationEqualV1(row, arg.ID, decoded, arg.ReservedBytes) || row.OwnerID != arg.OwnerID {
		return nil, ErrIdentityV1
	}
	if err = j.lock(ctx, tx, row, true); err != nil {
		return nil, err
	}
	pages := make([]int32, 0, len(decoded.Pages()))
	for _, page := range decoded.Pages() {
		pages = append(pages, int32(page.Plan.Page))
	}
	m, err := tx.q.CaptureSignatureFitOriginalAuthority(ctx, generated.CaptureSignatureFitOriginalAuthorityParams{PreparationID: row.ID, OrgID: row.OrgID, DocumentID: row.DocumentID, RecipientID: row.RecipientID, OwnerID: row.OwnerID, CeremonyEpoch: row.CeremonyEpoch, AuthorityPayload: authority, AuthoritySha256: digestBytesV1(decoded.SHA256()), AuthorityBytes: int64(len(authority)), OccupiedPages: pages})
	if err != nil || !originalAuthorityMetadataV1((*generated.GetSignatureFitOriginalAuthorityMetadataRow)(m), row) {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	key, mime, _, _ := objectLayoutV1(ObjectIDV1{"span", 0}, manualfit.ObjectPrefixV1(row.ID, row.OrgID, row.DocumentID))
	if _, err = tx.q.CaptureSignatureFitOriginalPayload(ctx, generated.CaptureSignatureFitOriginalPayloadParams{PreparationID: row.ID, OrgID: row.OrgID, DocumentID: row.DocumentID, OwnerID: row.OwnerID, Kind: "span", Page: 0, StorageKey: key, Sha256: digestBytesV1(digestV1(originalSpan)), Bytes: int64(len(originalSpan)), ContentType: mime, Payload: originalSpan}); err != nil {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	return row, nil
}

func (j *SQLOriginalJournalV1) Authority(ctx context.Context, p *generated.SignatureFitPreparation) (result *OriginalAuthorityV1, retErr error) {
	lease, err := j.admission(ctx, p)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if retErr != nil {
			if result != nil {
				result.Close()
				result = nil
			}
			transferred = false
		}
		if !transferred {
			lease.releaseOwner()
		}
	}()
	ctx = lease.context(ctx)
	tx, err := j.sessions.Begin(ctx)
	if err != nil {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	defer originalFinishV1(ctx, tx, &retErr)
	if err = j.lock(ctx, tx, p, false); err != nil {
		return nil, err
	}
	m, err := tx.q.GetSignatureFitOriginalAuthorityMetadata(ctx, generated.GetSignatureFitOriginalAuthorityMetadataParams{PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID})
	if err != nil || !originalAuthorityMetadataV1(m, p) {
		return nil, originalErrorV1(ctx, ErrOriginalPayloadV1)
	}
	if err = j.bodyAdmission(ctx, lease, p, "authority", 0, m.AuthorityBytes, 0); err != nil {
		return nil, err
	}
	raw, err := tx.q.GetSignatureFitOriginalAuthorityBody(ctx, generated.GetSignatureFitOriginalAuthorityBodyParams{PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID, ExpectedSha256: m.AuthoritySha256, ExpectedBytes: m.AuthorityBytes})
	if len(raw) > 0 {
		lease.ownBody(raw)
	}
	if err != nil || int64(len(raw)) != m.AuthorityBytes || !bytes.Equal(digestBytesV1(digestV1(raw)), p.AuthoritySha256) {
		return nil, ErrIdentityV1
	}
	a, err := manualfit.DecodeAuthorityV1(raw)
	if err != nil || !preparationEqualV1(p, p.ID, a, p.ReservedBytes) {
		return nil, ErrIdentityV1
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	if ctx.Err() != nil {
		return nil, originalErrorV1(ctx, ctx.Err())
	}
	result = &OriginalAuthorityV1{authority: a, release: lease.releaseOwner}
	transferred = true
	return result, nil
}

func originalPayloadMetadataV1(m *generated.GetSignatureFitOriginalPayloadMetadataRow, p *generated.SignatureFitPreparation, id ObjectIDV1) bool {
	key, mime, limit, ok := objectLayoutV1(id, manualfit.ObjectPrefixV1(p.ID, p.OrgID, p.DocumentID))
	return ok && m != nil && m.PreparationID == p.ID && m.OrgID == p.OrgID && m.DocumentID == p.DocumentID && m.Kind == id.Kind && m.Page == id.Page &&
		m.StorageKey == key && m.ContentType == mime && m.Bytes > 0 && m.Bytes <= limit && len(m.Sha256) == 32 && !bytes.Equal(m.Sha256, make([]byte, 32))
}

func (j *SQLOriginalJournalV1) Capture(ctx context.Context, p *generated.SignatureFitPreparation, id ObjectIDV1, key, mime string, raw []byte) (retErr error) {
	lease, err := j.admission(ctx, p)
	if err != nil {
		return err
	}
	defer lease.releaseOwner()
	ctx = lease.context(ctx)
	wantKey, wantMime, limit, ok := objectLayoutV1(id, manualfit.ObjectPrefixV1(p.ID, p.OrgID, p.DocumentID))
	if !ok || key != wantKey || mime != wantMime || len(raw) < 1 || int64(len(raw)) > limit {
		return ErrIdentityV1
	}
	tx, err := j.sessions.Begin(ctx)
	if err != nil {
		return originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	defer originalFinishV1(ctx, tx, &retErr)
	if err = j.lock(ctx, tx, p, true); err != nil {
		return err
	}
	m, err := tx.q.GetSignatureFitOriginalPayloadMetadata(ctx, generated.GetSignatureFitOriginalPayloadMetadataParams{PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID, Kind: id.Kind, Page: id.Page})
	if err == nil {
		if !originalPayloadMetadataV1(m, p, id) || m.Bytes != int64(len(raw)) || !bytes.Equal(m.Sha256, digestBytesV1(digestV1(raw))) {
			return ErrOriginalPayloadV1
		}
		if err = tx.Commit(ctx); err != nil {
			return originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	if err = j.bodyAdmission(ctx, lease, p, id.Kind, id.Page, int64(len(raw)), int64(len(raw))); err != nil {
		return err
	}
	original := bytes.Clone(raw)
	lease.ownBody(original)
	captured, err := tx.q.CaptureSignatureFitOriginalPayload(ctx, generated.CaptureSignatureFitOriginalPayloadParams{PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID, OwnerID: p.OwnerID, Kind: id.Kind, Page: id.Page, StorageKey: key, Sha256: digestBytesV1(digestV1(original)), Bytes: int64(len(original)), ContentType: mime, Payload: original})
	if err != nil || !originalPayloadMetadataV1((*generated.GetSignatureFitOriginalPayloadMetadataRow)(captured), p, id) {
		return originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	if err = tx.Commit(ctx); err != nil {
		return originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	return nil
}

func (j *SQLOriginalJournalV1) Load(ctx context.Context, p *generated.SignatureFitPreparation, id ObjectIDV1) (result *OriginalPayloadV1, retErr error) {
	lease, err := j.admission(ctx, p)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if retErr != nil {
			if result != nil {
				result.Close()
				result = nil
			}
			transferred = false
		}
		if !transferred {
			lease.releaseOwner()
		}
	}()
	ctx = lease.context(ctx)
	if _, _, _, ok := objectLayoutV1(id, manualfit.ObjectPrefixV1(p.ID, p.OrgID, p.DocumentID)); !ok {
		return nil, ErrIdentityV1
	}
	tx, err := j.sessions.Begin(ctx)
	if err != nil {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	defer originalFinishV1(ctx, tx, &retErr)
	if err = j.lock(ctx, tx, p, false); err != nil {
		return nil, err
	}
	h, err := tx.q.GetSignatureFitOriginalAuthorityMetadata(ctx, generated.GetSignatureFitOriginalAuthorityMetadataParams{PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID})
	if err != nil || !originalAuthorityMetadataV1(h, p) {
		return nil, ErrOriginalPayloadV1
	}
	if id.Kind == "page" {
		member := false
		for _, page := range h.OccupiedPages {
			if page == id.Page {
				member = true
				break
			}
		}
		if !member {
			return nil, ErrIdentityV1
		}
	}
	m, err := tx.q.GetSignatureFitOriginalPayloadMetadata(ctx, generated.GetSignatureFitOriginalPayloadMetadataParams{PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID, Kind: id.Kind, Page: id.Page})
	if errors.Is(err, pgx.ErrNoRows) {
		// Only a successfully rolled back and physically retired fresh locked read
		// can expose this negative. Uncertain cleanup converts it to SQLUnknown.
		if err = originalRollbackV1(tx); err != nil {
			return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
		}
		return nil, pgx.ErrNoRows
	}
	if err != nil || !originalPayloadMetadataV1(m, p, id) {
		return nil, originalErrorV1(ctx, ErrOriginalPayloadV1)
	}
	if err = j.bodyAdmission(ctx, lease, p, id.Kind, id.Page, m.Bytes, 0); err != nil {
		return nil, err
	}
	raw, err := tx.q.GetSignatureFitOriginalPayloadBody(ctx, generated.GetSignatureFitOriginalPayloadBodyParams{PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID, Kind: id.Kind, Page: id.Page, ExpectedSha256: m.Sha256, ExpectedBytes: m.Bytes})
	if len(raw) > 0 {
		lease.ownBody(raw)
	}
	if err != nil || int64(len(raw)) != m.Bytes || !bytes.Equal(digestBytesV1(digestV1(raw)), m.Sha256) {
		return nil, ErrIdentityV1
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	if ctx.Err() != nil {
		return nil, originalErrorV1(ctx, ctx.Err())
	}
	result = &OriginalPayloadV1{body: raw, release: lease.releaseOwner}
	transferred = true
	return result, nil
}

var _ OriginalJournalV1 = (*SQLOriginalJournalV1)(nil)
