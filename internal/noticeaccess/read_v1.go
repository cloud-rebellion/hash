// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package noticeaccess

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const snapshotSQLV1 = `SELECT cap.id,cap.org_id,cap.notice_id,cap.token_sha256,cap.file_commitment_sha256,cap.expires_at,
 n.notice_sha256,n.notice_bytes,n.subject,n.text_body,n.issued_at,n.retain_until,a.id,a.original_document_id,a.document_id,a.file_set
 FROM document_amendment_notice_access_v1 cap
 JOIN document_amendment_notices_v1 n ON n.id=cap.notice_id AND n.org_id=cap.org_id
 JOIN document_amendments_v1 a ON a.id=n.amendment_id AND a.org_id=n.org_id
 JOIN document_amendment_notice_deliveries_v1 d ON d.notice_id=n.id AND d.org_id=n.org_id AND d.email_delivery_id=cap.email_delivery_id AND d.recipient_email=cap.recipient_email
 JOIN email_deliveries mail ON mail.id=d.email_delivery_id AND mail.to_email=d.recipient_email
 JOIN documents original ON original.id=a.original_document_id AND original.org_id=a.org_id AND original.deleted_at IS NULL AND original.status='completed'
 JOIN documents candidate ON candidate.id=a.document_id AND candidate.org_id=a.org_id AND candidate.deleted_at IS NULL
 WHERE cap.notice_id=$1 AND cap.token_sha256=$2 AND ($3::uuid IS NULL OR cap.id=$3)
 AND cap.revoked_at IS NULL AND cap.expires_at>clock_timestamp() AND cap.expires_at<=n.retain_until
 AND cap.file_commitment_sha256=n.file_commitment_sha256 AND n.file_commitment_sha256=a.file_commitment_sha256
 AND octet_length(a.file_set)<=65536 AND octet_length(n.notice_bytes)<=32768
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(convert_from(a.file_set,'UTF8')::jsonb->'files') f
 LEFT JOIN documents df ON df.id=(f->>'document_id')::uuid AND df.org_id=a.org_id WHERE df.id IS NULL OR df.deleted_at IS NOT NULL)`

type snapshotV1 struct {
	access, org, notice, amendment, original, document uuid.UUID
	tokenSHA, fileSHA, noticeSHA                       [32]byte
	expires, issued, retainUntil                       time.Time
	files                                              amendments.FileSetV1
	public                                             PublicV1
	grant                                              *workguard.GrantV1
}

func (s *snapshotV1) closeV1() {
	if s != nil {
		if s.grant != nil {
			s.grant.Close()
			s.grant = nil
		}
		s.files = amendments.FileSetV1{}
		s.public = PublicV1{}
	}
}
func (e *EngineV1) lookupV1(ctx context.Context, notice uuid.UUID, tokenSHA [32]byte, access *uuid.UUID) (out *snapshotV1, failure error) {
	if e == nil || e.pool == nil || e.work == nil || ctx == nil || notice == uuid.Nil || tokenSHA == ([32]byte{}) {
		return nil, ErrDeniedV1
	}
	grant, err := e.work.TryAcquireProcessV1(ctx, workguard.VectorV1{ParentBytes: 512 << 10})
	if err != nil {
		return nil, ErrUnavailableV1
	}
	out = &snapshotV1{grant: grant}
	defer func() {
		if failure != nil {
			out.closeV1()
			out = nil
		}
	}()
	sqlGrant, err := e.work.TryAcquireProcessV1(ctx, workguard.VectorV1{ParentBytes: 16 << 10, DBStagingBytes: 256 << 10, SQLSessions: 1})
	if err != nil {
		return out, ErrUnavailableV1
	}
	defer sqlGrant.Close()
	conn, err := e.pool.Acquire(ctx)
	if err != nil {
		return out, ErrUnavailableV1
	}
	defer conn.Release()
	var token, fileSum, noticeSum, rawFiles, rawNotice []byte
	var subject, text string
	err = conn.QueryRow(ctx, snapshotSQLV1, notice, tokenSHA[:], access).Scan(&out.access, &out.org, &out.notice, &token, &fileSum, &out.expires, &noticeSum, &rawNotice, &subject, &text, &out.issued, &out.retainUntil, &out.amendment, &out.original, &out.document, &rawFiles)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrDeniedV1
	}
	if err != nil {
		return out, ErrUnavailableV1
	}
	defer clear(rawFiles)
	defer clear(rawNotice)
	defer clear(token)
	if len(token) != 32 || len(fileSum) != 32 || len(noticeSum) != 32 || subtle.ConstantTimeCompare(token, tokenSHA[:]) != 1 || out.org == uuid.Nil || out.notice != notice || out.original == uuid.Nil || out.document == uuid.Nil || out.issued.Year() < 2000 || out.issued.Year() > 9999 || out.expires.Year() > 9999 || !out.expires.After(time.Now()) || out.expires.After(out.retainUntil) {
		return out, ErrDeniedV1
	}
	copy(out.tokenSHA[:], token)
	copy(out.fileSHA[:], fileSum)
	copy(out.noticeSHA[:], noticeSum)
	if domainHashV1("hash:later-amendment-notice:v1", rawNotice) != out.noticeSHA {
		return out, ErrUnavailableV1
	}
	var issued amendments.IssueNoticeV1
	decoder := json.NewDecoder(bytes.NewReader(rawNotice))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&issued) != nil || decoder.Decode(new(any)) != io.EOF || issued.ValidateV1() != nil || issued.Subject != subject || issued.Text != text {
		return out, ErrUnavailableV1
	}
	out.files, err = DecodeFilesV1(rawFiles, out.fileSHA)
	if err != nil || out.files.DocumentID != out.document {
		return out, ErrUnavailableV1
	}
	out.public = PublicV1{Schema: SchemaV1, NoticeID: out.notice, OriginalDocumentID: out.original, DocumentID: out.document, Subject: subject, Text: text, IssuedAt: out.issued.UTC(), ExpiresAt: out.expires.UTC(), FileCommitmentSHA256: hex.EncodeToString(out.fileSHA[:]), Files: make([]PublicFileV1, len(out.files.Files))}
	for i, f := range out.files.Files {
		out.public.Files[i] = PublicFileV1{Position: f.Position, Title: f.Title, PDFSHA256: f.SHA256, PDFBytes: f.Bytes, PDFPages: f.Pages, FileVersionSHA256: FileVersionSHA256V1(f)}
	}
	return out, nil
}

// The final SQL SHARE lock is acquired AFTER all provider IO has retired. It
// serializes the actual response writer with one-way revocation. A revoke
// cannot acknowledge before an already-admitted bounded writer has joined.
func (e *EngineV1) withReadGuardV1(ctx context.Context, s *snapshotV1, consume func(context.Context) error) error {
	if s == nil || consume == nil {
		return ErrDeniedV1
	}
	grant, err := e.work.TryAcquireV1(ctx, s.org, workguard.VectorV1{ParentBytes: 16 << 10, DBStagingBytes: 16 << 10, SQLSessions: 1})
	if err != nil {
		return ErrUnavailableV1
	}
	defer grant.Close()
	conn, err := e.pool.Acquire(ctx)
	if err != nil {
		return ErrUnavailableV1
	}
	defer conn.Release()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ErrUnavailableV1
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	// Freeze every native subject in stable order before the capability lock.
	ids := []uuid.UUID{s.original}
	seen := map[uuid.UUID]bool{s.original: true}
	for _, f := range s.files.Files {
		if !seen[f.DocumentID] {
			ids = append(ids, f.DocumentID)
			seen[f.DocumentID] = true
		}
	}
	rows, err := tx.Query(ctx, `SELECT id FROM documents WHERE org_id=$1 AND id=ANY($2::uuid[]) AND deleted_at IS NULL ORDER BY id FOR SHARE`, s.org, ids)
	if err != nil {
		return ErrUnavailableV1
	}
	count := 0
	for rows.Next() {
		var id uuid.UUID
		if rows.Scan(&id) != nil {
			rows.Close()
			return ErrUnavailableV1
		}
		count++
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return ErrUnavailableV1
	}
	if count != len(ids) {
		return ErrDeniedV1
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `SELECT cap.id FROM document_amendment_notice_access_v1 cap
 JOIN document_amendment_notices_v1 n ON n.id=cap.notice_id AND n.org_id=cap.org_id
 JOIN document_amendments_v1 a ON a.id=n.amendment_id AND a.org_id=n.org_id
 WHERE cap.id=$1 AND cap.org_id=$2 AND cap.notice_id=$3 AND cap.token_sha256=$4 AND cap.file_commitment_sha256=$5
 AND n.notice_sha256=$6 AND a.file_commitment_sha256=$5 AND n.file_commitment_sha256=$5
 AND cap.revoked_at IS NULL AND cap.expires_at=$7 AND cap.expires_at>clock_timestamp()
 AND EXISTS(SELECT 1 FROM documents x WHERE x.id=a.original_document_id AND x.org_id=cap.org_id AND x.deleted_at IS NULL AND x.status='completed')
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(convert_from(a.file_set,'UTF8')::jsonb->'files') f LEFT JOIN documents d ON d.id=(f->>'document_id')::uuid AND d.org_id=a.org_id WHERE d.id IS NULL OR d.deleted_at IS NOT NULL)
 FOR SHARE OF cap`, s.access, s.org, s.notice, s.tokenSHA[:], s.fileSHA[:], s.noticeSHA[:], s.expires).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDeniedV1
	}
	if err != nil {
		return ErrUnavailableV1
	}
	until, cancel := context.WithDeadline(ctx, s.expires)
	defer cancel()
	if err := until.Err(); err != nil {
		return ErrDeniedV1
	}
	if err := consume(until); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RevokeV1 is called only inside the native owner's fresh authenticated
// transaction. DB role+tenant and one-way trigger independently enforce owner
// authority. Exact repeats return the original timestamp without a new update.
func RevokeV1(ctx context.Context, tx pgx.Tx, org, notice, access, actor uuid.UUID) (time.Time, bool, error) {
	if tx == nil || org == uuid.Nil || notice == uuid.Nil || access == uuid.Nil || actor == uuid.Nil {
		return time.Time{}, false, ErrDeniedV1
	}
	var role string
	if tx.QueryRow(ctx, `SELECT role FROM users WHERE id=$1 AND org_id=$2 FOR SHARE`, actor, org).Scan(&role) != nil || role != "owner" {
		return time.Time{}, false, ErrDeniedV1
	}
	var revoked *time.Time
	err := tx.QueryRow(ctx, `SELECT revoked_at FROM document_amendment_notice_access_v1 WHERE id=$1 AND notice_id=$2 AND org_id=$3 FOR UPDATE`, access, notice, org).Scan(&revoked)
	if err != nil {
		return time.Time{}, false, ErrDeniedV1
	}
	if revoked != nil {
		return *revoked, false, nil
	}
	var at time.Time
	err = tx.QueryRow(ctx, `UPDATE document_amendment_notice_access_v1 SET revoked_at=clock_timestamp(),revoked_by=$4 WHERE id=$1 AND notice_id=$2 AND org_id=$3 AND revoked_at IS NULL RETURNING revoked_at`, access, notice, org, actor).Scan(&at)
	if err != nil {
		return time.Time{}, false, ErrUnavailableV1
	}
	return at, true, nil
}
