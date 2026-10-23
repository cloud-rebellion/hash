// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package noticeaccess

import (
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"time"
)

const SchemaV1 = "hash-amendment-notice-access-v1"
const MaxFilesV1 = 17
const MaxFileBytesV1 int64 = 50 << 20
const MaxTotalFileBytesV1 int64 = 50 << 20
const MaxTotalPagesV1 int64 = 500
const MaxFileSetBytesV1 = 64 << 10
const TokenLengthV1 = 47 // hn1. plus43 strict unpadded base64url characters
const AccessTTL = 7 * 24 * time.Hour

// Native-only immutable input after the first fresh locked read; never decoded
// from a staff/public request. FileSetBytes are the EXACT persisted bytes.
type InputV1 struct {
	OrgID, NoticeID, AmendmentID, OriginalDocumentID, DocumentID, IssuedBy uuid.UUID
	NoticeSHA256, FileCommitmentSHA256                                     [32]byte
	FileSetBytes                                                           []byte
	FileSet                                                                amendments.FileSetV1
	Subject, Text, ReplyTo, FromName                                       string
	RecipientEmails                                                        []string
	IssuedAt, RetainUntil                                                  time.Time
}

// DeliveryV1 may be borrowed only for synchronous transactional writes. Do not
// retain Message or expose it in evidence/logs; its entrypoint is a capability.
// Insert capability + this exact email ID + delivery ref in ONE transaction.
type DeliveryV1 struct {
	AccessID, EmailDeliveryID                        uuid.UUID
	OrgID, NoticeID                                  uuid.UUID
	RecipientEmail                                   string
	TokenSHA256, FileCommitmentSHA256, MessageSHA256 [32]byte
	CreatedAt, ExpiresAt                             time.Time
	Message                                          dispatch.Message
}
type PublicFileV1 struct {
	Position          int16  `json:"position"`
	Title             string `json:"title"`
	PDFSHA256         string `json:"pdf_sha256"`
	PDFBytes          int64  `json:"pdf_bytes"`
	PDFPages          int32  `json:"pdf_pages"`
	FileVersionSHA256 string `json:"file_version_sha256"`
}
type PublicV1 struct {
	Schema               string         `json:"schema"`
	NoticeID             uuid.UUID      `json:"notice_id"`
	OriginalDocumentID   uuid.UUID      `json:"original_document_id"`
	DocumentID           uuid.UUID      `json:"document_id"`
	Subject              string         `json:"subject"`
	Text                 string         `json:"text"`
	IssuedAt             time.Time      `json:"issued_at"`
	ExpiresAt            time.Time      `json:"expires_at"`
	FileCommitmentSHA256 string         `json:"file_commitment_sha256"`
	Files                []PublicFileV1 `json:"files"`
}

// Neither an access exchange, a read, a download nor SMTP acceptance is a
// signature, identity verification, acknowledgement, delivery receipt or legal
// effectiveness decision. Public DTO intentionally has no such fields.
