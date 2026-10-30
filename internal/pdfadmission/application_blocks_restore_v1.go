// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"math"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrBlocksRestoreSourceV1 = errors.New("pdfadmission: historical block version cannot be read within its owned source bound")
var ErrBlocksRestoreKindV1 = errors.New("target version is not block-source")
var ErrBlocksRestoreVersionNotFoundV1 = errors.New("version not found")

// RestoreVersionV1 reads only this genuine writer's historical document scope.
// The locked scalar header contains no expanded JSON. Its storage-size proof
// follows the existing PG16.15/UTF8 uncompressed JSONB bound, not maintenance
// authority or cache repair. Compressed/unsupported sources fail before body IO.
// The original and returned version remain charged through consumer retirement.
func (w *ApplicationBlocksMutationWriterV1) RestoreVersionV1(ctx context.Context, version int32) (*generated.Document, string, error) {
	if w == nil || w.state == nil || version < 1 {
		return nil, "", ErrBlocksRestoreSourceV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.attempted {
		return nil, "", ErrBlocksRestoreSourceV1
	}
	s.attempted = true
	old := s.snapshot.document
	// This actual reader's existing fixed header class precedes the metadata
	// query. No caller row, bytes, size declaration or transaction is adopted.
	db := &applicationOwnedDBTXV1{session: s.session.state}
	var id uuid.UUID
	var created pgtype.Timestamptz
	var kind string
	var nameBytes, blockStored, variableStored int64
	var blocksPlain, variablesPlain, utf8 bool
	var plainOrigin bool
	var server, schemaVersion int32
	err := db.QueryRow(ctx, `SELECT v.id,v.created_at,v.schema_version,(v.html_source_json IS NULL AND v.html_materialization_id IS NULL),
 CASE WHEN octet_length(v.source_kind)<=6 THEN v.source_kind ELSE '' END,
 octet_length(v.name)::bigint,coalesce(pg_column_size(v.block_tree_json),-1)::bigint,
 coalesce(pg_column_size(v.variables_json),-1)::bigint,
 pg_column_compression(v.block_tree_json) IS NULL,pg_column_compression(v.variables_json) IS NULL,
 current_setting('server_version_num')::integer,current_setting('server_encoding')='UTF8'
 FROM document_versions v WHERE v.document_id=$1 AND v.org_id=$2 AND v.version_no=$3
	 FOR SHARE OF v`, old.ID, old.OrgID, version).Scan(&id, &created, &schemaVersion, &plainOrigin, &kind, &nameBytes, &blockStored, &variableStored, &blocksPlain, &variablesPlain, &server, &utf8)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrBlocksRestoreVersionNotFoundV1
	}
	if err != nil {
		return nil, "", err
	}
	if kind != "blocks" {
		return nil, "", ErrBlocksRestoreKindV1
	}
	if id == uuid.Nil || !applicationStampV1(created) || schemaVersion != 1 || !plainOrigin || nameBytes < 1 || server != 160015 || !utf8 || !blocksPlain || !variablesPlain {
		return nil, "", ErrBlocksRestoreSourceV1
	}
	blockUpper, err := blocksRestoreJSONBWireUpperV1(blockStored)
	if err != nil {
		return nil, "", err
	}
	variableUpper, err := blocksRestoreJSONBWireUpperV1(variableStored)
	if err != nil {
		return nil, "", err
	}
	wire, err := htmlAuthoringSumV1(blockUpper, variableUpper)
	if err != nil {
		return nil, "", err
	}
	if err := s.sourceWork.holdV1(ctx, nameBytes, wire); err != nil {
		return nil, "", err
	}
	target := &generated.DocumentVersion{ID: id, DocumentID: old.ID, OrgID: old.OrgID, VersionNo: version, CreatedAt: created, SourceKind: kind, SchemaVersion: schemaVersion}
	// Retain the same target row lock and exact scope/physical-size predicates.
	// HTML bodies, summary strings and unrelated historical fields are omitted.
	err = db.QueryRow(ctx, `SELECT name,block_tree_json,variables_json FROM document_versions
 WHERE id=$1 AND document_id=$2 AND org_id=$3 AND version_no=$4 AND created_at=$5
	 AND source_kind='blocks' AND schema_version=1 AND html_source_json IS NULL AND html_materialization_id IS NULL AND octet_length(name)=$6
 AND pg_column_compression(block_tree_json) IS NULL AND pg_column_compression(variables_json) IS NULL
 AND pg_column_size(block_tree_json)=$7 AND pg_column_size(variables_json)=$8`,
		id, old.ID, old.OrgID, version, created, nameBytes, blockStored, variableStored).Scan(&target.Name, &target.BlockTreeJson, &target.VariablesJson)
	if err != nil {
		return nil, "", err
	}
	if int64(len(target.Name)) != nameBytes || len(target.BlockTreeJson) == 0 || int64(len(target.BlockTreeJson)) > blockUpper || len(target.VariablesJson) == 0 || int64(len(target.VariablesJson)) > variableUpper {
		return nil, "", ErrBlocksRestoreSourceV1
	}
	s.restoreTarget = target
	// Reuse the native edit parser/decimal admission without normalizing or
	// rewriting historical bytes. Both inputs are funded before decoding.
	work := s.sourceWork
	rawWork, err := plainSendBlockLexicalWorkV1(ctx, target.BlockTreeJson)
	if err != nil {
		return nil, "", err
	}
	variableWork, err := plainSendBlockLexicalWorkV1(ctx, target.VariablesJson)
	if err != nil {
		return nil, "", err
	}
	if !htmlInputAddV1(&rawWork, variableWork, 4) {
		return nil, "", ErrBlocksRestoreSourceV1
	}
	if err := work.holdV1(ctx, rawWork, 0); err != nil {
		return nil, "", err
	}
	work.processing = true
	defer func() { work.processing = false }()
	admission := blocksCreationDecimalAdmissionV1{state: work, ctx: ctx}
	tree, err := blocks.ParseTreeForAuthoringV1(ctx, target.BlockTreeJson, admission)
	if work.admissionFailure != nil {
		return nil, "", work.admissionFailure
	}
	if err != nil {
		return nil, "", err
	}
	if err := blocks.ValidateForSendV1(tree, admission); err != nil {
		return nil, "", err
	}
	if _, err := blocks.ParseVariableValues(target.VariablesJson); err != nil {
		return nil, "", err
	}
	doc, err := s.writePlainSourceV1(ctx, old, target.BlockTreeJson, target.VariablesJson, int64(len(target.BlockTreeJson)), int64(len(target.VariablesJson)))
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(doc.BlocksJson, target.BlockTreeJson) || !bytes.Equal(doc.VariablesJson, target.VariablesJson) {
		return nil, "", ErrBlocksRestoreSourceV1
	}
	return doc, target.Name, nil
}

// For uncompressed direct stored JSONB on PG16.15/UTF8, L bounds flat bytes,
// JEntries <= floor(L/4), and each numeric's text is at most147457 bytes.
// This is the existing eidas_rule_sizes.sql/plan_source_sizes.sql size proof.
func blocksRestoreJSONBWireUpperV1(stored int64) (int64, error) {
	if stored < 1 || stored > math.MaxInt64-4 {
		return 0, ErrBlocksRestoreSourceV1
	}
	flat, total := stored+4, int64(2)
	if !htmlInputAddV1(&total, flat, 6) || !htmlInputAddV1(&total, flat/4, 147465) {
		return 0, ErrBlocksRestoreSourceV1
	}
	return total, nil
}
