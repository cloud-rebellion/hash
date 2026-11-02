// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

var ErrCanonicalCollabObservationV1 = errors.New("canonical document observation changed")

// A replay loan belongs to this exact genuine locked-source writer. The room
// supplies its actual replay length under its own mutex BEFORE making a copy.
// This is data-lifetime credit, never actor/checkpoint/transaction authority.
type ApplicationCanonicalCollabReplayLoanV1 struct {
	writer *ApplicationPlainDraftMutationWriterV1
	bytes  int
	used   bool
}

func (w *ApplicationPlainDraftMutationWriterV1) AdmitCanonicalCollabReplayV1(ctx context.Context, bytes int) (*ApplicationCanonicalCollabReplayLoanV1, error) {
	if w == nil || w.state == nil || bytes < 0 || bytes > 8<<20 {
		return nil, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.attempted || s.snapshot.document.SourceKind != "blocks" {
		return nil, ErrBlocksWriterV1
	}
	// Fixed replay/parameter containers remain positive for an empty replay.
	// Feed actual replay raw/bytea-wire lengths into the existing native body
	// resource calculator, which prices their conservative working/DB credit.
	// This is logical staging credit, not a physical heap/RSS promise.
	raw := int64(bytes) + 2*int64(unsafe.Sizeof(generated.SaveCanonicalCollabParams{})) + 2*int64(unsafe.Sizeof(ApplicationCanonicalCollabReplayLoanV1{})) + 512
	if err := s.sourceWork.holdV1(ctx, raw, int64(bytes)); err != nil {
		return nil, err
	}
	return &ApplicationCanonicalCollabReplayLoanV1{writer: w, bytes: bytes}, nil
}

// SaveCanonicalCollabV1 uses the original M70 single canonical/generation/replay
// SQL continuation, on this reader's private source and native DBTX. Caller
// snapshots, external transactions or missing measurement caches cannot enter.
func (w *ApplicationPlainDraftMutationWriterV1) SaveCanonicalCollabV1(ctx context.Context, loan *ApplicationCanonicalCollabReplayLoanV1, generation int64, replay []byte, updates int, user uuid.UUID, raw json.RawMessage) (*generated.Document, error) {
	if w == nil || w.state == nil || loan == nil || loan.writer != w || generation <= 0 || generation == math.MaxInt64 || replay == nil || len(replay) != loan.bytes || updates < 0 || updates > 65536 || user == uuid.Nil {
		return nil, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.attempted || loan.used || s.snapshot.document.SourceKind != "blocks" {
		return nil, ErrBlocksWriterV1
	}
	s.attempted, loan.used = true, true
	old := s.snapshot.document
	if err := (&ApplicationBlocksCreationWriterV1{state: s.sourceWork}).PrepareSourceV1(ctx, raw, old.VariablesJson); err != nil {
		return nil, err
	}
	blocks := s.sourceWork.blocks
	if err := s.fundPlainReturnV1(ctx, old, int64(len(blocks))); err != nil {
		return nil, err
	}
	if err := s.sourceWork.holdV1(ctx, 0, s.sourceWork.blocksWire+int64(len(old.VariablesJson))); err != nil {
		return nil, err
	}
	accepted, err := s.sourceWork.queries.SaveCanonicalCollab(ctx, generated.SaveCanonicalCollabParams{
		DocumentID: old.ID, OrgID: old.OrgID, Generation: generation, ExpectedUpdatedAt: old.UpdatedAt,
		BlocksJson: blocks, YdocState: replay, UpdateCount: int32(updates), UserID: user,
	})
	if err != nil {
		return nil, err
	}
	if !accepted {
		return nil, ErrCanonicalCollabObservationV1
	}
	row, err := s.sourceWork.queries.GetDocument(ctx, generated.GetDocumentParams{ID: old.ID, OrgID: old.OrgID})
	if err != nil {
		return nil, err
	}
	if row == nil || !applicationStampV1(row.UpdatedAt) || int64(len(row.BlocksJson)) > s.sourceWork.blocksWire {
		return nil, ErrBlocksWriterV1
	}
	expected := *old
	expected.BlocksJson = row.BlocksJson
	expected.UpdatedAt = row.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&expected, row) {
		return nil, ErrBlocksWriterV1
	}
	if err = s.retainPlainRowV1(row); err != nil {
		return nil, err
	}
	s.sourceWritten = true
	s.blocksWire = s.sourceWork.blocksWire
	s.variablesWire = int64(len(old.VariablesJson))
	return row, nil
}
