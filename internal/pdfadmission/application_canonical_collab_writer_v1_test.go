package pdfadmission

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestCanonicalCollabReplayRequiresGenuineWriterAndSameLoan(t *testing.T) {
	ctx := context.Background()
	for _, writer := range []*ApplicationPlainDraftMutationWriterV1{nil, {}, {state: &applicationBlocksMutationStateV1{}}} {
		if loan, err := writer.AdmitCanonicalCollabReplayV1(ctx, 0); loan != nil || !errors.Is(err, ErrBlocksWriterV1) {
			t.Fatal("fabricated or missing writer minted replay credit")
		}
		if row, err := writer.SaveCanonicalCollabV1(ctx, &ApplicationCanonicalCollabReplayLoanV1{}, 1, []byte{}, 0, uuid.New(), nil); row != nil || !errors.Is(err, ErrBlocksWriterV1) {
			t.Fatal("fabricated writer or loan dispatched canonical write")
		}
	}
	writer := &ApplicationPlainDraftMutationWriterV1{state: &applicationBlocksMutationStateV1{}}
	other := &ApplicationPlainDraftMutationWriterV1{state: &applicationBlocksMutationStateV1{}}
	for _, loan := range []*ApplicationCanonicalCollabReplayLoanV1{nil, {writer: other}, {writer: writer, bytes: 1}, {writer: writer, bytes: 0, used: true}} {
		if row, err := writer.SaveCanonicalCollabV1(ctx, loan, 1, []byte{}, 0, uuid.New(), nil); row != nil || !errors.Is(err, ErrBlocksWriterV1) {
			t.Fatal("foreign/size-mismatched/used loan dispatched canonical SQL")
		}
	}
}
