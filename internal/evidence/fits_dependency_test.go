// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
)

type fitsCommitmentFixture func(context.Context, uuid.UUID, uuid.UUID) (manualfit.CommittedFitsIndexV1, error)

func (f fitsCommitmentFixture) LoadCommittedFitsIndexV1(ctx context.Context, orgID, docID uuid.UUID) (manualfit.CommittedFitsIndexV1, error) {
	return f(ctx, orgID, docID)
}

type fitsArtifactReadTrap struct {
	*evidenceBlobStoreStub
	reads int
}

func (s *fitsArtifactReadTrap) GetVerifiedVersion(context.Context, string, string, []byte) ([]byte, error) {
	s.reads++
	return nil, errors.New("artifact read reached before index dependency was validated")
}

func TestBuildRefusesFitsIndexDependencyMismatchBeforeStorage(t *testing.T) {
	for _, fixture := range []struct {
		name          string
		docRequired   bool
		readerPresent bool
		pinRequired   bool
	}{
		{"missing-required-reader", true, false, false},
		{"required-reader-returns-historical", true, true, false},
		{"historical-reader-returns-required", false, true, true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			doc, builder, queries, versions := evidenceBuildFixture(t)
			doc.FitsIndexRequired = fixture.docRequired
			trap := &fitsArtifactReadTrap{evidenceBlobStoreStub: builder.Storage.(*evidenceBlobStoreStub)}
			builder.Storage = trap
			if fixture.readerPresent {
				builder.FitsIndexCommitments = fitsCommitmentFixture(func(_ context.Context, orgID, docID uuid.UUID) (manualfit.CommittedFitsIndexV1, error) {
					if orgID != doc.OrgID || docID != doc.ID {
						t.Fatal("index lookup lost its document or organization scope")
					}
					pin := manualfit.CommittedFitsIndexV1{Required: fixture.pinRequired}
					if pin.Required {
						pin.Object = manualfit.ObjectPinV1{Key: "org/fixture/index.json", VersionID: "fixture-version", SHA256: strings.Repeat("a", 64), Bytes: 1, ContentType: "application/json"}
					}
					return pin, nil
				})
			}
			result, err := builder.Build(context.Background(), doc)
			if result != nil || !errors.Is(err, ErrArtifactIntegrity) {
				t.Fatalf("dependency mismatch must refuse export: result=%v error=%v", result != nil, err)
			}
			if trap.reads != 0 || queries.eventLimit != 0 || versions.historyLimit != 0 {
				t.Fatal("dependency mismatch performed artifact or history work")
			}
		})
	}
}
