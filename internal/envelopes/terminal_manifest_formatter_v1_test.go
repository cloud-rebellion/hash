// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package envelopes

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"reflect"
	"testing"
)

// Pure formatter/digest compatibility only; these test-created rows/hash
// strings are never native source, SQL, publication or resource authority.
func TestTerminalManifestSnapshotFormatterPreservesOriginalBytesV1(t *testing.T) {
	root := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Name: `Envelope <&>`, IsEnvelope: true, Status: "finalizing"}
	child := func(name string, position int32) *generated.Document {
		return &generated.Document{ID: uuid.New(), OrgID: root.OrgID, Name: name, Status: "finalizing", SourceKind: "blocks", ParentEnvelopeID: pgtype.UUID{Bytes: root.ID, Valid: true}, EnvelopePosition: pgtype.Int4{Int32: position, Valid: true}, BlocksJson: []byte(`{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Frozen <&> {{amount}}"}]}`), VariablesJson: []byte(`{"amount":"200"}`)}
	}
	children := []*generated.Document{child("First | <&>\nchild", 2), child("Second", 3)}
	original, err := BuildTerminalManifest(root, children)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := make([]string, len(children))
	for i, child := range children {
		snapshots[i] = FrozenContentSnapshotDigestV1(child)
	}
	actual, err := BuildTerminalManifestFromSnapshotsV1(root, children, snapshots)
	if err != nil || !reflect.DeepEqual(actual, original) || actual.HTMLSection() != original.HTMLSection() {
		t.Fatal("original canonical digest/manifest/HTML bytes changed", err)
	}
	badFirst, badSecond := *children[0], *children[1]
	badFirst.SourceKind = "pdf"
	badSecond.ParentEnvelopeID = pgtype.UUID{}
	bad := []*generated.Document{&badFirst, &badSecond}
	_, oldErr := BuildTerminalManifest(root, bad)
	_, newErr := BuildTerminalManifestFromSnapshotsV1(root, bad, snapshots)
	if oldErr == nil || newErr == nil || oldErr.Error() != newErr.Error() {
		t.Fatal("topology gate moved after first child parse/digest", oldErr, newErr)
	}
}
