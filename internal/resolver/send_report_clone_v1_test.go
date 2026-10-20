// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

func TestCloneSendReportsV1PreservesAndDetachesActualPrivateProof(t *testing.T) {
	org, doc := uuid.New(), uuid.New()
	now := time.Now()
	binding := &generated.DocumentVariableBinding{DocumentID: doc, VariableName: "customer", SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: "title", Fallback: "manual", LastValue: "old", LastError: "old error"}
	id := crmconnection.Identity{ID: uuid.New(), OrgID: org, Generation: 2, Origin: "https://crm.example.test", CRMTeamID: "team_1", CRMUserID: "user_1"}
	sha := sha256.Sum256([]byte("synthetic typed record"))
	snapshot := crmconnection.Snapshot{Identity: id, CompletedAt: now.Add(-time.Second), Records: []crmconnection.RecordObservation{{Kind: crmconnection.Deal, ID: "deal_1", CRMTeamID: "team_1", ObservedAt: now.Add(-2 * time.Second), RecordUpdatedAt: now.Add(-time.Minute), BodySHA256: hex.EncodeToString(sha[:]), Fields: map[string]crmconnection.Scalar{"title": {Present: true, Value: "Reviewed title"}}}}}
	value, proof, fence, err := crmValue(&snapshot, binding)
	if err != nil {
		t.Fatal(err)
	}
	entry := ResolveReport{bindingSnapshot: binding, crmFence: fence, CRMObservation: proof, Variable: binding.VariableName, SourceKind: binding.SourceKind, SourceRef: binding.SourceRef, SourcePath: binding.SourcePath, Value: value, ResolvedFrom: "source"}
	if err = ValidateFreshCRMReport(entry, org, doc, now); err != nil {
		t.Fatal(err)
	}
	in := []ResolveReport{entry}
	out := CloneSendReportsV1(in)
	if !reflect.DeepEqual(out, in) || &out[0] == &in[0] || out[0].bindingSnapshot == binding || out[0].crmFence == fence || out[0].CRMObservation == proof {
		t.Fatal("clone changed or retained mutable report objects")
	}
	// Changing any original exported/private object cannot alter the clone.
	binding.SourceRef = "other"
	proof.Generation = "changed"
	fence.identity.Generation++
	fence.observation.BodySHA256 = "changed"
	in[0].Value = "changed"
	if err = ValidateFreshCRMReport(out[0], org, doc, now); err != nil {
		t.Fatalf("original mutation changed detached proof: %v", err)
	}
	second := CloneSendReportsV1(out)
	out[0].bindingSnapshot.SourcePath = "other"
	out[0].CRMObservation.Origin = "other"
	out[0].crmFence.identity.Origin = "other"
	out[0].crmFence.observation.Generation = "other"
	if err = ValidateFreshCRMReport(second[0], org, doc, now); err != nil {
		t.Fatalf("returned mutation changed independent clone: %v", err)
	}
	public := second[0]
	public.bindingSnapshot = nil
	public.crmFence = nil
	forged := CloneSendReportsV1([]ResolveReport{public})
	if !errors.Is(ValidateFreshCRMReport(forged[0], org, doc, now), ErrSourceFreshness) {
		t.Fatal("clone minted missing source proof")
	}
	if CloneSendReportsV1(nil) != nil {
		t.Fatal("nil report changed shape")
	}
	empty := CloneSendReportsV1([]ResolveReport{})
	if empty == nil || len(empty) != 0 {
		t.Fatal("empty report changed shape")
	}
}
