// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blocks

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type authoringDecimalRefusalV1 struct {
	calls   int
	failure error
}

func (a *authoringDecimalRefusalV1) BeforeDecimalV1(string) error { a.calls++; return a.failure }
func TestOwnedAuthoringNormalizerKeepsOriginalMissingIDDefaultsAndMapMergeV1(t *testing.T) {
	raw := []byte("{\"version\":0,\"blocks\":[{\"type\":\"paragraph\",\"text\":\"first\",\"text\":\"final\"}]}")
	var before *Tree
	normalized, err := NormalizeTreeForAuthoringV1(context.Background(), raw, &authoringDecimalRefusalV1{}, func(tree *Tree) error { before = tree; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if before == nil || before.Version != SchemaVersion || len(before.Blocks) != 1 || before.Blocks[0].ID == "" || before.Blocks[0].Text != "final" {
		t.Fatalf("original normalization changed: %#v", before)
	}
	canonical, err := ParseCanonicalTree(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Blocks[0].ID != before.Blocks[0].ID {
		t.Fatal("generated ID did not persist")
	}
	var round Tree
	if err = json.Unmarshal(normalized, &round); err != nil || round.Blocks[0].ID != before.Blocks[0].ID {
		t.Fatalf("persisted normalized tree: %v", err)
	}
}
func TestOwnedAuthoringNormalizerStopsBeforeOriginalDecimalConversionAndMarshalV1(t *testing.T) {
	sentinel := errors.New("owned decimal refused")
	admission := &authoringDecimalRefusalV1{failure: sentinel}
	marshaled := false
	raw := []byte("{\"version\":1,\"blocks\":[{\"type\":\"conditional\",\"attrs\":{\"expression\":\"1e1000000 > 0\"},\"content\":[{\"type\":\"paragraph\",\"text\":\"ready\"}]}]}")
	_, err := NormalizeTreeForAuthoringV1(context.Background(), raw, admission, func(*Tree) error { marshaled = true; return nil })
	if !errors.Is(err, sentinel) || admission.calls != 1 || marshaled {
		t.Fatalf("decimal refusal lost or late: calls=%d marshal=%v err=%v", admission.calls, marshaled, err)
	}
}
func TestOwnedAuthoringNormalizerJoinsOriginalCanonicalOutputAdmissionV1(t *testing.T) {
	sentinel := errors.New("output refused")
	_, err := NormalizeTreeForAuthoringV1(context.Background(), []byte("{\"version\":1,\"blocks\":[]}"), &authoringDecimalRefusalV1{}, func(*Tree) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}
