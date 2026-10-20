// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package templatepin

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"testing"
)

type canonicalDecimalRefusalV1 struct {
	calls   int
	failure error
}

func (a *canonicalDecimalRefusalV1) BeforeDecimalV1(string) error { a.calls++; return a.failure }
func TestCanonicalAdmissionStopsBeforeDecimalAndMarshalV1(t *testing.T) {
	sentinel := errors.New("native decimal capacity refused")
	admission := &canonicalDecimalRefusalV1{failure: sentinel}
	marshaled := false
	raw := []byte(`{"version":1,"blocks":[{"id":"condition","type":"conditional","attrs":{"expression":"1e1000000 > 0"},"content":[{"id":"clause","type":"paragraph","text":"ready"}]}]}`)
	_, err := CanonicalizeWithAdmissionV1(context.Background(), raw, []byte("{}"), admission, func(*blocks.Tree) error { marshaled = true; return nil })
	if !errors.Is(err, sentinel) || admission.calls != 1 || marshaled {
		t.Fatalf("canonical conversion/Marshal ran before admission: calls=%d marshal=%v err=%v", admission.calls, marshaled, err)
	}
}
func TestCanonicalAdmissionPreservesOriginalCommitmentAndMissingIDRefusalV1(t *testing.T) {
	raw := []byte(`{"version":1,"blocks":[{"id":"clause","type":"paragraph","text":"Hello {{customer}}"}]}`)
	variables := []byte(`{"z":"last","customer":"Exact customer","a":"first"}`)
	original, err := Canonicalize(raw, variables)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := CanonicalizeWithAdmissionV1(context.Background(), raw, variables, nil, func(*blocks.Tree) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if owned.SHA256 != original.SHA256 || !bytes.Equal(owned.BlocksJSON, original.BlocksJSON) || !bytes.Equal(owned.VariablesJSON, original.VariablesJSON) {
		t.Fatal("existing canonical commitment bytes changed")
	}
	if _, err := CanonicalizeWithAdmissionV1(context.Background(), []byte(`{"version":1,"blocks":[{"type":"paragraph","text":"missing ID"}]}`), []byte("{}"), nil, nil); !errors.Is(err, blocks.ErrMissingID) {
		t.Fatal("canonical read assigned authoring IDs", err)
	}
}
