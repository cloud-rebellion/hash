// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"reflect"
	"testing"
)

func TestOwnedEIDASInputRetainsOriginalPolicyV1(t *testing.T) {
	for _, raw := range []string{
		"",
		"{}",
		"null",
		"[]",
		"{broken",
		"{\"amount\":\"1 234,50\",\"country\":\"SE\",\"document_type\":\"order\"}",
		"{\"deal_amount\":\"1e308\",\"jurisdiction\":\"NO\"}",
		"{\"total\":\"5e-324\",\"country_code\":\"DK\"}",
		"{\"amount\":\"0\",\"value\":\"9000\"}",
		"{\"amount\":\"not specified\",\"value\":\"9000\"}",
		"{\"amount\":\"NaN\"}",
		"{\"amount\":\"+Inf\"}",
		"{\"amount\":\"1,2.3\"}",
		"{\"amount\":\"1,2,3\"}",
		"{\"amount\":9007199254740993,\"external\":{\"number\":1e3,\"text\":\"<&>\"},\"flag\":true}",
		"{\"country\":null,\"jurisdiction\":\"SE\",\"type\":\"service\"}",
		"{\"amount\":\"\\u00a01\\u202f234,50\\u00a0\"}",
		"{\"amount\":1e100000}",
	} {
		t.Run(raw, func(t *testing.T) {
			d := &generated.Document{VariablesJson: json.RawMessage(raw)}
			before, old := BuildEIDASEvaluateInput(d)
			after, next := eidas.InputForDocumentV1(d)
			if (old == nil) != (next == nil) || (old != nil && old.Error() != next.Error()) || !reflect.DeepEqual(before, after) {
				t.Fatalf("policy changed: old=%#v/%v new=%#v/%v", before, old, after, next)
			}
		})
	}
}
