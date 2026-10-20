// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blocks

// SignatureFieldIDForVariablesForSigningV1 preserves the original signer
// pre-order, conditional short circuit and default signer-role projection.
// Its only added effect is the SAME decimal-conversion admission hook used by
// the native immutable block source. It returns an ID, never a mutable tree.
func SignatureFieldIDForVariablesForSigningV1(tree *Tree, role string, vars map[string]string, admission ConditionalSendAdmissionV1) (string, error) {
	if tree == nil {
		return "", nil
	}
	work := newConditionalSendWorkV1(admission)
	var visit func([]Block) (string, error)
	visit = func(items []Block) (string, error) {
		for i := range items {
			block := &items[i]
			if block.Type == TypeConditional {
				included, err := evalConditionStrictForSendV1(block.AttrString("expression", ""), vars, work)
				if err != nil {
					return "", work.resultV1(err)
				}
				if !included {
					continue
				}
			}
			if block.Type == TypeSignatureField {
				want := block.AttrString("recipient_role", "")
				if want == "" {
					want = "signer"
				}
				if want == role {
					return block.ID, nil
				}
			}
			found, err := visit(block.Content)
			if err != nil || found != "" {
				return found, err
			}
		}
		return "", nil
	}
	field, err := visit(tree.Blocks)
	return field, work.resultV1(err)
}
