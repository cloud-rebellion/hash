// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/aiauthoring"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"net/http"
	"sync"
)

type ownedAIResultV1[T any] struct {
	ctx   context.Context
	owner *aiauthoring.ResultV1[T]
}

func (o *ownedAIResultV1[T]) MarshalJSON() (out []byte, failure error) {
	if o == nil || o.owner == nil {
		return []byte("null"), nil
	}
	failure = o.owner.WithValueV1(o.ctx, func(value T) error { var err error; out, err = json.Marshal(value); return err })
	return out, failure
}
func (o *ownedAIResultV1[T]) CloseConsumerV1() {
	if o != nil && o.owner != nil {
		o.owner.CloseConsumerV1()
	}
}

type ownedAIArgumentsResultV1 struct{ state *ownedAIArgumentsStateV1 }
type ownedAIArgumentsStateV1 struct {
	once  sync.Once
	value any
	input *pdfadmission.ApplicationDocumentAIInputV1
}

func (o *ownedAIArgumentsResultV1) MarshalJSON() ([]byte, error) { return json.Marshal(o.state.value) }
func (o *ownedAIArgumentsResultV1) CloseConsumerV1() {
	if o != nil && o.state != nil {
		o.state.once.Do(func() {
			if nested, ok := o.state.value.(interface{ CloseConsumerV1() }); ok {
				nested.CloseConsumerV1()
			}
			o.state.input.CloseConsumerV1()
		})
	}
}
func withAIArgumentsV1(r *http.Request, d Deps, args json.RawMessage, run ToolHandler) (result any, failure error) {
	// Parser-only tests without a native application factory retain validation;
	// successful production cannot enter the coordinator without a real factory.
	if d.PDFCreationSessions == nil {
		return run(r, args)
	}
	user, _ := auth.FromContext(r.Context())
	input, err := d.PDFCreationSessions.NewAIArgumentsV1(r.Context(), user.OrgID, args)
	if err != nil {
		return nil, err
	}
	defer func() {
		result = &ownedAIArgumentsResultV1{state: &ownedAIArgumentsStateV1{value: result, input: input}}
	}()
	failure = input.WithArgumentsV1(r.Context(), func(raw []byte) error { result, failure = run(r, json.RawMessage(raw)); return failure })
	return result, failure
}
