// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ai

import (
	"context"
	"errors"
	"math"
	"text/template"
	"text/template/parse"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

var ErrNativeWorkflowV1 = errors.New("ai: owned workflow unavailable")

// This interface is implemented by the genuine, retained dispatch owner. It
// exposes fixed operations, never a DBTX, arbitrary SQL, caller resource vector,
// detached grant or user-supplied durable-success claim.
type NativeWorkflowV1 interface {
	RetainV1(context.Context, int64) error
	ParseTreeV1(context.Context, []byte) (*blocks.Tree, error)
	ReadRecipientNamesV1(context.Context, uuid.UUID) ([]string, error)
	ReadOrganizationProviderV1(context.Context, uuid.UUID) (*generated.OrgAiSetting, error)
	WrapProviderV1(context.Context, Provider) (Provider, error)
	PrepareUsageV1(context.Context, string, string, string, int) error
	ObserveUsageV1(context.Context, *CompletionObservationV1) error
}

// The coordinator installs its fixed private receipt-bound observer on the
// actual dispatch owner before executing the original feature callback.
type NativeUsageObserverV1 interface {
	ReserveNativeUsageV1(context.Context, NativeWorkflowV1, string, string, string, int) error
	ObserveNativeUsageV1(context.Context, NativeWorkflowV1, *CompletionObservationV1) error
}

type nativeWorkflowContextKeyV1 struct{}

func WithNativeWorkflowV1(ctx context.Context, owner NativeWorkflowV1) context.Context {
	return context.WithValue(ctx, nativeWorkflowContextKeyV1{}, owner)
}
func NativeWorkflowFromContextV1(ctx context.Context) NativeWorkflowV1 {
	if ctx == nil {
		return nil
	}
	owner, _ := ctx.Value(nativeWorkflowContextKeyV1{}).(NativeWorkflowV1)
	return owner
}
func RetainNativeV1(ctx context.Context, n int64) error {
	if n < 0 {
		return ErrNativeWorkflowV1
	}
	if owner := NativeWorkflowFromContextV1(ctx); owner != nil && n > 0 {
		return owner.RetainV1(ctx, n)
	}
	return nil
}
func NativeCostV1(fixed, count, scale int64) (int64, error) {
	if fixed < 0 || count < 0 || scale < 0 || (scale > 0 && count > (math.MaxInt64-fixed)/scale) {
		return 0, ErrNativeWorkflowV1
	}
	return fixed + count*scale, nil
}

// There is no exported constructor. Only the actual Runtime.writeAudit point
// creates this immutable observation from the real selected provider/result.
// A normal caller cannot convert raw params, an event ID or a detached context
// into an observed incurred-cost receipt.
type CompletionObservationV1 struct {
	self   *CompletionObservationV1
	owner  NativeWorkflowV1
	origin context.Context
	params generated.InsertAICompletionAuditParams
}

func newCompletionObservationV1(ctx context.Context, owner NativeWorkflowV1, params generated.InsertAICompletionAuditParams) *CompletionObservationV1 {
	out := &CompletionObservationV1{owner: owner, origin: ctx, params: params}
	out.self = out
	return out
}
func (o *CompletionObservationV1) ParamsForV1(owner NativeWorkflowV1, origin context.Context) (generated.InsertAICompletionAuditParams, error) {
	if o == nil || o.self != o || owner == nil || o.owner != owner || o.origin != origin || NativeWorkflowFromContextV1(origin) != owner {
		return generated.InsertAICompletionAuditParams{}, ErrNativeWorkflowV1
	}
	return o.params, nil
}

// The existing app prompts have only literal text and single string fields.
// Measure those actual AST nodes and actual input strings before the original
// template executor/builder. Unsupported executable template programs cannot
// use this finite native profile; no output/token hint substitutes for size.
func nativeTemplateOutputV1(t *template.Template, input map[string]string) (int64, int64, error) {
	if t == nil || t.Tree == nil || t.Tree.Root == nil {
		return 0, 0, ErrNativeWorkflowV1
	}
	var total, nodes int64
	for _, node := range t.Tree.Root.Nodes {
		nodes++
		var n int64
		switch value := node.(type) {
		case *parse.TextNode:
			n = int64(len(value.Text))
		case *parse.ActionNode:
			if value.Pipe == nil || len(value.Pipe.Decl) != 0 || len(value.Pipe.Cmds) != 1 || len(value.Pipe.Cmds[0].Args) != 1 {
				return 0, 0, ErrNativeWorkflowV1
			}
			field, ok := value.Pipe.Cmds[0].Args[0].(*parse.FieldNode)
			if !ok || len(field.Ident) != 1 {
				return 0, 0, ErrNativeWorkflowV1
			}
			text, exists := input[field.Ident[0]]
			if exists {
				n = int64(len(text))
			} else {
				n = int64(len("<no value>"))
			}
		default:
			return 0, 0, ErrNativeWorkflowV1
		}
		var err error
		total, err = NativeCostV1(total, n, 1)
		if err != nil {
			return 0, 0, err
		}
	}
	return total, nodes, nil
}
func RenderPromptV1(ctx context.Context, prompt *Prompt, input map[string]string) (Request, error) {
	if NativeWorkflowFromContextV1(ctx) == nil {
		return prompt.Render(input)
	}
	system, ns, err := nativeTemplateOutputV1(prompt.SystemTpl, input)
	if err != nil {
		return Request{}, err
	}
	user, nu, err := nativeTemplateOutputV1(prompt.UserTpl, input)
	if err != nil {
		return Request{}, err
	}
	total, err := NativeCostV1(system, user, 1)
	if err != nil {
		return Request{}, err
	}
	cost, err := NativeCostV1(4096, total, 4)
	if err != nil {
		return Request{}, err
	}
	cost, err = NativeCostV1(cost, ns+nu, 512)
	if err != nil {
		return Request{}, err
	}
	if err = RetainNativeV1(ctx, cost); err != nil {
		return Request{}, err
	}
	return prompt.Render(input)
}

// The exact original parser, including legacy block-ID behavior, gets real
// lexical and decimal admission from the actual document dispatch owner.
func ParseTreeV1(ctx context.Context, raw []byte) (*blocks.Tree, error) {
	if owner := NativeWorkflowFromContextV1(ctx); owner != nil {
		return owner.ParseTreeV1(ctx, raw)
	}
	return blocks.ParseTree(raw)
}

func (r *Runtime) ForNativeWorkflowV1(owner NativeWorkflowV1) *Runtime {
	if r == nil || owner == nil {
		return nil
	}
	copy := *r
	copy.nativeWorkflow = owner
	copy.Cache = nil
	return &copy
}

// Restored text has no token/HTTP-byte ceiling. Fund actual feature JSON/string
// and output serialization classes before the unchanged feature parsers run.
func PrepareFeatureResultV1(ctx context.Context, text string) error {
	cost, err := NativeCostV1(8192, int64(len(text)), 512)
	if err != nil {
		return err
	}
	return RetainNativeV1(ctx, cost)
}

// Native receipts retain the real supported integer values. Validate BEFORE
// legacy schema casts so2^32+23 cannot masquerade as23 in an opaque observation.
func nativeCompletionValuesV1(req Request, resp Response, latency int) error {
	for _, value := range []int{req.PromptVersion, resp.InputTokens, resp.OutputTokens, latency} {
		if value < 0 || int64(value) > math.MaxInt32 {
			return ErrCompletionAudit
		}
	}
	return nil
}
