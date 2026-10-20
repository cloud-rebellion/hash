// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package aiauthoring

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
)

type SignerClarifyInputV1 struct{ BlockID, SelectionText, Question, Locale string }

func openSignerPhaseV1(ctx context.Context, d DependenciesV1, request *pdfadmission.ApplicationSignerAIRequestV1, state *resultStateV1) (*phaseV1, error) {
	p := &phaseV1{}
	state.phases = append(state.phases, p)
	org, doc, err := request.ScopeV1(ctx, d.Sessions)
	if err != nil {
		return p, err
	}
	p.session, err = d.Sessions.OpenV1(ctx, org, doc)
	if err != nil {
		return p, err
	}
	p.admission, err = p.session.NewAdmissionV1(ctx)
	return p, err
}

// Cost uses the private usage context after caller cancellation, so scope comes
// only from the already-issued receipt's actual native session identity.
func openSignerCostPhaseV1(ctx context.Context, d DependenciesV1, dispatch *phaseV1, state *resultStateV1) (*phaseV1, error) {
	p := &phaseV1{}
	state.phases = append(state.phases, p)
	identity, err := dispatch.work.AuditIdentityV1()
	if err != nil {
		return p, err
	}
	p.session, err = d.Sessions.OpenV1(ctx, identity.OrgID, identity.DocumentID)
	if err != nil {
		return p, err
	}
	p.admission, err = p.session.NewAdmissionV1(ctx)
	return p, err
}
func lockSignerPhaseV1(ctx context.Context, p *phaseV1, native *pdfadmission.ApplicationSignerAIRequestV1, request *sign.SignerAIRequestV1) (*generated.Document, *generated.Recipient, error) {
	var err error
	p.work, err = p.session.NewSignerAIWorkV1(ctx, native)
	if err != nil {
		return nil, nil, err
	}
	if err = p.work.LockScopeV1(ctx); err != nil {
		return nil, nil, err
	}
	doc, rec, err := p.work.ReadSignerDocumentV1(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err = request.RecheckV1(ctx, doc, rec); err != nil {
		return nil, nil, err
	}
	return doc, rec, nil
}

// Actual recipient request→dispatch→independent usage/cost→answer protocol.
// No callback can supply a success result, request receipt or cost params.
func CompleteSignerClarifierV1(parent, ctx context.Context, d DependenciesV1, request *sign.SignerAIRequestV1, runtime *ai.Runtime, in SignerClarifyInputV1) (result *ResultV1[aiapps.ClarifyResult], failure error) {
	state := &resultStateV1{factory: d.Sessions, original: parent, workflow: ctx}
	result = &ResultV1[aiapps.ClarifyResult]{state: state, body: &resultBodyV1[aiapps.ClarifyResult]{}}
	state.erase = func() { result.body.value = aiapps.ClarifyResult{} }
	fail := func(err error) (*ResultV1[aiapps.ClarifyResult], error) {
		state.failed = true
		result.body.value = aiapps.ClarifyResult{}
		return result, err
	}
	if parent == nil || ctx == nil || parent.Err() != nil || ctx.Err() != nil || d.Sessions == nil || d.Audit == nil || runtime == nil || request == nil {
		return fail(errors.New("signer AI dependencies unavailable"))
	}
	native, err := request.NativeV1()
	if err != nil {
		return fail(err)
	}
	if err := native.VerifyInputV1(ctx, in.BlockID, in.Locale, in.SelectionText, in.Question); err != nil {
		return fail(err)
	}
	org, docID, err := native.ScopeV1(ctx, d.Sessions)
	if err != nil {
		return fail(err)
	}
	state.accounting, err = d.Sessions.ReserveDocumentAIAccountingV1(ctx, org, docID)
	if err != nil {
		return fail(err)
	}
	requested, err := openSignerPhaseV1(ctx, d, native, state)
	if err != nil {
		return fail(err)
	}
	var receipt *pdfadmission.ApplicationDocumentAIRequestReceiptV1
	var first, second audit.PendingEvent
	err = requested.session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		doc, rec, err := lockSignerPhaseV1(call, requested, native, request)
		if err != nil {
			return err
		}
		first, requested.extraEvent, err = ownedaudit.LogSignerAIRequestV1(d.Audit, call, requested.work, true)
		if err != nil {
			return err
		}
		second, requested.event, err = ownedaudit.LogSignerAIRequestV1(d.Audit, call, requested.work, false)
		if err != nil {
			return err
		}
		if err = request.RecheckV1(call, doc, rec); err != nil {
			return err
		}
		return requested.work.CheckSignerCredentialV1(call)
	})
	if err != nil {
		return fail(err)
	}
	if err = requested.session.CommitV1(ctx); err != nil {
		return fail(err)
	}
	receipt, err = requested.work.CommittedRequestV1(requested.event)
	if err != nil {
		return fail(err)
	}
	if err = ownedaudit.PublishV1(d.Audit, first, requested.extraEvent); err != nil {
		return fail(err)
	}
	if err = ownedaudit.PublishV1(d.Audit, second, requested.event); err != nil {
		return fail(err)
	}
	if err = requested.work.CloseCommittedRequestSourceV1(receipt); err != nil {
		return fail(err)
	}
	cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	err = requested.session.CloseV1(cleanup)
	stop()
	if err != nil {
		return fail(err)
	}
	dispatch, err := openSignerPhaseV1(ctx, d, native, state)
	if err != nil {
		return fail(err)
	}
	var value aiapps.ClarifyResult
	var answer audit.PendingEvent
	err = dispatch.session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		doc, rec, err := lockSignerPhaseV1(call, dispatch, native, request)
		if err != nil {
			return err
		}
		observer := &signerUsageObserverV1{dependencies: d, state: state, dispatch: dispatch, receipt: receipt}
		owner, err := dispatch.work.NewRuntimeV1(call, observer)
		if err != nil {
			return err
		}
		observer.owner = owner
		owned := ai.WithNativeWorkflowV1(call, owner)
		dispatch.borrow, err = dispatch.work.BeginWorkflowV1(owned)
		if err != nil {
			return err
		}
		scoped := runtime.ForAuditedRequest(nil, func(context.Context, generated.InsertAICompletionAuditParams) error {
			return errors.New("native signer observation required")
		}).ForNativeWorkflowV1(owner)
		clause, contextText := in.SelectionText, ""
		if in.BlockID != "" {
			block, err := authoring.AIAppBlockContextV1(owned, doc, in.BlockID)
			if err != nil {
				return err
			}
			if clause == "" {
				clause = block.Text
			}
			tree, err := ai.ParseTreeV1(owned, doc.BlocksJson)
			if err != nil {
				return err
			}
			if tree != nil {
				for i := range tree.Blocks {
					if tree.Blocks[i].ID == in.BlockID {
						before, after := "", ""
						if i > 0 {
							before = tree.Blocks[i-1].Text
						}
						if i+1 < len(tree.Blocks) {
							after = tree.Blocks[i+1].Text
						}
						size, err := ai.NativeCostV1(4096, int64(len(before))+int64(len(after)), 8)
						if err != nil {
							return err
						}
						if err = ai.RetainNativeV1(owned, size); err != nil {
							return err
						}
						contextText = before + "\n\n" + after
						break
					}
				}
			}
		}
		if err = request.RecheckV1(owned, doc, rec); err != nil {
			return err
		}
		if err = dispatch.work.CheckSignerCredentialV1(owned); err != nil {
			return err
		}
		value, err = (&aiapps.Clarifier{Runtime: scoped}).Clarify(owned, aiapps.ClarifyInput{OrgID: org, DocumentID: docID, Locale: in.Locale, ClauseText: clause, SurroundingContext: contextText, Question: in.Question})
		if err != nil {
			return err
		}
		if !observer.observedV1() {
			return pdfadmission.ErrDocumentAIAuditV1
		}
		if err = request.RecheckV1(owned, doc, rec); err != nil {
			return err
		}
		if err = dispatch.work.CheckSignerCredentialV1(owned); err != nil {
			return err
		}
		answer, dispatch.event, err = ownedaudit.LogSignerAIAnswerV1(d.Audit, owned, dispatch.work, receipt, value.ShieldActive, value.LatencyMs, value.InputTokens, value.OutputTokens)
		if err != nil {
			return err
		}
		if err = request.RecheckV1(owned, doc, rec); err != nil {
			return err
		}
		return dispatch.work.CheckSignerCredentialV1(owned)
	})
	if err != nil {
		return fail(err)
	}
	if err = dispatch.session.CommitV1(ctx); err != nil {
		return fail(err)
	}
	if err = ownedaudit.PublishV1(d.Audit, answer, dispatch.event); err != nil {
		return fail(err)
	}
	result.body.value = value
	return result, nil
}

type signerUsageObserverV1 struct {
	mu                 sync.Mutex
	dependencies       DependenciesV1
	state              *resultStateV1
	dispatch           *phaseV1
	receipt            *pdfadmission.ApplicationDocumentAIRequestReceiptV1
	owner              *pdfadmission.ApplicationDocumentAIRuntimeV1
	prepared, observed bool
}

func (o *signerUsageObserverV1) ReserveNativeUsageV1(origin context.Context, owner ai.NativeWorkflowV1, provider, model, prompt string, version int) error {
	o.mu.Lock()
	if o.prepared || o.owner == nil || owner != o.owner {
		o.mu.Unlock()
		return pdfadmission.ErrDocumentAIAuditV1
	}
	o.prepared = true
	o.mu.Unlock()
	return o.state.accounting.PrepareUsageV1(origin, o.dispatch.work, o.receipt, o.owner, provider, model, prompt, version)
}
func (o *signerUsageObserverV1) ObserveNativeUsageV1(origin context.Context, owner ai.NativeWorkflowV1, observation *ai.CompletionObservationV1) error {
	o.mu.Lock()
	if !o.prepared || o.observed || o.owner == nil || owner != o.owner {
		o.mu.Unlock()
		return pdfadmission.ErrDocumentAIAuditV1
	}
	o.observed = true
	o.mu.Unlock()
	usage, err := o.state.accounting.ObserveUsageV1(origin, o.dispatch.work, o.receipt, o.owner, observation)
	if err != nil {
		return err
	}
	o.state.usages = append(o.state.usages, usage)
	if err = o.state.accounting.PersistUsageV1(usage); err != nil {
		return errors.New("AI usage persistence failed")
	}
	costCtx, err := usage.CostContextV1()
	if err != nil {
		return err
	}
	cost, err := openSignerCostPhaseV1(costCtx, o.dependencies, o.dispatch, o.state)
	if err != nil {
		return errors.New("AI completion event persistence failed")
	}
	var pending audit.PendingEvent
	err = cost.session.WithTxV1(costCtx, func(call context.Context, _ generated.DBTX) error {
		var err error
		cost.cost, err = cost.session.NewDocumentAICostV1(call, usage)
		if err != nil {
			return err
		}
		if err = cost.cost.ReadUsageV1(call); err != nil {
			return err
		}
		pending, cost.event, err = ownedaudit.LogSignerAICostV1(o.dependencies.Audit, call, cost.cost)
		return err
	})
	if err == nil {
		err = cost.session.CommitV1(costCtx)
	}
	if err == nil {
		err = ownedaudit.PublishV1(o.dependencies.Audit, pending, cost.event)
	}
	if err != nil {
		return errors.New("AI completion event persistence failed")
	}
	cleanup, stop := context.WithTimeout(context.WithoutCancel(costCtx), 5*time.Second)
	err = cost.session.CloseV1(cleanup)
	stop()
	return err
}
func (o *signerUsageObserverV1) observedV1() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.observed
}
