// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/send"
	"sync"
)

type automationSendResponseKeyV1 struct{}

// One original automation route invokes either Send or Resume, then at most
// ONE documented concurrent-sealing Resume. Fixed slots retain real results
// through final error/status serialization; this is no admission authority.
type automationSendResponseV1 struct {
	mu              sync.Mutex
	self            *automationSendResponseV1
	results         [2]*send.SendResult
	materialization *blockauthoring.AutomationResultV1
	count           int
	closed          bool
}

func newAutomationSendResponseV1(ctx context.Context) (context.Context, *automationSendResponseV1) {
	c := &automationSendResponseV1{}
	c.self = c
	return context.WithValue(ctx, automationSendResponseKeyV1{}, c), c
}
func automationSendResponseFromV1(ctx context.Context) *automationSendResponseV1 {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(automationSendResponseKeyV1{}).(*automationSendResponseV1)
	if c == nil || c.self != c {
		return nil
	}
	c.mu.Lock()
	valid := !c.closed && c.count < len(c.results)
	c.mu.Unlock()
	if !valid {
		return nil
	}
	return c
}
func (c *automationSendResponseV1) retainV1(result *send.SendResult) bool {
	if c == nil || c.self != c || result == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.count >= len(c.results) {
		return false
	}
	c.results[c.count] = result
	c.count++
	return true
}

// Exactly one materialization result precedes the existing at-most-two Send
// results. This typed slot grants no request/source/transaction authority.
func (c *automationSendResponseV1) retainMaterializationV1(result *blockauthoring.AutomationResultV1) bool {
	if c == nil || c.self != c || result == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.materialization != nil {
		return false
	}
	c.materialization = result
	return true
}
func (c *automationSendResponseV1) closeV1() {
	if c == nil || c.self != c {
		return
	}
	c.mu.Lock()
	c.closed = true
	results := c.results
	materialization := c.materialization
	c.materialization = nil
	c.results = [2]*send.SendResult{}
	c.count = 0
	c.mu.Unlock()
	if materialization != nil {
		materialization.CloseConsumerV1()
	}
	for _, r := range results {
		if r != nil {
			r.Links = nil
			r.CloseConsumerV1()
		}
	}
}
