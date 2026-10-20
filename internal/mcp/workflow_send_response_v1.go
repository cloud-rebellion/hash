// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"github.com/bright-interaction/hash/internal/send"
	"net/http"
	"sync"
)

type workflowSendResponseKeyV1 struct{}

// This is only a fixed synchronous response last-use owner. It creates no
// native work/session/scope authority and accepts no caller completion flag.
// The actual dispatch installs it before the real Send call and closes it only
// after original error/result JSON serialization and ResponseWriter return.
type workflowSendResponseV1 struct {
	mu     sync.Mutex
	self   *workflowSendResponseV1
	result *send.SendResult
	closed bool
}

func newWorkflowSendResponseV1(r *http.Request) (*http.Request, *workflowSendResponseV1) {
	c := &workflowSendResponseV1{}
	c.self = c
	return r.WithContext(context.WithValue(r.Context(), workflowSendResponseKeyV1{}, c)), c
}
func workflowSendResponseFromV1(r *http.Request) *workflowSendResponseV1 {
	if r == nil {
		return nil
	}
	c, _ := r.Context().Value(workflowSendResponseKeyV1{}).(*workflowSendResponseV1)
	if c == nil || c.self != c {
		return nil
	}
	c.mu.Lock()
	valid := !c.closed && c.result == nil
	c.mu.Unlock()
	if !valid {
		return nil
	}
	return c
}
func (c *workflowSendResponseV1) retainV1(result *send.SendResult) bool {
	if c == nil || c.self != c || result == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.result != nil {
		return false
	}
	c.result = result
	return true
}
func (c *workflowSendResponseV1) closeV1() {
	if c == nil || c.self != c {
		return
	}
	c.mu.Lock()
	c.closed = true
	result := c.result
	c.result = nil
	c.mu.Unlock()
	if result != nil {
		result.Links = nil
		result.CloseConsumerV1()
	}
}
