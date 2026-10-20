// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
)

// A fixed factory-owned registry covers constructor-only parent grants as well
// as native stages. No dynamic map capacity or caller retirement hint is used.
func (f *ApplicationSessionFactoryV1) registerDocumentPackageOperationV1(s *applicationDocumentPackageOperationStateV1) bool {
	if f == nil || f.state == nil || s == nil || s.factory != f {
		return false
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	for i, old := range p.documentPackageOperations {
		if old == nil {
			p.documentPackageOperations[i] = s
			return true
		}
	}
	return false
}
func (f *ApplicationSessionFactoryV1) unregisterDocumentPackageOperationV1(s *applicationDocumentPackageOperationStateV1) {
	if f == nil || f.state == nil || s == nil {
		return
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, old := range p.documentPackageOperations {
		if old == s {
			p.documentPackageOperations[i] = nil
			return
		}
	}
}
func (f *ApplicationSessionFactoryV1) reconcileDocumentPackageOperationsV1(ctx context.Context) error {
	p := f.state
	p.mu.Lock()
	owners := p.documentPackageOperations
	p.mu.Unlock()
	var result error
	for _, s := range owners {
		if s == nil {
			continue
		}
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			result = errors.Join(result, (&ApplicationDocumentPackageOperationV1{state: s}).CloseV1(ctx))
		}
	}
	return result
}
