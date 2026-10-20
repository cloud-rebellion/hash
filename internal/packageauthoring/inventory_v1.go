// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package packageauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"sync"
	"time"
)

type InventoryResultV1 struct{ state *inventoryResultStateV1 }
type inventoryResultStateV1 struct {
	mu     sync.Mutex
	value  pdfadmission.DocumentPackageInventoryV1
	reader *pdfadmission.ApplicationHTMLRevisionReaderV1
	closed bool
}

func (r *InventoryResultV1) MarshalJSON() ([]byte, error) {
	if r == nil || r.state == nil {
		return []byte("null"), nil
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, pdfadmission.ErrDocumentPackageDraftV1
	}
	return json.Marshal(s.value)
}
func (r *InventoryResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	reader := s.reader
	s.reader = nil
	s.value = pdfadmission.DocumentPackageInventoryV1{}
	s.mu.Unlock()
	if reader != nil {
		reader.CloseConsumerV1()
	}
}
func InventoryV1(ctx context.Context, d DependenciesV1, actor authoring.Actor, root uuid.UUID) (result *InventoryResultV1, failure error) {
	if d.Sessions == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || root == uuid.Nil {
		return nil, pdfadmission.ErrDocumentPackageInputV1
	}
	session, e := d.Sessions.OpenV1(ctx, actor.OrgID, root)
	var admission *pdfadmission.ApplicationAdmissionV1
	state := &inventoryResultStateV1{}
	result = &InventoryResultV1{state: state}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if failure != nil {
			result.CloseConsumerV1()
		}
		if session != nil {
			failure = errors.Join(failure, session.CloseV1(cleanup))
		}
		if admission != nil {
			_, e := admission.ReconcileCleanupV1(cleanup)
			failure = errors.Join(failure, e)
		}
		if failure != nil {
			result.CloseConsumerV1()
		}
	}()
	if e != nil {
		return result, e
	}
	admission, e = session.NewAdmissionV1(ctx)
	if e != nil {
		return result, e
	}
	failure = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		reader, e := session.NewHTMLRevisionReaderV1(call)
		state.reader = reader
		if e != nil {
			return e
		}
		guard, e := readStaffDraftRootV1(call, db, reader, actor, root)
		if e != nil {
			return e
		}
		// Root evidence/privacy admission already preceded its body expansion.
		state.value, e = reader.ReadDocumentPackageInventoryV1(call)
		if errors.Is(e, pdfadmission.ErrDocumentPackagePendingPrivacyV1) {
			return authoring.ErrPendingPrivacyReview
		}
		if errors.Is(e, pdfadmission.ErrDocumentPackagePrivacyChangingV1) {
			return authoring.ErrPrivacyReviewChanging
		}
		if e != nil {
			return e
		}
		return guard.Recheck(call)
	})
	return result, failure
}
