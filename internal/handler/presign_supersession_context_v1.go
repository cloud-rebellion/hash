// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"net/http"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func (s *Server) handlePreSignSupersessionContextV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if !s.requireHTMLAuthoringRuntimeV1(w) {
		return
	}
	document, err := presignUUIDParam(r, "document_id")
	if err != nil || len(r.URL.Query()) != 0 {
		writeError(w, 400, "canonical document UUID required")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, u.OrgID, document)
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	defer o.closeConsumerV1(ctx)
	defer o.closeSQLV1(ctx)
	var raw []byte
	err = o.session.WithTxV1(ctx, func(call context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		guard, e := lockHTMLAuthorV1(call, tx, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, false)
		if e != nil {
			return e
		}
		raw, e = o.reader.ReadPreSignSupersessionContextV1(call, u.UserID, document, s.preSignExecutionAvailableV1())
		if e != nil {
			return e
		}
		return guard.Recheck(call)
	})
	if err == nil {
		err = o.session.CommitV1(ctx)
	}
	if err == nil {
		err = o.closeSQLV1(ctx)
	}
	if err != nil {
		s.writePreSignSupersessionErrorV1(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
