// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
)

var errOwnerMutationInput = errors.New("invalid organization settings")

func (s *Server) sessionOwnerActor(r *http.Request, user auth.SessionUser) (authoring.Actor, error) {
	authorize, err := s.sessionDraftAuthorization(r, user.OrgID, user.UserID)
	if err != nil {
		return authoring.Actor{}, err
	}
	return authoring.Actor{OrgID: user.OrgID, UserID: user.UserID, Authorize: authorize}, nil
}
