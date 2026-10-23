// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"

	"github.com/bright-interaction/hash/internal/crmreview"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Interactive source keeps its exact historical mapping-review requirement.
// Only a genuine immutable approved-API birth may use the alternate source
// authority. Fresh actual resolver fences/account/rules remain mandatory; this
// method neither fabricates human review nor accepts caller report JSON.
func (w *ApplicationHTMLSendWorkV1) CheckPreSignSourceDataV1(call context.Context, source *ApplicationHTMLSendSourceV1, authority presignregistry.ExecutionAuthorityV1, resolution *ApplicationHTMLSendResolutionV1) error {
	if w == nil || w.self != w || source == nil || source.state == nil || source.state.work != w {
		return ErrHTMLSendWorkV1
	}
	if authority.Definition().Kind != presignregistry.KindApprovedData {
		return w.CheckCRMReviewV1(call, source, resolution)
	}
	w.mu.Lock()
	if !w.valid(call) || w.sourceDocument == nil || w.crmReviewChecks >= 2 {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	doc := w.sourceDocument
	db := &applicationOwnedDBTXV1{session: w.session.state}
	w.mu.Unlock()
	var credential, materialization uuid.UUID
	var binding, original []byte
	var revision int64
	var commitment string
	p, g := authority.Policy().Reference(), authority.Grant().Reference()
	err := db.QueryRow(call, `SELECT executor_credential_id,original_credential_sha256,materialization_id,materialization_revision,source_commitment,crm_bindings_sha256
  FROM presign_source_requests_v1 WHERE org_id=$1 AND document_id=$2 AND state='committed'
   AND policy_id=$3 AND policy_revision=$4 AND encode(policy_sha256,'hex')=$5
   AND grant_id=$6 AND grant_revision=$7 AND encode(grant_sha256,'hex')=$8`, doc.OrgID, doc.ID, p.ID, p.Revision, p.SHA256, g.ID, g.Revision, g.SHA256).
		Scan(&credential, &original, &materialization, &revision, &commitment, &binding)
	if errors.Is(err, pgx.ErrNoRows) {
		// An explicit but different source relationship is a conflict, not an
		// invitation to use the interactive path for that same API document.
		var exists bool
		if e := db.QueryRow(call, `SELECT EXISTS(SELECT 1 FROM presign_source_requests_v1 WHERE org_id=$1 AND document_id=$2)`, doc.OrgID, doc.ID).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return ErrHTMLSendWorkV1
		}
		return w.CheckCRMReviewV1(call, source, resolution)
	}
	if err != nil {
		return err
	}
	actor := authority.Policy().Snapshot().Executor
	if actor.Kind != presign.ExecutorAPIKey || actor.CredentialID != credential || !doc.HtmlCurrentMaterializationID.Valid || uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) != materialization ||
		!doc.HtmlCurrentMaterializationSequence.Valid || int64(doc.HtmlCurrentMaterializationSequence.Int32) != revision || doc.HtmlEffectiveSourceCommitment.String != commitment {
		return ErrHTMLSendWorkV1
	}
	// The already reauthorized private capability must be the source's original
	// API credential binding, including its secret hash (never the secret).
	expected, err := hex.DecodeString(authority.CredentialCommitmentV1())
	if err != nil || !bytes.Equal(original, expected) {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if !w.valid(call) {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	w.crmReviewChecks++
	w.mu.Unlock()
	rows, err := w.readCurrentBindingModelsV1(call)
	if err != nil {
		return err
	}
	digest, err := crmreview.CRMSemanticDigest(rows)
	if err != nil {
		return err
	}
	hasCRM := authority.Definition().DataRules.CRM != nil
	if hasCRM {
		expected, err := hex.DecodeString(digest)
		if err != nil || !bytes.Equal(expected, binding) {
			return presignregistry.ErrConflict
		}
	} else if len(binding) != 0 || len(rows) != 0 {
		return presignregistry.ErrConflict
	}
	var reports []resolver.ResolveReport
	if resolution != nil {
		state := resolution.state
		if state == nil {
			return ErrHTMLSendWorkV1
		}
		state.mu.Lock()
		if !state.liveV1() || !state.attempted || state.failure != nil || state.active != 0 || state.work.stage.operation != w.stage.operation || state.document.ID != doc.ID || state.document.OrgID != doc.OrgID {
			state.mu.Unlock()
			return ErrHTMLSendWorkV1
		}
		state.active++
		reports = state.crmReports
		state.mu.Unlock()
		defer func() { state.mu.Lock(); state.active--; state.retireV1(); state.mu.Unlock() }()
	}
	return resolver.CheckCRMReports(call, &htmlSendCRMPolicyReadsV1{work: w, ctx: call}, doc.OrgID, reports)
}
