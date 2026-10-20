// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"sort"
)

type ownedSendFamilyMemberV1 struct {
	work          *pdfadmission.ApplicationHTMLSendWorkV1
	models        *pdfadmission.HTMLSendModelsV1
	source        *pdfadmission.ApplicationHTMLSendSourceV1
	resolution    *pdfadmission.ApplicationHTMLSendResolutionV1
	original, doc *generated.Document
	evidence      *pdfadmission.ApplicationHTMLSendEvidenceV1
}

func readOwnedEnvelopeMembersV1(ctx context.Context, root *pdfadmission.ApplicationHTMLSendWorkV1) ([]*ownedSendFamilyMemberV1, error) {
	works, err := root.ReadEnvelopeMembersV1(ctx)
	if err != nil {
		return nil, err
	}
	members := make([]*ownedSendFamilyMemberV1, len(works))
	for i, work := range works {
		models, err := work.ReadModelsV1(ctx)
		if err != nil {
			return nil, err
		}
		members[i] = &ownedSendFamilyMemberV1{work: work, models: models, doc: models.Document, original: models.Document}
	}
	return members, nil
}
func ownedEnvelopeDocumentsV1(members []*ownedSendFamilyMemberV1) []*generated.Document {
	out := make([]*generated.Document, len(members))
	for i, m := range members {
		if m != nil {
			out[i] = m.doc
		}
	}
	return out
}

// Original child structure/canonical/immutable policy runs before freezing.
// Every source came from the SAME root's admitted actual ordered membership.
func validateOwnedEnvelopeMembersV1(ctx context.Context, root uuid.UUID, members []*ownedSendFamilyMemberV1, status string, projectRoles bool) ([]string, error) {
	if len(members) == 0 {
		return nil, errors.New("send envelope: envelope has no children")
	}
	roleSet := make(map[string]struct{})
	for i, m := range members {
		if m == nil || m.doc == nil {
			return nil, fmt.Errorf("send envelope: child %d is nil", i+1)
		}
		child := m.doc
		if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != root {
			return nil, fmt.Errorf("send envelope: child %s is no longer attached", child.ID)
		}
		if child.IsEnvelope {
			return nil, fmt.Errorf("send envelope: child %s is itself an envelope", child.ID)
		}
		if child.Status != status {
			return nil, fmt.Errorf("send envelope: child %s is not %s", child.ID, status)
		}
		if child.SourceKind != "blocks" {
			return nil, fmt.Errorf("send envelope: child %s must be blocks-source", child.ID)
		}
		if m.source == nil {
			var err error
			m.source, err = m.work.NewSourceV1(ctx)
			if err != nil {
				return nil, err
			}
		}
		err := m.source.ValidateBlockStructureV1()
		if errors.Is(err, pdfadmission.ErrPlainSendBlockTreeV1) {
			return nil, fmt.Errorf("send envelope: parse child %s blocks: %w", child.ID, err)
		}
		if errors.Is(err, pdfadmission.ErrPlainSendBlockEvidenceV1) {
			return nil, fmt.Errorf("send envelope: child %s: %w: %v", child.ID, ErrUnsupportedBlockEvidence, err)
		}
		if err != nil {
			return nil, err
		}
		if projectRoles {
			roles, err := m.source.RequiredBlockRolesV1()
			if err != nil {
				if errors.Is(err, pdfadmission.ErrPlainSendBlockValuesV1) {
					return nil, fmt.Errorf("send envelope: child %s variables: %w", child.ID, err)
				}
				if errors.Is(err, pdfadmission.ErrPlainSendBlockVariablesV1) {
					return nil, fmt.Errorf("send envelope: child %s signer roles: %w", child.ID, err)
				}
				return nil, err
			}
			for _, role := range roles {
				roleSet[role] = struct{}{}
			}
		}
	}
	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}
func (e *Engine) freezeOwnedEnvelopeMembersV1(ctx context.Context, members []*ownedSendFamilyMemberV1, bindings *sendBindingPreparation) error {
	if e.Resolver == nil {
		return errors.New("send envelope: variable resolver unavailable")
	}
	for _, m := range members {
		resolution, err := m.work.NewResolverV1(ctx, m.source, e.Resolver)
		if err != nil {
			return err
		}
		m.resolution = resolution
		if err = resolution.FreezeV1(); err != nil {
			return fmt.Errorf("freeze envelope child %s: %w", m.doc.ID, err)
		}
		view, err := resolution.SnapshotV1()
		if err != nil {
			return err
		}
		candidate := *m.doc
		candidate.VariablesJson = view.Frozen
		source, err := resolution.NewResolvedSourceV1()
		if err != nil {
			return err
		}
		if err = validateOwnedResolvedBlockVariablesV1(source); err != nil {
			return fmt.Errorf("freeze envelope child %s: %w", m.doc.ID, err)
		}
		if !source.MatchesDocumentV1(&candidate) {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		if err = source.ValidateCurrentV1(); err != nil {
			return err
		}
		m.source = source
		m.doc = &candidate
		if bindings == nil {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		childBindings := ownedSendBindingPreparationV1(m.doc, view)
		for id, definitions := range childBindings.definitions {
			bindings.definitions[id] = definitions
		}
		for id, reports := range childBindings.crmReports {
			bindings.crmReports[id] = reports
		}
		bindings.observations = append(bindings.observations, childBindings.observations...)
	}
	return nil
}
func guardOwnedEnvelopeEIDASV1(rootDoc *generated.Document, rootSource *pdfadmission.ApplicationHTMLSendSourceV1, members []*ownedSendFamilyMemberV1) (eidas.Decision, error) {
	if rootDoc == nil || rootSource == nil {
		return eidas.Decision{}, errors.New("eidas: envelope contains nil document")
	}
	decisions := make([]eidas.Decision, 0, len(members)+1)
	evaluate := func(doc *generated.Document, source *pdfadmission.ApplicationHTMLSendSourceV1) error {
		if doc == nil || source == nil {
			return errors.New("eidas: envelope contains nil document")
		}
		decision, err := source.EvaluateEIDASV1()
		if err != nil {
			if errors.Is(err, pdfadmission.ErrHTMLSendEIDASInputV1) {
				return fmt.Errorf("build eIDAS evaluation input for document %s: %w", doc.ID, err)
			}
			return fmt.Errorf("evaluate eIDAS rules for document %s: %w", doc.ID, err)
		}
		decisions = append(decisions, decision)
		return nil
	}
	if err := evaluate(rootDoc, rootSource); err != nil {
		return eidas.Decision{}, err
	}
	for _, m := range members {
		if m == nil {
			return eidas.Decision{}, errors.New("eidas: envelope contains nil document")
		}
		if err := evaluate(m.doc, m.source); err != nil {
			return eidas.Decision{}, err
		}
	}
	aggregated, err := aggregateEIDASDecisions(decisions)
	if err != nil {
		return eidas.Decision{}, err
	}
	return aggregated, enforceEIDASSendDecision(eidas.Tier(rootDoc.RoutingTier), aggregated)
}

func persistOwnedEnvelopeResolutionsV1(ctx context.Context, locked, prepared []*ownedSendFamilyMemberV1) error {
	if len(locked) != len(prepared) {
		return ErrDraftChangedDuringSend
	}
	for i, m := range locked {
		before := prepared[i]
		if m == nil || before == nil || before.resolution == nil {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		if err := m.work.VerifyAndPersistResolutionV1(ctx, before.resolution); err != nil {
			return err
		}
		candidate, err := m.work.NewResolvedSourceV1(before.resolution)
		if err != nil {
			return err
		}
		if err = validateOwnedResolvedBlockVariablesV1(candidate); err != nil {
			return err
		}
		if err = m.source.ValidateReviewedV1(); err != nil {
			return err
		}
		if err = candidate.ValidateCurrentV1(); err != nil {
			return err
		}
		if err = m.source.ValidateCurrentV1(); err != nil {
			return err
		}
		if !candidate.MatchesDocumentV1(before.doc) {
			return ErrDraftChangedDuringSend
		}
		m.doc, m.source, err = m.work.PersistResolvedVariablesV1(ctx, before.resolution)
		if err != nil {
			return fmt.Errorf("persist frozen envelope child %s: %w", before.doc.ID, err)
		}
	}
	return nil
}
func checkOwnedEnvelopeCRMReviewsV1(ctx context.Context, locked, prepared []*ownedSendFamilyMemberV1) error {
	if len(locked) != len(prepared) {
		return ErrDraftChangedDuringSend
	}
	for i, m := range locked {
		if m == nil || prepared[i] == nil {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		if err := m.work.CheckCRMReviewV1(ctx, m.source, prepared[i].resolution); err != nil {
			return err
		}
	}
	return nil
}

func pinOwnedEnvelopeMembersV1(ctx context.Context, root *pdfadmission.ApplicationHTMLSendWorkV1, client *storage.Client) ([]*ownedSendFamilyMemberV1, error) {
	members, err := readOwnedEnvelopeMembersV1(ctx, root)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		m.source, err = m.work.NewSourceV1(ctx)
		if err != nil {
			return nil, err
		}
		if err = m.source.ValidateReviewedV1(); err != nil {
			return nil, fmt.Errorf("resume send envelope: child HTML source: %w", err)
		}
		if err = m.source.ValidateCurrentV1(); err != nil {
			return nil, err
		}
		m.evidence, err = m.work.NewEvidenceV1(ctx, m.source, client)
		if err != nil {
			return nil, err
		}
		if err = m.evidence.PreparePinsV1(); err != nil {
			return nil, fmt.Errorf("resume send envelope: pin child evidence VersionIds: %w", err)
		}
		m.doc, err = m.work.PinEvidenceVersionsV1(ctx, m.evidence)
		if err != nil {
			return nil, fmt.Errorf("resume send envelope: pin child evidence VersionIds: %w", err)
		}
		m.source, err = m.work.NewSourceV1(ctx)
		if err != nil {
			return nil, err
		}
		if err = m.source.ValidateReviewedV1(); err != nil {
			return nil, err
		}
		if err = m.source.ValidateCurrentV1(); err != nil {
			return nil, err
		}
		if err = m.evidence.BindPinnedV1(m.source); err != nil {
			return nil, err
		}
	}
	return members, nil
}
func validateOwnedResolvedFamilySnapshotV1(members []*ownedSendFamilyMemberV1) error {
	for _, m := range members {
		if m == nil || m.doc == nil || m.source == nil {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		if err := validateOwnedResolvedBlockVariablesV1(m.source); err != nil {
			return fmt.Errorf("resume send envelope: validate child frozen variables: %w", err)
		}
		if !m.source.MatchesDocumentV1(m.doc) {
			return pdfadmission.ErrHTMLSendWorkV1
		}
	}
	return nil
}
func bindOwnedEnvelopeFieldsV1(ctx context.Context, root *pdfadmission.ApplicationHTMLSendWorkV1, previous []*ownedSendFamilyMemberV1) ([]*ownedSendFamilyMemberV1, []string, error) {
	members, err := readOwnedEnvelopeMembersV1(ctx, root)
	if err != nil {
		return nil, nil, err
	}
	if err = verifyPreparedEnvelopeChildren(ownedEnvelopeDocumentsV1(previous), ownedEnvelopeDocumentsV1(members)); err != nil {
		return nil, nil, err
	}
	for i, m := range members {
		m.source, err = m.work.NewSourceV1(ctx)
		if err != nil {
			return nil, nil, err
		}
		if err = validateOwnedResolvedSealedSnapshotV1(m.source, m.doc); err != nil {
			return nil, nil, err
		}
		if err = m.source.ValidateCurrentV1(); err != nil {
			return nil, nil, err
		}
		m.evidence = previous[i].evidence
	}
	// Binding happens only after the caller has validated actual root recipients.
	return members, nil, nil
}
