// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package workguard

import (
	"context"
	"github.com/google/uuid"
)

// These enums describe one actual admission decision. They confer no resource,
// source, SQL, provider or retirement permission.
type AdmissionDenialReasonV1 uint8

const (
	AdmissionNotDeniedV1 AdmissionDenialReasonV1 = iota
	AdmissionInvalidV1
	AdmissionContextV1
	AdmissionCoordinatorUnavailableV1
	AdmissionGlobalGrantCountV1
	AdmissionOrganisationGrantCountV1
	AdmissionGlobalResourceV1
	AdmissionOrganisationResourceV1
)

type AdmissionDimensionV1 uint8

const (
	AdmissionNoDimensionV1 AdmissionDimensionV1 = iota
	AdmissionParentBytesV1
	AdmissionDBStagingBytesV1
	AdmissionChildAddressBytesV1
	AdmissionPDFWorkersV1
	AdmissionSQLSessionsV1
	AdmissionProviderStreamsV1
	AdmissionRendererRequestsV1
)

// Immutable fixed numeric value from the exact rejecting branch. No pointers,
// organisation identifier/inventory, text, callback or live coordinator alias
// are retained. Observation is not available capacity or a permit.
type AdmissionDenialV1 struct {
	reason                                    AdmissionDenialReasonV1
	dimension                                 AdmissionDimensionV1
	requested, globalLimit, organisationLimit VectorV1
	before                                    SnapshotV1
	globalGrantLimit, organisationGrantLimit  int64
}
type AdmissionDenialSnapshotV1 struct {
	Reason                                    AdmissionDenialReasonV1
	Dimension                                 AdmissionDimensionV1
	Requested, GlobalLimit, OrganisationLimit VectorV1
	Before                                    SnapshotV1
	GlobalGrantLimit, OrganisationGrantLimit  int64
}

func (d AdmissionDenialV1) SnapshotV1() AdmissionDenialSnapshotV1 {
	return AdmissionDenialSnapshotV1{d.reason, d.dimension, d.requested, d.globalLimit, d.organisationLimit, d.before, d.globalGrantLimit, d.organisationGrantLimit}
}
func (d AdmissionDenialV1) CapacityV1() bool {
	return d.reason >= AdmissionGlobalGrantCountV1 && d.reason <= AdmissionOrganisationResourceV1
}
func recordAdmissionDenialReasonV1(d *AdmissionDenialV1, reason AdmissionDenialReasonV1) {
	if d != nil {
		d.reason = reason
	}
}
func (c *CoordinatorV1) recordAdmissionCapacityDenialLockedV1(d *AdmissionDenialV1, org uuid.UUID, cost VectorV1, reason AdmissionDenialReasonV1, dimension AdmissionDimensionV1) {
	if d == nil {
		return
	}
	before := SnapshotV1{Global: vectorV1(c.global.used), GlobalGrants: c.global.grants, ActiveOrganisations: int64(len(c.orgs))}
	if a := c.orgs[org]; a != nil {
		before.Organisation = vectorV1(a.used)
		before.OrganisationGrants = a.grants
	}
	*d = AdmissionDenialV1{reason: reason, dimension: dimension, requested: cost, globalLimit: c.limits.Global, organisationLimit: c.limits.Organisation, before: before, globalGrantLimit: c.limits.MaxGrants, organisationGrantLimit: c.limits.MaxOrganisationGrants}
}

// TryAcquireWithDenialV1 uses the one original atomic acquisition core. The
// caller must already own its fixed observation/error frame independently;
// this numeric companion itself never allocates a diagnostic error or logs.
// Invalid/context/unavailable refusals are distinguished from true capacity.
func (c *CoordinatorV1) TryAcquireWithDenialV1(ctx context.Context, org uuid.UUID, cost VectorV1) (*GrantV1, AdmissionDenialV1, error) {
	var denial AdmissionDenialV1
	grant, err := c.tryAcquireV1(ctx, org, cost, &denial)
	return grant, denial, err
}
