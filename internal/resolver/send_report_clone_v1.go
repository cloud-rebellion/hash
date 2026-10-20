// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import "strings"

// CloneSendReportsV1 detaches the actual typed resolver report, including its
// private binding/account fences. It does not attest freshness or grant work;
// the native producer prices these copies before calling it.
func CloneSendReportsV1(in []ResolveReport) []ResolveReport {
	if in == nil {
		return nil
	}
	out := make([]ResolveReport, len(in))
	for i, r := range in {
		c := r
		c.Variable = strings.Clone(r.Variable)
		c.SourceKind = strings.Clone(r.SourceKind)
		c.SourceRef = strings.Clone(r.SourceRef)
		c.SourcePath = strings.Clone(r.SourcePath)
		c.Value = strings.Clone(r.Value)
		c.ResolvedFrom = strings.Clone(r.ResolvedFrom)
		if r.bindingSnapshot != nil {
			b := *r.bindingSnapshot
			b.VariableName = strings.Clone(b.VariableName)
			b.SourceKind = strings.Clone(b.SourceKind)
			b.SourceRef = strings.Clone(b.SourceRef)
			b.SourcePath = strings.Clone(b.SourcePath)
			b.Fallback = strings.Clone(b.Fallback)
			b.LastValue = strings.Clone(b.LastValue)
			b.LastError = strings.Clone(b.LastError)
			c.bindingSnapshot = &b
		}
		cloneObservation := func(o CRMValueObservation) CRMValueObservation {
			o.Generation = strings.Clone(o.Generation)
			o.Origin = strings.Clone(o.Origin)
			o.CRMTeamID = strings.Clone(o.CRMTeamID)
			o.CRMUserID = strings.Clone(o.CRMUserID)
			o.BodySHA256 = strings.Clone(o.BodySHA256)
			o.ValueSHA256 = strings.Clone(o.ValueSHA256)
			o.Transformation = strings.Clone(o.Transformation)
			return o
		}
		if r.CRMObservation != nil {
			o := cloneObservation(*r.CRMObservation)
			c.CRMObservation = &o
		}
		if r.crmFence != nil {
			f := *r.crmFence
			f.identity.Origin = strings.Clone(f.identity.Origin)
			f.identity.CRMTeamID = strings.Clone(f.identity.CRMTeamID)
			f.identity.CRMUserID = strings.Clone(f.identity.CRMUserID)
			f.observation = cloneObservation(f.observation)
			c.crmFence = &f
		}
		out[i] = c
	}
	return out
}
