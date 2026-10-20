// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"math"
	"strings"
	"time"
)

// Runs only AFTER the fixed actual payload walk has acquired its native loan.
// Preserve concrete hook values while detaching scalar strings from whole
// document/recipient/source buffers. No arbitrary custom Marshaler is invoked.
func htmlAuditCloneValueV1(ctx context.Context, v any, depth int) (any, error) {
	if depth > 8 || ctx.Err() != nil {
		return nil, ErrHTMLAuditEventV1
	}
	switch x := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, uuid.UUID, time.Time:
		return x, nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, ErrHTMLAuditEventV1
		}
		return x, nil
	case string:
		return strings.Clone(x), nil
	case article13.Snapshot:
		x.Schema = strings.Clone(x.Schema)
		x.SentAt = strings.Clone(x.SentAt)
		x.Controller = strings.Clone(x.Controller)
		x.ControllerContact = strings.Clone(x.ControllerContact)
		x.Processor = strings.Clone(x.Processor)
		x.ProcessorContact = strings.Clone(x.ProcessorContact)
		x.PurposeSummary = strings.Clone(x.PurposeSummary)
		x.LegalBasisDisclosure = strings.Clone(x.LegalBasisDisclosure)
		x.SupervisoryAuthority = strings.Clone(x.SupervisoryAuthority)
		x.PolicyURL = strings.Clone(x.PolicyURL)
		x.DSRCapability = article13.DSRCapability(strings.Clone(string(x.DSRCapability)))
		x.Copy.Title = strings.Clone(x.Copy.Title)
		x.Copy.Intro = strings.Clone(x.Copy.Intro)
		x.Copy.ControllerLabel = strings.Clone(x.Copy.ControllerLabel)
		x.Copy.ControllerContactLabel = strings.Clone(x.Copy.ControllerContactLabel)
		x.Copy.ProcessorLabel = strings.Clone(x.Copy.ProcessorLabel)
		x.Copy.PurposeLabel = strings.Clone(x.Copy.PurposeLabel)
		x.Copy.LegalBasisLabel = strings.Clone(x.Copy.LegalBasisLabel)
		x.Copy.RetentionLabel = strings.Clone(x.Copy.RetentionLabel)
		x.Copy.RetentionValue = strings.Clone(x.Copy.RetentionValue)
		x.Copy.AuthorityLabel = strings.Clone(x.Copy.AuthorityLabel)
		x.Copy.RightsSummary = strings.Clone(x.Copy.RightsSummary)
		x.Copy.RightsBody = strings.Clone(x.Copy.RightsBody)
		x.Copy.SubmitRequestLabel = strings.Clone(x.Copy.SubmitRequestLabel)
		x.Copy.KindLabel = strings.Clone(x.Copy.KindLabel)
		x.Copy.DSRAccessLabel = strings.Clone(x.Copy.DSRAccessLabel)
		x.Copy.DSRRectificationLabel = strings.Clone(x.Copy.DSRRectificationLabel)
		x.Copy.DSRErasureLabel = strings.Clone(x.Copy.DSRErasureLabel)
		x.Copy.DSRRestrictionLabel = strings.Clone(x.Copy.DSRRestrictionLabel)
		x.Copy.DSRPortabilityLabel = strings.Clone(x.Copy.DSRPortabilityLabel)
		x.Copy.DSRObjectionLabel = strings.Clone(x.Copy.DSRObjectionLabel)
		x.Copy.NoteLabel = strings.Clone(x.Copy.NoteLabel)
		x.Copy.NotePlaceholder = strings.Clone(x.Copy.NotePlaceholder)
		x.Copy.SendRequestLabel = strings.Clone(x.Copy.SendRequestLabel)
		x.Copy.RequestReceived = strings.Clone(x.Copy.RequestReceived)
		x.Copy.ReadPolicyLabel = strings.Clone(x.Copy.ReadPolicyLabel)
		x.Copy.AcknowledgementLabel = strings.Clone(x.Copy.AcknowledgementLabel)
		x.Copy.FinePrint = strings.Clone(x.Copy.FinePrint)
		return x, nil
	case htmlsource.PartyBinding:
		x.Slot = strings.Clone(x.Slot)
		return x, nil
	case map[string]any:
		if x == nil {
			return map[string]any(nil), nil
		}
		out := make(map[string]any, len(x))
		for k, v := range x {
			if ctx.Err() != nil {
				return nil, ErrHTMLAuditEventV1
			}
			value, err := htmlAuditCloneValueV1(ctx, v, depth+1)
			if err != nil {
				return nil, err
			}
			out[strings.Clone(k)] = value
		}
		return out, nil
	case map[string]string:
		if x == nil {
			return map[string]string(nil), nil
		}
		out := make(map[string]string, len(x))
		for k, v := range x {
			if ctx.Err() != nil {
				return nil, ErrHTMLAuditEventV1
			}
			out[strings.Clone(k)] = strings.Clone(v)
		}
		return out, nil
	case []string:
		if x == nil {
			return []string(nil), nil
		}
		out := make([]string, len(x))
		for i, v := range x {
			if ctx.Err() != nil {
				return nil, ErrHTMLAuditEventV1
			}
			out[i] = strings.Clone(v)
		}
		return out, nil
	case []map[string]any:
		if x == nil {
			return []map[string]any(nil), nil
		}
		out := make([]map[string]any, len(x))
		for i, v := range x {
			value, err := htmlAuditCloneValueV1(ctx, v, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = value.(map[string]any)
		}
		return out, nil
	case []map[string]string:
		if x == nil {
			return []map[string]string(nil), nil
		}
		out := make([]map[string]string, len(x))
		for i, v := range x {
			value, err := htmlAuditCloneValueV1(ctx, v, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = value.(map[string]string)
		}
		return out, nil
	case []htmlsource.PartyBinding:
		if x == nil {
			return []htmlsource.PartyBinding(nil), nil
		}
		out := make([]htmlsource.PartyBinding, len(x))
		for i, v := range x {
			if ctx.Err() != nil {
				return nil, ErrHTMLAuditEventV1
			}
			v.Slot = strings.Clone(v.Slot)
			out[i] = v
		}
		return out, nil
	default:
		return nil, ErrHTMLAuditEventV1
	}
}
