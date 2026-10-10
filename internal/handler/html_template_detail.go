// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
)

type htmlTemplateApprovalResponse struct {
	Version       int32  `json:"version"`
	ContentSHA256 string `json:"content_sha256"`
	ApprovedBy    string `json:"approved_by,omitempty"`
	ApprovedAt    string `json:"approved_at,omitempty"`
}

// Approval describes the exact returned revision, including approved defaults.
// A concurrent edit may make these pins stale; instantiation rechecks them under
// the current template lock. Lists intentionally do not perform this lookup.
func toHTMLTemplateDetailResponse(template *generated.Template, revision *generated.HtmlTemplateRevision) (templateResponse, error) {
	var empty templateResponse
	if template == nil || revision == nil || template.SourceKind != "html" || template.ID == uuid.Nil || template.OrgID == uuid.Nil ||
		template.Version <= 0 || revision.TemplateID != template.ID || revision.OrgID != template.OrgID || revision.Version != template.Version ||
		len(template.HtmlContentSha256) != 32 || !bytes.Equal(template.HtmlContentSha256, revision.ContentSha256) {
		return empty, errors.New("HTML template revision identity does not match")
	}
	digest := hex.EncodeToString(template.HtmlContentSha256)
	current, err := htmlmaster.CanonicalTemplate(template.HtmlMasterJson, template.VariablesJson)
	if err != nil || current.SHA256 != digest {
		return empty, errors.New("HTML template content commitment does not match")
	}
	retained, err := htmlmaster.CanonicalTemplate(revision.HtmlMasterJson, revision.VariablesJson)
	if err != nil || retained.SHA256 != digest {
		return empty, errors.New("HTML template approval content does not match")
	}
	if revision.ApprovedBy.Valid != revision.ApprovedAt.Valid || (revision.ApprovedBy.Valid &&
		(uuid.UUID(revision.ApprovedBy.Bytes) == uuid.Nil || revision.ApprovedAt.Time.IsZero() || revision.ApprovedAt.InfinityModifier != pgtype.Finite)) {
		return empty, errors.New("HTML template approval is incomplete")
	}
	response, err := toTemplateResponse(template)
	if err != nil {
		return empty, err
	}
	response.HTMLMasterJSON = current.MasterJSON
	response.HTMLApproval = &htmlTemplateApprovalResponse{Version: template.Version, ContentSHA256: digest}
	if revision.ApprovedBy.Valid {
		response.HTMLApproval.ApprovedBy = uuid.UUID(revision.ApprovedBy.Bytes).String()
		response.HTMLApproval.ApprovedAt = revision.ApprovedAt.Time.UTC().Format(time.RFC3339Nano)
	}
	return response, nil
}
