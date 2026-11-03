// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"net/http"
)

func documentPurposeSchemaV1() map[string]any {
	return map[string]any{"type": "string", "enum": []string{"document", "presentation", "signing"}, "description": "Persisted draft authoring purpose; omitted creation purpose retains historical signing. Acknowledgement is a separate signing-workflow setting."}
}
func registerDocumentPurposeToolV1(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name: "set_document_purpose", Write: true,
		Description: "Explicitly change an editable draft's purpose without changing its source content. Document and presentation modes have no recipient/signing workflow. Changing away from signing refuses recipients, fields, envelope/package preparation and retained evidence. Sent/signed documents cannot be reclassified.",
		InputSchema: schemaObject(map[string]any{"document_id": stringSchema("document UUID"), "expected_updated_at": stringSchema("exact current updated_at observation"), "purpose": documentPurposeSchemaV1()}, []string{"document_id", "expected_updated_at", "purpose"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, ok := auth.FromContext(r.Context())
			if !ok {
				return nil, errors.New("authentication required")
			}
			var in struct {
				DocumentID string                  `json:"document_id"`
				Expected   string                  `json:"expected_updated_at"`
				Purpose    documentpurpose.Purpose `json:"purpose"`
			}
			if err := MustParseArgs(args, &in); err != nil {
				return nil, err
			}
			if documentpurpose.Validate(in.Purpose) != nil {
				return nil, documentpurpose.ErrInvalid
			}
			id, err := uuid.Parse(in.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a UUID")
			}
			if err = auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), id, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			return blockauthoring.MutateDocumentPurposeV1(r.Context(), blockauthoring.DependenciesV1{Sessions: d.PDFCreationSessions, Audit: d.Audit}, blockauthoring.ActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "set_document_purpose"}, id, versions.ViaMCP, in.Expected, checkDocumentObservation, in.Purpose)
		},
	})
}
