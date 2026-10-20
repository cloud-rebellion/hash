// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/packageauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

func registerDocumentPackageToolsV1(s *Server, d Deps) {
	s.RegisterTool(ToolDef{Name: "add_document_attachment", Write: true, MinRole: auth.RoleSender,
		Description: "Select one exact verified standalone PDF/HTML document as a contractual attachment to a draft agreement. Does not send or sign the package. Observe current clocks and package generation first. State committed is saved even with reconciliation_required; state unknown must be refreshed before retry. Document-scoped tokens are refused.",
		InputSchema: schemaObject(map[string]any{
			"document_id":                stringSchema("main agreement uuid"),
			"member_document_id":         stringSchema("standalone attachment uuid"),
			"expected_updated_at":        stringSchema("observed main updated_at RFC3339"),
			"expected_member_updated_at": stringSchema("observed attachment updated_at RFC3339"),
			"expected_package_id":        stringSchema("observed package uuid, or empty string for absent header"),
			"expected_generation":        stringSchema("observed positive bigint decimal string, or 0 for absent header"),
			"ordinal":                    intSchema("explicit unused position from1to16", 1, 16, 1),
			"title":                      stringSchema("attachment title,1to512UTF8bytes"),
			"category":                   stringSchema("open-ended business label,0to128UTF8bytes"),
		}, []string{"document_id", "member_document_id", "expected_updated_at", "expected_member_updated_at", "expected_package_id", "expected_generation", "ordinal", "title", "category"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			if d.PDFCreationSessions == nil || d.Storage == nil || d.Audit == nil {
				return nil, errors.New("attachment processing is unavailable")
			}
			u, ok := auth.FromContext(r.Context())
			if !ok {
				return nil, auth.ErrMutationPermissionRevoked
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			// uuid.Nil intentionally refuses all document-agent credentials even when
			// this handler is called without central catalog scope enforcement.
			authorize, e := auth.APIKeyTransactionAuthorization(ctx, uuid.Nil, mcpScopeWriteAuthoring)
			if e != nil {
				return nil, e
			}
			input, e := d.PDFCreationSessions.NewDocumentPackageArgumentsV1(ctx, u.OrgID, args)
			if e != nil {
				_, message := packageauthoring.PublicErrorV1(e)
				return nil, errors.New(message)
			}
			defer func() { result = &ownedPackageSelectionResultV1{value: result, input: input} }()
			if e = input.ReadArgumentsV1(ctx); e != nil {
				_, message := packageauthoring.PublicErrorV1(e)
				return nil, errors.New(message)
			}
			out, e := packageauthoring.SelectV1(ctx, packageauthoring.DependenciesV1{Sessions: d.PDFCreationSessions, Storage: d.Storage, Audit: d.Audit},
				authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, input, "", "")
			if e != nil {
				_, message := packageauthoring.PublicErrorV1(e)
				return nil, errors.New(message)
			}
			if out.Cause != nil {
				slog.Warn("Hash attachment selection requires reconciliation", "state", out.State, "error_type", fmt.Sprintf("%T", out.Cause))
				out.Cause = nil
			}
			return out, nil
		},
	})

	s.RegisterTool(ToolDef{Name: "save_document_attachments", Write: true, MinRole: auth.RoleSender,
		Description: "Save the full draft attachment order and labels atomically. Members must already be selected; omitted IDs are detached. Empty members detaches all. Pins never follow live sources. Use observed root updated_at,package ID and string generation. No replacement/Send/signing; document tokens are refused. committed is saved; unknown requires readback before retry.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("main agreement uuid"), "expected_updated_at": stringSchema("observed root RFC3339 clock"), "expected_package_id": stringSchema("observed existing package uuid"), "expected_generation": stringSchema("observed positive bigint decimal string"),
			"members": map[string]any{"type": "array", "maxItems": 16, "items": schemaObject(map[string]any{"document_id": stringSchema("already selected document uuid"), "title": stringSchema("1to512 UTF8 bytes"), "category": stringSchema("0to128 UTF8 bytes,open-ended")}, []string{"document_id", "title", "category"})},
		}, []string{"document_id", "expected_updated_at", "expected_package_id", "expected_generation", "members"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			if d.PDFCreationSessions == nil || d.Audit == nil {
				return nil, errors.New("attachment processing is unavailable")
			}
			u, ok := auth.FromContext(r.Context())
			if !ok {
				return nil, auth.ErrMutationPermissionRevoked
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			authorize, e := auth.APIKeyTransactionAuthorization(ctx, uuid.Nil, mcpScopeWriteAuthoring)
			if e != nil {
				return nil, e
			}
			input, e := d.PDFCreationSessions.NewDocumentPackageLayoutArgumentsV1(ctx, u.OrgID, args)
			if e != nil {
				_, message := packageauthoring.PublicErrorV1(e)
				return nil, errors.New(message)
			}
			defer func() { result = &ownedPackageSelectionResultV1{value: result, input: input} }()
			if e = input.ReadLayoutArgumentsV1(ctx); e != nil {
				_, message := packageauthoring.PublicErrorV1(e)
				return nil, errors.New(message)
			}
			out, e := packageauthoring.SaveLayoutV1(ctx, packageauthoring.DependenciesV1{Sessions: d.PDFCreationSessions, Audit: d.Audit}, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, input, "", "")
			if e != nil {
				_, message := packageauthoring.PublicErrorV1(e)
				return nil, errors.New(message)
			}
			if out.Cause != nil {
				slog.Warn("Hash attachment layout requires reconciliation", "state", out.State, "error_type", fmt.Sprintf("%T", out.Cause))
				out.Cause = nil
			}
			return out, nil
		},
	})
	s.RegisterTool(ToolDef{Name: "get_document_attachments", MinRole: auth.RoleSender,
		Description: "Observe an editable draft agreement's exact selected attachment metadata and package generation. Reads frozen selections, including after original source deletion. Does not verify storage or send/sign a package.",
		InputSchema: schemaObject(map[string]any{"document_id": stringSchema("draft agreement uuid")}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			if d.PDFCreationSessions == nil {
				return nil, errors.New("attachment processing is unavailable")
			}
			u, ok := auth.FromContext(r.Context())
			if !ok {
				return nil, auth.ErrMutationPermissionRevoked
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			input, e := d.PDFCreationSessions.NewDocumentPackageInventoryArgumentsV1(ctx, u.OrgID, args)
			if e != nil {
				_, message := packageauthoring.PublicErrorV1(e)
				return nil, errors.New(message)
			}
			defer func() { result = &ownedPackageSelectionResultV1{value: result, input: input} }()
			if e = input.ReadArgumentsV1(ctx); e != nil {
				_, message := packageauthoring.PublicErrorV1(e)
				return nil, errors.New(message)
			}
			var owned *packageauthoring.InventoryResultV1
			e = input.WithInventoryV1(ctx, u.OrgID, func(root uuid.UUID) error {
				authorize, e := auth.APIKeyTransactionAuthorization(ctx, root, mcpScopeRead)
				if e != nil {
					return e
				}
				owned, e = packageauthoring.InventoryV1(ctx, packageauthoring.DependenciesV1{Sessions: d.PDFCreationSessions},
					authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, root)
				return e
			})
			if e != nil {
				if owned != nil {
					owned.CloseConsumerV1()
				}
				_, message := packageauthoring.PublicErrorV1(e)
				return nil, errors.New(message)
			}
			return owned, nil
		},
	})

}

// Central tools/call retains this input grant through success/error JSON
// serialization. The outcome contains only fixed IDs, clocks and status text.
type ownedPackageSelectionResultV1 struct {
	mu     sync.Mutex
	value  any
	input  *pdfadmission.ApplicationDocumentPackageInputV1
	closed bool
}

func (r *ownedPackageSelectionResultV1) MarshalJSON() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, pdfadmission.ErrDocumentPackageInputV1
	}
	return json.Marshal(r.value)
}
func (r *ownedPackageSelectionResultV1) CloseConsumerV1() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	input := r.input
	value := r.value
	r.input = nil
	r.value = nil
	r.mu.Unlock()
	if owner, ok := value.(interface{ CloseConsumerV1() }); ok {
		owner.CloseConsumerV1()
	}
	if input != nil {
		input.CloseConsumerV1()
	}
}
