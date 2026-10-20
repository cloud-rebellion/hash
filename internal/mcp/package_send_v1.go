// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
)

var errPackageSendArgumentsV1 = errors.New("invalid exact Send arguments; use document_id, lawful_basis and optional reviewed package_send only")

// Only these two fixed tool contracts use this parser. At most three fields,
// 2KiB and one nested scalar object; no generic recursive JSON/schema engine.
// Key equality precedes typed decoding, rejecting case aliases and duplicates.
func exactPackageSendObjectV1(raw []byte, fields []string, required int) ([3]json.RawMessage, error) {
	var values [3]json.RawMessage
	if len(raw) < 2 || len(raw) > 2048 || len(fields) > len(values) || validateJSONUnicode(raw) != nil {
		return values, errPackageSendArgumentsV1
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return values, errPackageSendArgumentsV1
	}
	for d.More() {
		tok, err = d.Token()
		if err != nil {
			return values, errPackageSendArgumentsV1
		}
		key, ok := tok.(string)
		if !ok {
			return values, errPackageSendArgumentsV1
		}
		index := -1
		for i, name := range fields {
			if key == name {
				index = i
				break
			}
		}
		if index < 0 || values[index] != nil {
			return values, errPackageSendArgumentsV1
		}
		if err = d.Decode(&values[index]); err != nil || bytes.Equal(bytes.TrimSpace(values[index]), []byte("null")) {
			return values, errPackageSendArgumentsV1
		}
	}
	tok, err = d.Token()
	if err != nil || tok != json.Delim('}') {
		return values, errPackageSendArgumentsV1
	}
	if _, err = d.Token(); err != io.EOF {
		return values, errPackageSendArgumentsV1
	}
	for i := 0; i < required; i++ {
		if values[i] == nil {
			return values, errPackageSendArgumentsV1
		}
	}
	return values, nil
}

type packageSendArgumentsV1 struct {
	document    uuid.UUID
	lawfulBasis string
	selection   pdfadmission.HTMLSendPackageSelectionV1
}

func parsePackageSendArgumentsV1(raw []byte) (packageSendArgumentsV1, error) {
	var out packageSendArgumentsV1
	v, err := exactPackageSendObjectV1(raw, []string{"document_id", "lawful_basis", "package_send"}, 2)
	if err != nil {
		return out, err
	}
	var document string
	if json.Unmarshal(v[0], &document) != nil || json.Unmarshal(v[1], &out.lawfulBasis) != nil {
		return out, errPackageSendArgumentsV1
	}
	out.document, err = uuid.Parse(document)
	if err != nil || out.document == uuid.Nil {
		return packageSendArgumentsV1{}, errPackageSendArgumentsV1
	}
	if err = send.ValidateLawfulBasis(out.lawfulBasis); err != nil {
		return packageSendArgumentsV1{}, err
	}
	if v[2] != nil {
		if _, err = exactPackageSendObjectV1(v[2], []string{"expected_updated_at", "package_id", "generation"}, 3); err != nil {
			return packageSendArgumentsV1{}, err
		}
		var observation send.PackageSendObservationV1
		if json.Unmarshal(v[2], &observation) != nil {
			return packageSendArgumentsV1{}, errPackageSendArgumentsV1
		}
		out.selection, err = observation.SelectionV1()
		if err != nil {
			return packageSendArgumentsV1{}, errPackageSendArgumentsV1
		}
	}
	return out, nil
}

func packageSendInputSchemaV1() map[string]any {
	schema := schemaObject(map[string]any{
		"document_id":  stringSchema("document UUID; packages may observe the same recorded attempt on retry"),
		"lawful_basis": map[string]any{"type": "string", "enum": []string{"contract"}, "description": "Explicit controller GDPR Article6 lawful-basis instruction; not recipient package consent"},
		"package_send": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"expected_updated_at", "package_id", "generation"}, "properties": map[string]any{
			"expected_updated_at": stringSchema("exact reviewed root UTC timestamp from get_document_attachments"),
			"package_id":          stringSchema("reviewed saved package UUID"), "generation": stringSchema("exact positive int64 generation as a decimal string")}},
	}, []string{"document_id", "lawful_basis"})
	schema["additionalProperties"] = false
	return schema
}

type packageSendToolReceiptV1 struct {
	AttemptID              uuid.UUID `json:"attempt_id"`
	Outcome                string    `json:"outcome"`
	ReconciliationRequired bool      `json:"reconciliation_required"`
}
type packageSendToolOutcomeV1 struct {
	DocumentID  uuid.UUID                 `json:"document_id"`
	Status      string                    `json:"status"`
	Links       []send.SignLink           `json:"links"`
	PackageSend *packageSendToolReceiptV1 `json:"package_send,omitempty"`
	Error       string                    `json:"error,omitempty"`
}

func packageSendToolOutcomeFromV1(document uuid.UUID, result send.SendResult, requested bool) (packageSendToolOutcomeV1, error) {
	out := packageSendToolOutcomeV1{DocumentID: document, Status: result.Status, Links: result.Links}
	if !requested {
		if result.PackageAttemptID != uuid.Nil {
			return packageSendToolOutcomeV1{}, errors.New("unexpected package Send result; inspect the saved document")
		}
		return out, nil
	}
	if result.PackageAttemptID == uuid.Nil {
		return packageSendToolOutcomeV1{}, errors.New("package Send result requires inspection")
	}
	if len(result.Links) != 0 {
		return packageSendToolOutcomeV1{}, &packageSendToolErrorV1{document: document, attempt: result.PackageAttemptID}
	}
	out.Links = []send.SignLink{}
	out.PackageSend = &packageSendToolReceiptV1{AttemptID: result.PackageAttemptID, Outcome: "completed"}
	switch result.Status {
	case "sealing":
		out.PackageSend.Outcome = "active"
		out.PackageSend.ReconciliationRequired = true
	case "sent", "in_progress", "changes_requested", "finalizing", "completed", "declined", "voided", "expired":
	default:
		return packageSendToolOutcomeV1{}, &packageSendToolErrorV1{document: document, attempt: result.PackageAttemptID}
	}
	return out, nil
}

// Only the actual fixed send_document handler can mint this private error.
// It carries selectors and fixed copy, never the underlying error or links.
type packageSendToolErrorV1 struct{ document, attempt uuid.UUID }

func (*packageSendToolErrorV1) Error() string {
	return "Send outcome requires inspection before continuing"
}
func packageSendErrorResultV1(tool string, err error) (ToolResult, bool) {
	e, ok := err.(*packageSendToolErrorV1)
	if tool != "send_document" || !ok || e == nil || e.document == uuid.Nil || e.attempt == uuid.Nil {
		return ToolResult{}, false
	}
	out := packageSendToolOutcomeV1{DocumentID: e.document, Status: "unknown", Links: []send.SignLink{}, Error: e.Error(), PackageSend: &packageSendToolReceiptV1{AttemptID: e.attempt, Outcome: "unknown", ReconciliationRequired: true}}
	raw, _ := json.Marshal(out)
	return ToolResult{IsError: true, Content: []ToolContent{{Type: "text", Text: string(raw)}}}, true
}

type packageSendInspectionResultV1 struct {
	AttemptID       uuid.UUID `json:"attempt_id"`
	Outcome         string    `json:"outcome"`
	RetryAuthorized bool      `json:"retry_authorized"`
	owner           *send.PackageSendAttemptInspectionV1
	cancel          context.CancelFunc
}

func (r *packageSendInspectionResultV1) CloseConsumerV1() {
	if r == nil {
		return
	}
	if r.owner != nil {
		r.owner.CloseConsumerV1()
		r.owner = nil
	}
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
}

func registerPackageSendInspectionV1(s *Server, d Deps) {
	schema := schemaObject(map[string]any{"document_id": stringSchema("authorized document UUID"), "attempt_id": stringSchema("exact persisted Send attempt selector")}, []string{"document_id", "attempt_id"})
	schema["additionalProperties"] = false
	s.RegisterTool(ToolDef{Name: "get_document_send_attempt", MinRole: auth.RoleSender, InputSchema: schema,
		Description: "Read one exact package Send outcome with current read authority. Returns active/completed/aborted/not_recorded and retry_authorized=false. Does not resume, send, mint links or authorize replay.",
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			values, err := exactPackageSendObjectV1(args, []string{"document_id", "attempt_id"}, 2)
			if err != nil {
				return nil, err
			}
			var documentText, attemptText string
			if json.Unmarshal(values[0], &documentText) != nil || json.Unmarshal(values[1], &attemptText) != nil {
				return nil, errPackageSendArgumentsV1
			}
			document, err := uuid.Parse(documentText)
			if err != nil || document == uuid.Nil {
				return nil, errPackageSendArgumentsV1
			}
			attempt, err := uuid.Parse(attemptText)
			if err != nil || attempt == uuid.Nil {
				return nil, errPackageSendArgumentsV1
			}
			if err = auth.EnforceDocScope(r.Context(), document); err != nil {
				return nil, err
			}
			user, ok := auth.FromContext(r.Context())
			if !ok || d.Send == nil {
				return nil, auth.ErrMutationPermissionRevoked
			}
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			authorize, err := auth.APIKeyTransactionAuthorization(ctx, document, mcpScopeRead)
			if err != nil {
				cancel()
				return nil, err
			}
			owner, err := d.Send.InspectPackageSendAttemptV1(ctx, send.Actor{OrgID: user.OrgID, UserID: &user.UserID, Authorize: authorize, Via: "mcp", Tool: "get_document_send_attempt"}, document, attempt)
			if err != nil {
				if owner != nil {
					owner.CloseConsumerV1()
				}
				cancel()
				return nil, err
			}
			out := &packageSendInspectionResultV1{AttemptID: attempt, owner: owner, cancel: cancel}
			err = owner.WithObservationV1(func(v pdfadmission.HTMLSendPackageAttemptObservationV1) error {
				if v.AttemptID != attempt {
					return pdfadmission.ErrHTMLSendPackageInspectionV1
				}
				switch v.Outcome {
				case pdfadmission.HTMLSendPackageAttemptActiveV1:
					out.Outcome = "active"
				case pdfadmission.HTMLSendPackageAttemptCompletedV1:
					out.Outcome = "completed"
				case pdfadmission.HTMLSendPackageAttemptAbortedV1:
					out.Outcome = "aborted"
				case pdfadmission.HTMLSendPackageAttemptNotRecordedV1:
					out.Outcome = "not_recorded"
				default:
					return pdfadmission.ErrHTMLSendPackageInspectionV1
				}
				return nil
			})
			if err != nil {
				out.CloseConsumerV1()
				return nil, err
			}
			return out, nil
		},
	})
}
