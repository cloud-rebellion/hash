// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/google/uuid"
)

// PDFRevisionBridgeV1 is implemented by the native handler adapter. The same
// pins as the REST routes apply: expected_updated_at and expected_pdf_sha256.
type PDFRevisionBridgeV1 interface {
	ReplacePDFV1(ctx context.Context, a DesignActorV1, id uuid.UUID, in PDFReplaceInputV1) (any, error)
	PDFHistoryV1(ctx context.Context, a DesignActorV1, id uuid.UUID) (any, error)
	ReviewPDFV1(ctx context.Context, a DesignActorV1, id uuid.UUID, in PDFReviewInputV1) (any, error)
}
type PDFReplaceInputV1 struct {
	ExpectedUpdatedAt string
	ExpectedPDFSHA256 string
	Summary           string
	PDF               []byte
}
type PDFReviewInputV1 struct {
	ExpectedUpdatedAt string
	ExpectedPDFSHA256 string
	ReviewedPages     []int
}

// 50 MiB of PDF is about 67 MiB of base64; refuse before decoding.
const maxPDFRevisionBase64V1 = (50<<20)/3*4 + 8

func pdfRevisionPinSchemaV1(props map[string]any) {
	props["document_id"] = stringSchema("UUID of the imported-PDF draft")
	props["expected_updated_at"] = stringSchema("document updated_at (RFC 3339) from get_document_pdf_history")
	props["expected_pdf_sha256"] = stringSchema("document pdf_sha256 as 64 hex characters, from get_document_pdf_history (get_document returns it base64-encoded; do not copy that)")
}

func registerPDFRevisionToolsV1(s *Server, d Deps) {
	type pinArgs struct {
		DocumentID        string `json:"document_id"`
		ExpectedUpdatedAt string `json:"expected_updated_at"`
		ExpectedPDFSHA256 string `json:"expected_pdf_sha256"`
	}
	actorFor := func(r *http.Request, raw json.RawMessage, into any, write bool) (DesignActorV1, uuid.UUID, error) {
		if d.PDFRevisions == nil {
			return DesignActorV1{}, uuid.Nil, errors.New("PDF revisions unavailable")
		}
		if err := designDecodeV1(raw, into); err != nil {
			return DesignActorV1{}, uuid.Nil, err
		}
		var p pinArgs
		if err := json.Unmarshal(raw, &p); err != nil {
			return DesignActorV1{}, uuid.Nil, err
		}
		id, err := uuid.Parse(p.DocumentID)
		if err != nil || id == uuid.Nil {
			return DesignActorV1{}, uuid.Nil, errors.New("valid document_id required")
		}
		actor, err := designActorV1(r.Context(), id, write)
		return actor, id, err
	}

	replaceProps := map[string]any{}
	pdfRevisionPinSchemaV1(replaceProps)
	replaceProps["pdf_base64"] = stringSchema("base64-encoded replacement PDF; the MCP request body is limited to 1 MiB, so the PDF can be at most about 760 KiB here (use the REST upload for larger files)")
	replaceProps["summary"] = stringSchema("optional plain-text note, at most 500 characters")
	s.RegisterTool(ToolDef{
		Name: "replace_document_pdf", Write: true,
		Description: "Replace the imported PDF of an unsent, unsigned PDF-source draft in place. Keeps the document ID, link, recipients and audit trail; retains the previous PDF; clears the field layout and requires a fresh review before the document can be sent. Refused for non-drafts, signed or filled documents, envelopes, amendment drafts, template-backed PDFs and designed HTML documents. Use get_document_pdf_history for the pins. Does not send.",
		InputSchema: func() map[string]any {
			o := schemaObject(replaceProps, []string{"document_id", "expected_updated_at", "expected_pdf_sha256", "pdf_base64"})
			o["additionalProperties"] = false
			return o
		}(),
		Handler: func(r *http.Request, raw json.RawMessage) (any, error) {
			var args struct {
				pinArgs
				PDFBase64 string `json:"pdf_base64"`
				Summary   string `json:"summary"`
			}
			actor, id, err := actorFor(r, raw, &args, true)
			if err != nil {
				return nil, err
			}
			if len(args.PDFBase64) == 0 || len(args.PDFBase64) > maxPDFRevisionBase64V1 {
				return nil, errors.New("pdf_base64 must be a base64-encoded PDF of at most 50 MiB")
			}
			data, err := base64.StdEncoding.DecodeString(args.PDFBase64)
			if err != nil {
				return nil, errors.New("pdf_base64 is not valid base64")
			}
			release, err := importguard.Shared.Acquire(actor.OrgID)
			if err != nil {
				return nil, err
			}
			defer release()
			return d.PDFRevisions.ReplacePDFV1(r.Context(), actor, id, PDFReplaceInputV1{ExpectedUpdatedAt: args.ExpectedUpdatedAt, ExpectedPDFSHA256: args.ExpectedPDFSHA256, Summary: args.Summary, PDF: data})
		},
	})

	historyProps := map[string]any{"document_id": stringSchema("UUID of the imported-PDF document")}
	s.RegisterTool(ToolDef{
		Name:        "get_document_pdf_history",
		Description: "Read the retained PDF revisions of an imported-PDF document (newest first), who reviewed each, the current updated_at/pdf_sha256 pins and pdf_review_required. pdf_review_required describes the standalone document only: a PDF attached to a signing package still needs a human review in a staff session, even when pdf_review_required is false. Revision 0 is the originally imported PDF and exists only once the PDF has been replaced.",
		InputSchema: func() map[string]any {
			o := schemaObject(historyProps, []string{"document_id"})
			o["additionalProperties"] = false
			return o
		}(),
		Handler: func(r *http.Request, raw json.RawMessage) (any, error) {
			var args struct {
				DocumentID string `json:"document_id"`
			}
			actor, id, err := actorFor(r, raw, &args, false)
			if err != nil {
				return nil, err
			}
			return d.PDFRevisions.PDFHistoryV1(r.Context(), actor, id)
		},
	})

	reviewProps := map[string]any{}
	pdfRevisionPinSchemaV1(reviewProps)
	reviewProps["visually_reviewed"] = map[string]any{"type": "boolean", "description": "Explicit attestation that you inspected every page of this exact PDF"}
	reviewProps["reviewed_pages"] = map[string]any{"type": "array", "minItems": 1, "maxItems": 500, "items": map[string]any{"type": "integer", "minimum": 1, "maximum": 500}}
	s.RegisterTool(ToolDef{
		Name: "review_document_pdf", Write: true,
		Description: "Explicitly acknowledge the exact current replaced PDF after inspecting EVERY page (download it with the history route first). Supply visually_reviewed=true and reviewed_pages=1..N. Refused for signing-purpose documents: a human reviews those in a staff session. A PDF attached to a signing package also needs a human review, even when pdf_review_required is false for the standalone document. Does not approve contractual terms or send.",
		InputSchema: func() map[string]any {
			o := schemaObject(reviewProps, []string{"document_id", "expected_updated_at", "expected_pdf_sha256", "visually_reviewed", "reviewed_pages"})
			o["additionalProperties"] = false
			return o
		}(),
		Handler: func(r *http.Request, raw json.RawMessage) (any, error) {
			var args struct {
				pinArgs
				VisuallyReviewed bool  `json:"visually_reviewed"`
				ReviewedPages    []int `json:"reviewed_pages"`
			}
			actor, id, err := actorFor(r, raw, &args, true)
			if err != nil {
				return nil, err
			}
			if !args.VisuallyReviewed {
				return nil, errors.New("visual review remains pending; inspect every page before explicitly acknowledging it")
			}
			return d.PDFRevisions.ReviewPDFV1(r.Context(), actor, id, PDFReviewInputV1{ExpectedUpdatedAt: args.ExpectedUpdatedAt, ExpectedPDFSHA256: args.ExpectedPDFSHA256, ReviewedPages: args.ReviewedPages})
		},
	})
}
