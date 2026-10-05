// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
)

func TestRejectedPDFUploadRemovesSpilledFile(t *testing.T) {
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	file, err := form.CreateFormFile("pdf", "oversized-buffer.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(bytes.Repeat([]byte("a"), multipartFileMemory+1)); err != nil {
		t.Fatal(err)
	}
	if err = form.Close(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"document", "template"} {
		t.Run(kind, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body.Bytes()))
			req.Header.Set("Content-Type", form.FormDataContentType())
			if err := req.ParseMultipartForm(multipartFileMemory); err != nil {
				t.Fatal(err)
			}
			opened, err := req.MultipartForm.File["pdf"][0].Open()
			if err != nil {
				t.Fatal(err)
			}
			disk, ok := opened.(*os.File)
			if !ok {
				opened.Close()
				t.Fatal("fixture did not spill to disk")
			}
			path := disk.Name()
			opened.Close()
			recorder := httptest.NewRecorder()
			s := &Server{}
			if kind == "document" {
				s.importDocumentFromPDF(recorder, req, uuid.New(), uuid.New())
			} else {
				s.createPDFTemplate(recorder, req, uuid.New(), uuid.New())
			}
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("want invalid upload, got %d", recorder.Code)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("temporary upload retained: %v", err)
			}
		})
	}
}
