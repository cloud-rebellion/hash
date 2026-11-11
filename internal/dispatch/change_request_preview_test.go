//go:build emailpreview

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package dispatch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestExportChangeRequestEmailPreviewsV1 exports synthetic native-rendered mail
// only when explicitly built with emailpreview. It opens no SMTP connection.
func TestExportChangeRequestEmailPreviewsV1(t *testing.T) {
	dir := os.Getenv("HASH_EMAIL_PREVIEW_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("HASH_EMAIL_PREVIEW_DIR must name a fresh absolute output directory")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	total := 0
	write := func(name, body string) {
		t.Helper()
		total += len(body)
		if len(body) == 0 || len(body) > ServiceEmailDesignRenderedBytesV1 || total > 1<<20 {
			t.Fatal("synthetic email previews exceed the output budget")
		}
		if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, locale := range []string{"sv", "en", "sv-long"} {
		c := TemplateContext{
			Locale: locale, RecipientName: "Exempelperson", DocumentName: "Internt funktionstest",
			ChangeContext: "Genom att signera bekräftar deltagaren endast att han har granskat detta interna testdokument och genomfört signeringsfunktionen. Signeringen gäller ingen offert, beställning eller annat kommersiellt avtal.",
			DeclineReason: "Test",
			OpenURL:       "https://example.invalid/documents/example?x=1&y=2",
			ApproveURL:    "https://example.invalid/a/cr?t=approve",
			DenyURL:       "https://example.invalid/a/cr?t=deny",
		}
		c.ChangeQuote = c.ChangeContext
		if locale == "sv-long" {
			c.Locale = "sv"
			c.RecipientName = "Exempelperson med ett mycket långt namn"
			c.DocumentName = "Ett internt funktionstest med en lång dokumentrubrik som fortfarande ska vara lätt att läsa på mobilen"
		}
		_, native, _, err := Render(KindChangesRequested, c)
		if err != nil {
			t.Fatal(err)
		}
		write(locale+"-native", native)
		for _, mode := range []string{"light", "dark"} {
			// A synthetic theme exercises tenant colours without installation data.
			d := DefaultServiceEmailDesignV1()
			d.Primary = "#ff4b00"
			if mode == "dark" {
				d.Background, d.Surface, d.Text = "#111111", "#151515", "#fffcf4"
			}
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := CanonicalServiceEmailDesignV1(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			_, body, _, err := RenderServiceEmailV1(KindChangesRequested, c, &ServiceEmailTemplateV1{Revision: 1, DesignJSON: canonical})
			if err != nil {
				t.Fatal(err)
			}
			write(locale+"-workspace-"+mode, body)
		}
	}
}
