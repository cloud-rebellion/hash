package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/storage"
)

func TestTemplatePDFBodyRequiresOriginalNativeSourceAndRetiredSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for name, h := range map[string]*ApplicationPDFTemplateSourceV1{
		"nil": nil, "empty": {}, "no session": {state: &applicationPDFTemplateSourceStateV1{}},
		"closed": {state: &applicationPDFTemplateSourceStateV1{closed: true}},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			err := h.WithPDFBodyV1(ctx, &storage.Client{}, func([]byte) error { called = true; return nil })
			if !errors.Is(err, ErrPDFTemplateSourceV1) || called {
				t.Fatal("non-native source reached provider consumer", err)
			}
		})
	}
}
