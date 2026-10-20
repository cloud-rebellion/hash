package chromium

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/chromedp/cdproto/network"
)

func TestStrictResourceFailurePolicyAndMainRequestOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, text                                     string
		strict, document, main, wantResource, wantMain bool
	}{
		{name: "policy-denial-strict", text: "net::ERR_ACCESS_DENIED", strict: true, wantResource: true},
		{name: "unknown-strict-private-text", text: "private-protocol-reason?token=do-not-expose", strict: true, wantResource: true},
		{name: "aborted-resource-strict", text: "net::ERR_ABORTED", strict: true, wantResource: true},
		{name: "missing-file-strict", text: "net::ERR_FILE_NOT_FOUND", strict: true, wantResource: true},
		{name: "legacy-unknown-permissive", text: "net::ERR_ACCESS_DENIED"},
		{name: "legacy-known-permissive", text: "net::ERR_CONNECTION_REFUSED", wantResource: true},
		{name: "iframe-failure-does-not-abort-main", text: "net::ERR_ACCESS_DENIED", strict: true, document: true, wantResource: true},
		{name: "exact-main-failure-aborts-task", text: "net::ERR_CONNECTION_REFUSED", strict: true, document: true, main: true, wantMain: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			navigation := newHashNavigation(true, true)
			navigation.observe(&network.EventRequestWillBeSent{RequestID: "main-request", FrameID: "root-frame", LoaderID: "root-loader", Type: network.ResourceTypeDocument})
			if err := navigation.bind("root-frame", "root-loader", "", false); err != nil {
				t.Fatal(err)
			}
			var mainFailure, resourceFailure error
			var mainMu, resourceMu sync.RWMutex
			ctx, abort := context.WithCancel(context.Background())
			defer abort()
			event := &network.EventLoadingFailed{RequestID: "asset-request", Type: network.ResourceTypeImage, ErrorText: tc.text}
			if tc.document {
				event.Type = network.ResourceTypeDocument
			}
			if tc.main {
				event.RequestID = "main-request"
			}
			recordEventLoadingFailed(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), eventLoadingFailedOptions{
				failOnResourceLoadingFailed: tc.strict,
				mainNavigation:              navigation, loadingFailed: &mainFailure, loadingFailedMu: &mainMu,
				resourceLoadingFailed: &resourceFailure, resourceLoadingFailedMu: &resourceMu, cancelOnMainPageError: abort,
			}, event)
			if (mainFailure != nil) != tc.wantMain || (resourceFailure != nil) != tc.wantResource || (ctx.Err() != nil) != tc.wantMain {
				t.Fatalf("incorrect failure/abort ownership: main=%v resource=%v context=%v", mainFailure, resourceFailure, ctx.Err())
			}
			if resourceFailure != nil && strings.Contains(resourceFailure.Error(), "do-not-expose") {
				t.Fatal("arbitrary browser protocol text escaped into public render failure")
			}
		})
	}
}
