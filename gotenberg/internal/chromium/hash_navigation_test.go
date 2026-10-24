// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
)

func hashNavigationDocument(frame, loader, request string) *network.EventRequestWillBeSent {
	return &network.EventRequestWillBeSent{FrameID: cdp.FrameID(frame), LoaderID: cdp.LoaderID(loader), RequestID: network.RequestID(request), Type: network.ResourceTypeDocument}
}

func hashNavigationLifecycleEvents(n *hashNavigation, frame, loader string, names ...string) {
	for _, name := range names {
		n.observe(&page.EventLifecycleEvent{FrameID: cdp.FrameID(frame), LoaderID: cdp.LoaderID(loader), Name: name})
	}
}

func TestHashNavigationRequiresExactMainDocument(t *testing.T) {
	for _, early := range []bool{false, true} {
		t.Run(map[bool]string{false: "after-reply", true: "before-reply"}[early], func(t *testing.T) {
			n := newHashNavigation(true, true)
			if !early {
				if err := n.bind("main-frame", "new-loader", "", false); err != nil {
					t.Fatal(err)
				}
			}
			n.observe(hashNavigationDocument("iframe", "iframe-loader", "iframe-request"))
			n.observe(&network.EventLoadingFinished{RequestID: "iframe-request"})
			n.observe(&network.EventLoadingFinished{RequestID: "image-request"})
			hashNavigationLifecycleEvents(n, "iframe", "iframe-loader", "DOMContentLoaded", "load")
			hashNavigationLifecycleEvents(n, "main-frame", "old-loader", "DOMContentLoaded", "load")
			// Unkeyed Page events cannot admit any document.
			n.observe(&page.EventDomContentEventFired{})
			n.observe(&page.EventLoadEventFired{})
			n.observe(hashNavigationDocument("main-frame", "new-loader", "main-request"))
			hashNavigationLifecycleEvents(n, "main-frame", "new-loader", "DOMContentLoaded", "load")
			if early {
				if err := n.bind("main-frame", "new-loader", "", false); err != nil {
					t.Fatal(err)
				}
			}
			if complete, err := n.state(); complete || err != nil {
				t.Fatal("unrelated terminal events admitted incomplete main document")
			}
			n.observe(&network.EventLoadingFailed{RequestID: "image-request", ErrorText: "private-error"})
			n.observe(&page.EventLifecycleEvent{FrameID: "main-frame", LoaderID: "new-loader", Name: "networkIdle2"})
			if complete, err := n.state(); complete || err != nil {
				t.Fatal("unrelated failure or legacy idle name changed admission")
			}
			n.observe(&network.EventLoadingFinished{RequestID: "main-request"})
			if err := n.wait(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHashNavigationRetainsFastEarlyCompletionAndRedirectIdentity(t *testing.T) {
	n := newHashNavigation(false, false)
	n.observe(hashNavigationDocument("frame", "loader", "request"))
	// Redirect uses the same protocol identity, independently of URL changes.
	n.observe(hashNavigationDocument("frame", "loader", "request"))
	n.observe(&network.EventLoadingFinished{RequestID: "request"})
	hashNavigationLifecycleEvents(n, "frame", "loader", "DOMContentLoaded", "load", "networkIdle")
	if err := n.bind("frame", "loader", "", false); err != nil {
		t.Fatal(err)
	}
	if complete, err := n.state(); complete || err != nil || n.early != nil {
		t.Fatal("missing requested almost-idle event was accepted or journal retained")
	}
	hashNavigationLifecycleEvents(n, "frame", "old", "networkAlmostIdle")
	if complete, _ := n.state(); complete {
		t.Fatal("old loader admitted almost-idle")
	}
	hashNavigationLifecycleEvents(n, "frame", "loader", "networkAlmostIdle")
	if err := n.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHashNavigationRefusesMainFailureIncludingUnknownOrCanceled(t *testing.T) {
	for _, early := range []bool{false, true} {
		for _, name := range []string{"net::ERR_CONTENT_LENGTH_MISMATCH", "net::UNKNOWN_NEW_ERROR-private-name", "net::ERR_ABORTED", "net::ERR_ACCESS_DENIED"} {
			n := newHashNavigation(true, true)
			if !early {
				if err := n.bind("frame", "loader", "", false); err != nil {
					t.Fatal(err)
				}
			}
			n.observe(hashNavigationDocument("frame", "loader", "request"))
			n.observe(&network.EventLoadingFailed{RequestID: "request", ErrorText: name, Canceled: true})
			hashNavigationLifecycleEvents(n, "frame", "loader", "DOMContentLoaded", "load")
			n.observe(&network.EventLoadingFinished{RequestID: "request"})
			if early {
				_ = n.bind("frame", "loader", "", false)
			}
			if err := n.wait(context.Background()); !errors.Is(err, ErrLoadingFailed) || strings.Contains(err.Error(), "private-name") {
				t.Fatal("main failure accepted or private error text retained: ", err)
			}
		}
	}
}

func TestHashNavigationRefusesMissingAmbiguousOrDownloadIdentity(t *testing.T) {
	for _, c := range []struct {
		name, frame, loader, errorText string
		download                       bool
	}{
		{"no-frame", "", "loader", "", false},
		{"same-document", "frame", "", "", false},
		{"navigation-failure", "frame", "loader", "private-message", false},
		{"download", "frame", "loader", "", true},
		{"oversized-frame", strings.Repeat("x", 257), "loader", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := newHashNavigation(true, true)
			if err := n.bind(cdp.FrameID(c.frame), cdp.LoaderID(c.loader), c.errorText, c.download); !errors.Is(err, ErrLoadingFailed) || strings.Contains(err.Error(), "private-message") {
				t.Fatal("invalid navigation result admitted/leaked: ", err)
			}
		})
	}
	for _, request := range []string{"", "different"} {
		n := newHashNavigation(true, true)
		n.observe(hashNavigationDocument("frame", "loader", "first"))
		n.observe(hashNavigationDocument("frame", "loader", request))
		if err := n.bind("frame", "loader", "", false); !errors.Is(err, ErrLoadingFailed) {
			t.Fatal("ambiguous request accepted: ", err)
		}
	}
}

func TestHashNavigationBoundsEarlyEventsAndHonorsCancellation(t *testing.T) {
	n := newHashNavigation(true, true)
	for i := 0; i <= hashNavigationEarlyLimit; i++ {
		n.observe(&network.EventLoadingFinished{RequestID: "other"})
	}
	if len(n.early) != hashNavigationEarlyLimit || !errors.Is(n.bind("frame", "loader", "", false), ErrLoadingFailed) {
		t.Fatal("early journal unbounded or overflow accepted")
	}
	n = newHashNavigation(true, true)
	n.observe(hashNavigationDocument("frame", "loader", "request"))
	hashNavigationLifecycleEvents(n, "frame", "loader", "DOMContentLoaded", "load")
	n.observe(&network.EventLoadingFinished{RequestID: "request"})
	if err := n.bind("frame", "loader", "", false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := n.wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled caller admitted completed navigation")
	}
}

func TestHashNavigationConcurrentObservationBindingAndWaiting(t *testing.T) {
	n := newHashNavigation(true, true)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 32; j++ {
				n.observe(&network.EventLoadingFinished{RequestID: "unrelated"})
				hashNavigationLifecycleEvents(n, "other", "loader", "load")
				_, _ = n.state()
			}
		})
	}
	if err := n.bind("frame", "loader", "", false); err != nil {
		t.Fatal(err)
	}
	n.observe(hashNavigationDocument("frame", "loader", "request"))
	hashNavigationLifecycleEvents(n, "frame", "loader", "DOMContentLoaded", "load")
	n.observe(&network.EventLoadingFinished{RequestID: "request"})
	if err := n.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestHashNavigationInitialRootClassifiesRedirectAndIframeSeparately(t *testing.T) {
	n := newHashNavigation(true, true)
	if err := n.setInitialFrame("root", "initial"); err != nil {
		t.Fatal(err)
	}
	n.observe(hashNavigationDocument("root", "new", "main"))
	response := &network.EventResponseReceived{FrameID: "root", LoaderID: "new", RequestID: "main", Type: network.ResourceTypeDocument}
	if !n.isMainResponse(response) || !n.isMainRequest("main") {
		t.Fatal("early committed main response lost before Navigate reply")
	}
	iframe := &network.EventResponseReceived{FrameID: "iframe", LoaderID: "child", RequestID: "child-request", Type: network.ResourceTypeDocument}
	if n.isMainResponse(iframe) || n.isMainRequest("child-request") {
		t.Fatal("iframe classified as main document")
	}
	if err := n.bind("root", "new", "", false); err != nil || !n.isMainResponse(response) {
		t.Fatal("redirected response identity lost after binding: ", err)
	}
	response.LoaderID = "old"
	if n.isMainResponse(response) {
		t.Fatal("old loader response borrowed current main identity")
	}
}

func TestHashNavigationLateFailureOrRootReplacementCannotBorrowCompletion(t *testing.T) {
	for _, mode := range []string{"late-failure", "new-loader-event", "new-frame-event", "current-root-barrier"} {
		t.Run(mode, func(t *testing.T) {
			n := newHashNavigation(true, true)
			if err := n.setInitialFrame("frame", "about-blank"); err != nil {
				t.Fatal(err)
			}
			n.observe(&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "frame", LoaderID: "about-blank"}})
			n.observe(hashNavigationDocument("frame", "loader", "request"))
			hashNavigationLifecycleEvents(n, "frame", "loader", "DOMContentLoaded", "load")
			n.observe(&network.EventLoadingFinished{RequestID: "request"})
			if err := n.bind("frame", "loader", "", false); err != nil {
				t.Fatal(err)
			}
			if err := n.checkRoot(&cdp.Frame{ID: "frame", LoaderID: "loader"}); err != nil {
				t.Fatal("complete current root refused: ", err)
			}
			switch mode {
			case "late-failure":
				n.observe(&network.EventLoadingFailed{RequestID: "request", ErrorText: "net::UNKNOWN"})
			case "new-loader-event":
				n.observe(&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "frame", LoaderID: "replacement"}})
			case "new-frame-event":
				n.observe(&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "replacement", LoaderID: "loader"}})
			case "current-root-barrier":
				_ = n.checkRoot(&cdp.Frame{ID: "frame", LoaderID: "replacement"})
			}
			if err := n.checkRoot(&cdp.Frame{ID: "frame", LoaderID: "loader"}); !errors.Is(err, ErrLoadingFailed) {
				t.Fatal("old success erased a sticky refusal: ", err)
			}
		})
	}
}

func TestHashNavigationEarlyReplacementAndRestorationRemainRefused(t *testing.T) {
	for _, replacement := range []string{"different", "initial"} {
		n := newHashNavigation(true, true)
		if err := n.setInitialFrame("frame", "initial"); err != nil {
			t.Fatal(err)
		}
		n.observe(&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "frame", LoaderID: "initial"}})
		n.observe(hashNavigationDocument("frame", "expected", "request"))
		n.observe(&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "frame", LoaderID: "expected"}})
		n.observe(&network.EventLoadingFinished{RequestID: "request"})
		hashNavigationLifecycleEvents(n, "frame", "expected", "DOMContentLoaded", "load")
		n.observe(&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "frame", LoaderID: cdp.LoaderID(replacement)}})
		n.observe(&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "frame", LoaderID: "expected"}})
		if err := n.bind("frame", "expected", "", false); !errors.Is(err, ErrLoadingFailed) {
			t.Fatal("early replacement dropped: ", err)
		}
		if err := n.checkRoot(&cdp.Frame{ID: "frame", LoaderID: "expected"}); !errors.Is(err, ErrLoadingFailed) {
			t.Fatal("restoration erased replacement: ", err)
		}
	}
}
