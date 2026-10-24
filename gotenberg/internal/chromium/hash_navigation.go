// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
)

const hashNavigationEarlyLimit = 1024

type hashNavigationContextKey struct{}

const (
	hashNavigationRequest uint8 = iota + 1
	hashNavigationFinished
	hashNavigationFailed
	hashNavigationLifecycle
	hashNavigationRoot
)

const (
	hashNavigationDOM uint8 = 1 << iota
	hashNavigationLoad
	hashNavigationIdle
	hashNavigationAlmostIdle
)

// Keep only protocol identities and closed lifecycle flags. Do not retain page
// URLs, headers, error text or arbitrary event payloads while Navigate replies.
type hashNavigationEvent struct {
	kind    uint8
	frame   cdp.FrameID
	loader  cdp.LoaderID
	request network.RequestID
	flags   uint8
	failure uint8
}

// A fresh conversion tab must load a new, positively identified main document.
// Events may precede the Page.navigate reply, so a finite early-event journal is
// replayed only after that reply supplies the exact frame and loader identity.
// This state never starts a goroutine or substitutes an iframe/resource event.
type hashNavigation struct {
	mu            sync.Mutex
	notify        chan struct{}
	early         []hashNavigationEvent
	bound         bool
	frame         cdp.FrameID
	loader        cdp.LoaderID
	request       network.RequestID
	initialFrame  cdp.FrameID
	initialLoader cdp.LoaderID
	pendingMain   network.RequestID
	abort         context.CancelFunc
	finished      bool
	flags         uint8
	required      uint8
	err           error
	failure       uint8
}

func newHashNavigation(skipIdle, skipAlmostIdle bool) *hashNavigation {
	required := hashNavigationDOM | hashNavigationLoad
	if !skipIdle {
		required |= hashNavigationIdle
	}
	if !skipAlmostIdle {
		required |= hashNavigationAlmostIdle
	}
	return &hashNavigation{notify: make(chan struct{}, 1), required: required}
}

func (n *hashNavigation) signalLocked() {
	select {
	case n.notify <- struct{}{}:
	default:
	}
}

func (n *hashNavigation) failLocked(reason string) {
	if n.err == nil {
		n.err = fmt.Errorf("main document %s: %w", reason, ErrLoadingFailed)
	}
	n.signalLocked()
}

func (n *hashNavigation) observe(ev any) {
	var e hashNavigationEvent
	switch ev := ev.(type) {
	case *network.EventRequestWillBeSent:
		if ev.Type != network.ResourceTypeDocument {
			return
		}
		e = hashNavigationEvent{kind: hashNavigationRequest, frame: ev.FrameID, loader: ev.LoaderID, request: ev.RequestID}
	case *network.EventLoadingFinished:
		e = hashNavigationEvent{kind: hashNavigationFinished, request: ev.RequestID}
	case *network.EventLoadingFailed:
		failure := uint8(4)
		switch ev.ErrorText {
		case "net::ERR_CONTENT_LENGTH_MISMATCH":
			failure = 1
		case "net::ERR_INCOMPLETE_CHUNKED_ENCODING":
			failure = 2
		case "net::ERR_INVALID_CHUNKED_ENCODING":
			failure = 3
		case "net::ERR_ACCESS_DENIED":
			failure = 5
		}
		e = hashNavigationEvent{kind: hashNavigationFailed, request: ev.RequestID, failure: failure}
	case *page.EventLifecycleEvent:
		var flag uint8
		switch ev.Name {
		case "DOMContentLoaded":
			flag = hashNavigationDOM
		case "load":
			flag = hashNavigationLoad
		case "networkIdle":
			flag = hashNavigationIdle
		case "networkAlmostIdle":
			flag = hashNavigationAlmostIdle
		default:
			return
		}
		e = hashNavigationEvent{kind: hashNavigationLifecycle, frame: ev.FrameID, loader: ev.LoaderID, flags: flag}
	case *page.EventFrameNavigated:
		if ev.Frame == nil || ev.Frame.ParentID != "" {
			return
		}
		e = hashNavigationEvent{kind: hashNavigationRoot, frame: ev.Frame.ID, loader: ev.Frame.LoaderID}
	default:
		return
	}
	n.mu.Lock()
	defer func() {
		abort := n.abort
		failed := n.err != nil
		n.mu.Unlock()
		if failed && abort != nil {
			// This is a plain context cancel, never chromedp's joining cancel.
			abort()
		}
	}()
	if n.err != nil {
		return
	}
	if len(e.frame) > 256 || len(e.loader) > 256 || len(e.request) > 256 {
		n.failLocked("event identity exceeds bound")
		return
	}
	if !n.bound {
		if e.kind == hashNavigationRequest && n.initialFrame != "" && e.frame == n.initialFrame && e.loader != "" {
			n.pendingMain = e.request
		}
		if len(n.early) == hashNavigationEarlyLimit {
			n.failLocked("early event journal exceeds bound")
			return
		}
		n.early = append(n.early, e)
		return
	}
	n.applyLocked(e)
}

func (n *hashNavigation) applyLocked(e hashNavigationEvent) {
	switch e.kind {
	case hashNavigationRequest:
		if e.frame != n.frame || e.loader != n.loader {
			return
		}
		if e.request == "" || (n.request != "" && n.request != e.request) {
			n.failLocked("request identity missing or ambiguous")
			return
		}
		// Redirects repeat RequestWillBeSent with the same request/loader.
		n.request = e.request
	case hashNavigationFinished:
		if n.request != "" && e.request == n.request {
			n.finished = true
		}
	case hashNavigationFailed:
		if n.request != "" && e.request == n.request {
			// Every failure of this exact request is fatal, including canceled
			// requests and Chromium error names unknown to the legacy listener.
			n.failure = e.failure
			n.failLocked("request failed")
		}
	case hashNavigationLifecycle:
		if e.frame == n.frame && e.loader == n.loader {
			n.flags |= e.flags
		}
	case hashNavigationRoot:
		if e.frame != n.frame || e.loader != n.loader {
			n.failLocked("root document replaced")
		}
	}
	n.signalLocked()
}

func (n *hashNavigation) bind(frame cdp.FrameID, loader cdp.LoaderID, errorText string, download bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	reason := ""
	switch {
	case n.bound:
		reason = "navigation already bound"
	case errorText == "net::ERR_ACCESS_DENIED":
		n.failure = 5
		reason = "navigation denied by request policy"
	case errorText != "":
		reason = "navigation reported failure"
	case download:
		reason = "navigation became a download"
	case frame == "":
		reason = "navigation frame missing"
	case loader == "":
		reason = "navigation loader missing"
	case n.initialFrame != "" && frame != n.initialFrame:
		reason = "navigation root frame changed"
	case len(frame) > 256 || len(loader) > 256:
		reason = "navigation identity exceeds bound"
	}
	if reason != "" {
		n.failLocked(reason)
		return n.err
	}
	if n.err != nil {
		return n.err
	}
	n.bound, n.frame, n.loader = true, frame, loader
	seenExpected := false
	for _, e := range n.early {
		// Ignore only the exact captured initial root before this navigation's
		// first request/root event. A replacement and restoration must retain
		// its refusal even when the final barrier sees the expected loader.
		if e.kind == hashNavigationRoot && (e.frame != frame || e.loader != loader) {
			if !seenExpected && e.frame == n.initialFrame && e.loader == n.initialLoader {
				continue
			}
		}
		if (e.kind == hashNavigationRequest || e.kind == hashNavigationRoot) && e.frame == frame && e.loader == loader {
			seenExpected = true
		}
		n.applyLocked(e)
		if n.err != nil {
			break
		}
	}
	n.early = nil
	n.signalLocked()
	return n.err
}

func (n *hashNavigation) state() (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.bound && n.request != "" && n.finished && n.flags&n.required == n.required, n.err
}

func (n *hashNavigation) isMainRequest(request network.RequestID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if request == "" {
		return false
	}
	return (n.bound && request == n.request) || (!n.bound && request == n.pendingMain)
}

func (n *hashNavigation) isMainResponse(e *network.EventResponseReceived) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if e.Type != network.ResourceTypeDocument || e.FrameID == "" {
		return false
	}
	if !n.bound {
		return n.initialFrame != "" && e.FrameID == n.initialFrame
	}
	return e.FrameID == n.frame && e.LoaderID == n.loader && e.RequestID == n.request && n.request != ""
}

func (n *hashNavigation) setInitialFrame(frame cdp.FrameID, loader cdp.LoaderID) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if frame == "" || len(frame) > 256 || len(loader) > 256 || n.initialFrame != "" || n.bound {
		n.failLocked("initial root identity invalid")
		return n.err
	}
	n.initialFrame = frame
	n.initialLoader = loader
	return n.err
}

func (n *hashNavigation) checkRoot(frame *cdp.Frame) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if frame == nil || frame.ID != n.frame || frame.LoaderID != n.loader || !n.bound || n.request == "" || !n.finished || n.flags&n.required != n.required {
		n.failLocked("current root or completion changed")
	}
	return n.err
}

func (n *hashNavigation) logWitness(ctx context.Context, logger *slog.Logger, stage string) {
	n.mu.Lock()
	frame, loader, request, bound, finished, failed, flags, failure := n.frame, n.loader, n.request, n.bound, n.finished, n.err != nil, n.flags, n.failure
	n.mu.Unlock()
	logger.DebugContext(ctx, "hash main document navigation "+stage,
		"frame_id", string(frame), "loader_id", string(loader), "request_id", string(request),
		"bound", bound, "loading_finished", finished, "failed", failed, "lifecycle_flags", flags, "loading_failure_class", failure)
}

func (n *hashNavigation) wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait for main document: %w", err)
		}
		complete, err := n.state()
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for main document: %w", ctx.Err())
		case <-n.notify:
		}
	}
}
