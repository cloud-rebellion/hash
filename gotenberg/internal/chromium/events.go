package chromium

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/dlclark/regexp2"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

// listenForNetworkActivity accumulates per-conversion network activity into
// aggregate from the always-on Network domain events. It is a no-op when
// aggregate is nil.
func listenForNetworkActivity(ctx context.Context, aggregate *networkAggregate) {
	if aggregate == nil {
		return
	}

	chromedp.ListenTarget(ctx, func(ev any) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			aggregate.onResponseReceived(e)
		case *network.EventLoadingFinished:
			aggregate.onLoadingFinished(e)
		case *network.EventLoadingFailed:
			aggregate.onLoadingFailed(e)
		}
	})
}

type eventWebSocketCreatedOptions struct {
	allowList, denyList []*regexp2.Regexp
	denyPrivateIPs      bool
	denyPublicIPs       bool
}

// listenForEventWebSocketCreated validates the target of every WebSocket
// handshake against the same allow / deny lists and IP-class policy as
// [listenForEventRequestPaused]. Chromium never surfaces a WebSocket
// handshake as a fetch.EventRequestPaused, so without this listener a page
// could open a WebSocket to an address the outbound filter would otherwise
// block. See https://github.com/gotenberg/gotenberg/issues/1011.
//
// This listener records an operator-visible warning with the full ws:// URL.
// The connection itself is severed by the pinning proxy, which every
// WebSocket handshake traverses once the implicit loopback / link-local proxy
// bypass is removed (see the "<-loopback>" flag in browser.go). When the
// operator configures a custom proxy or host-resolver mappings, the pinning
// proxy is not started; the WebSocket then follows the operator's egress path
// and this warning is the remaining safeguard, since a WebSocket handshake
// cannot be aborted through the CDP Network domain.
func listenForEventWebSocketCreated(ctx context.Context, logger *slog.Logger, options eventWebSocketCreatedOptions) {
	chromedp.ListenTarget(ctx, func(ev any) {
		e, ok := ev.(*network.EventWebSocketCreated)
		if !ok {
			return
		}

		go func() {
			logger.DebugContext(ctx, fmt.Sprintf("event EventWebSocketCreated fired for '%s'", e.URL))

			deadline, ok := ctx.Deadline()
			if !ok {
				logger.ErrorContext(ctx, "context has no deadline, cannot filter WebSocket URL")
				return
			}

			err := gotenberg.FilterOutboundURL(ctx, e.URL, options.allowList, options.denyList, deadline,
				gotenberg.WithDenyPrivateIPs(options.denyPrivateIPs),
				gotenberg.WithDenyPublicIPs(options.denyPublicIPs),
			)
			if err != nil {
				logger.WarnContext(ctx, err.Error())
			}
		}()
	})
}

type eventRequestPausedOptions struct {
	allowList, denyList []*regexp2.Regexp
	denyPrivateIPs      bool
	denyPublicIPs       bool
	allowedFilePrefixes []string
	extraHttpHeaders    []ExtraHttpHeader
}

// listenForEventRequestPaused listens for requests to check if they are
// allowed or not.  It also set the extra HTTP headers, if any.
// See https://github.com/gotenberg/gotenberg/issues/1011.
// TODO: https://chromedevtools.github.io/devtools-protocol/tot/Network/#method-setBlockedURLs (experimental for now).
func listenForEventRequestPaused(ctx context.Context, logger *slog.Logger, options eventRequestPausedOptions) {
	if len(options.extraHttpHeaders) == 0 {
		logger.DebugContext(ctx, "no extra HTTP headers")
	} else {
		logger.DebugContext(ctx, fmt.Sprintf("extra HTTP headers: %+v", options.extraHttpHeaders))
	}

	// Shared by every scope match of this conversion, across all paused
	// requests. Its lifetime is the conversion, as this function is called once
	// per conversion with that conversion's context.
	budget := newScopeMatchBudget(scopeMatchBudgetPerConversion)

	chromedp.ListenTarget(ctx, func(ev any) {
		if e, ok := ev.(*fetch.EventRequestPaused); ok {
			go func() {
				logger.DebugContext(ctx, fmt.Sprintf("event EventRequestPaused fired for '%s'", e.Request.URL))
				allow := true

				deadline, ok := ctx.Deadline()
				if !ok {
					logger.ErrorContext(ctx, "context has no deadline, cannot filter URL")
					return
				}

				err := gotenberg.FilterOutboundURL(ctx, e.Request.URL, options.allowList, options.denyList, deadline,
					gotenberg.WithDenyPrivateIPs(options.denyPrivateIPs),
					gotenberg.WithDenyPublicIPs(options.denyPublicIPs),
				)
				if err != nil {
					logger.WarnContext(ctx, err.Error())
					allow = false
				}

				// Sub-resource file:// URLs are opt-in per route. A route
				// that renders local files (HTML, Markdown) populates
				// allowedFilePrefixes with the request working directory
				// so its own assets load while sibling requests' /tmp
				// paths stay out of reach. Every other route leaves the
				// slice empty; treat that as default-deny so a file://
				// sub-resource that slips past the deny-list (which
				// exempts /tmp/) still cannot read the working
				// directories of other in-flight conversions.
				if allow && strings.HasPrefix(e.Request.URL, "file://") && !isAllowedFileSubResource(e.Request.URL, options.allowedFilePrefixes) {
					logger.WarnContext(ctx, fmt.Sprintf("'%s' is not within any allowed file prefix", e.Request.URL))
					allow = false
				}

				cctx := chromedp.FromContext(ctx)
				executorCtx := cdp.WithExecutor(ctx, cctx.Target)

				if !allow {
					// Keep the existing AccessDenied policy. The owned navigation
					// observer now refuses every exact-main failure, including
					// AccessDenied, while iframe failures keep resource policy.
					req := fetch.FailRequest(e.RequestID, network.ErrorReasonAccessDenied)
					err = req.Do(executorCtx)
					if err != nil {
						logger.ErrorContext(ctx, fmt.Sprintf("fail request: %s", err))
					}
					return
				}

				req := fetch.ContinueRequest(e.RequestID)

				var extraHttpHeadersToSet []ExtraHttpHeader
				if len(options.extraHttpHeaders) > 0 {
					// The user wants to set extra HTTP headers.

					// First, we have to check if at least one header has to be
					// set for the current request.
					for _, header := range options.extraHttpHeaders {
						// This goroutine outlives the response: nothing cancels an
						// in-flight match, so stop as soon as the conversion is over.
						select {
						case <-ctx.Done():
							return
						default:
						}

						if header.Scope == nil {
							// Non-scoped header.
							logger.DebugContext(ctx, fmt.Sprintf("extra HTTP header '%s' will be set for request URL '%s'", header.Name, e.Request.URL))
							extraHttpHeadersToSet = append(extraHttpHeadersToSet, header)
							continue
						}

						if !budget.tryAcquire() {
							// Treat the remaining scoped headers as non-matching rather
							// than spending more CPU on a request the client may already
							// have given up on.
							logger.WarnContext(ctx, fmt.Sprintf("scope matching budget of %s exhausted, extra HTTP header '%s' and any subsequent scoped header will not be set; simplify the 'scope' patterns or reduce the number of scoped headers", scopeMatchBudgetPerConversion, header.Name))
							break
						}

						matchStart := time.Now()
						ok, err := header.Scope.MatchString(e.Request.URL)
						budget.consume(time.Since(matchStart))

						switch {
						case err != nil:
							logger.ErrorContext(ctx, fmt.Sprintf("fail to match extra HTTP header '%s' scope with URL '%s': %s", header.Name, e.Request.URL, err))
						case ok:
							logger.DebugContext(ctx, fmt.Sprintf("extra HTTP header '%s' (scoped) will be set for request URL '%s'", header.Name, e.Request.URL))
							extraHttpHeadersToSet = append(extraHttpHeadersToSet, header)
						default:
							logger.DebugContext(ctx, fmt.Sprintf("scoped extra HTTP header '%s' (scoped) will not be set for request URL '%s'", header.Name, e.Request.URL))
						}
					}
				}

				if len(extraHttpHeadersToSet) > 0 {
					logger.DebugContext(ctx, fmt.Sprintf("setting extra HTTP headers for request URL '%s': %+v", e.Request.URL, extraHttpHeadersToSet))

					originalHeaders := e.Request.Headers
					headers := make(map[string]string)

					for key, value := range originalHeaders {
						strValue, ok := value.(string)
						if ok {
							headers[key] = strValue
						} else {
							logger.ErrorContext(ctx, fmt.Sprintf("ignoring header '%s' for URL '%s' since it cannot be cast to a string", key, e.Request.URL))
						}
					}

					var headersEntries []*fetch.HeaderEntry
					for key, value := range headers {
						headersEntries = append(headersEntries, &fetch.HeaderEntry{
							Name:  key,
							Value: value,
						})
					}
					for _, header := range extraHttpHeadersToSet {
						headersEntries = append(headersEntries, &fetch.HeaderEntry{
							Name:  header.Name,
							Value: header.Value,
						})
					}

					req.Headers = headersEntries
				}

				err = req.Do(executorCtx)
				if err != nil {
					logger.ErrorContext(ctx, fmt.Sprintf("continue request: %s", err))
				}
			}()
		}
	})
}

type eventResponseReceivedOptions struct {
	mainNavigation                  *hashNavigation
	mainPageUrl                     string
	failOnHttpStatusCodes           []int64
	invalidHttpStatusCode           *error
	invalidHttpStatusCodeMu         *sync.RWMutex
	failOnResourceOnHttpStatusCode  []int64
	ignoreResourceHttpStatusDomains []string
	invalidResourceHttpStatusCode   *error
	invalidResourceHttpStatusCodeMu *sync.RWMutex
	cancelOnMainPageError           context.CancelFunc
}

// listenForEventResponseReceived listens for an invalid HTTP status code
// returned by the main page or by one or more resources.
// See:
// https://github.com/gotenberg/gotenberg/issues/613.
// https://github.com/gotenberg/gotenberg/issues/1021.
func listenForEventResponseReceived(
	ctx context.Context,
	logger *slog.Logger,
	options eventResponseReceivedOptions,
) {
	normalizedIgnoreDomains := normalizeDomains(options.ignoreResourceHttpStatusDomains)

	for _, code := range []int64{199, 299, 399, 499, 599} {
		if slices.Contains(options.failOnHttpStatusCodes, code) {
			for i := code - 99; i <= code; i++ {
				options.failOnHttpStatusCodes = append(options.failOnHttpStatusCodes, i)
			}
		}

		if slices.Contains(options.failOnResourceOnHttpStatusCode, code) {
			for i := code - 99; i <= code; i++ {
				options.failOnResourceOnHttpStatusCode = append(options.failOnResourceOnHttpStatusCode, i)
			}
		}
	}

	chromedp.ListenTarget(ctx, func(ev any) {
		if ev, ok := ev.(*network.EventResponseReceived); ok {
			mainPage := ev.Response.URL == options.mainPageUrl
			if options.mainNavigation != nil {
				mainPage = options.mainNavigation.isMainResponse(ev)
			}
			if mainPage {
				logger.DebugContext(ctx, fmt.Sprintf("event EventResponseReceived fired for main page: %+v", ev.Response))

				if slices.Contains(options.failOnHttpStatusCodes, ev.Response.Status) {
					options.invalidHttpStatusCodeMu.Lock()
					defer options.invalidHttpStatusCodeMu.Unlock()

					*options.invalidHttpStatusCode = fmt.Errorf("%d: %s", ev.Response.Status, ev.Response.StatusText)

					// Cancel the task context so that any in-flight wait
					// operations (waitForSelector, waitForExpression, etc.)
					// abort immediately instead of polling until timeout.
					// See https://github.com/gotenberg/gotenberg/issues/1492.
					if options.cancelOnMainPageError != nil {
						options.cancelOnMainPageError()
					}
				}

				return
			}

			logger.DebugContext(ctx, fmt.Sprintf("event EventResponseReceived fired for a resource: %+v", ev.Response))

			if slices.Contains(options.failOnResourceOnHttpStatusCode, ev.Response.Status) {
				if !shouldCheckResourceHttpStatusCode(ev.Response.URL, normalizedIgnoreDomains) {
					logger.DebugContext(ctx, fmt.Sprintf("skip resource HTTP status code check for '%s' due to domain filtering", ev.Response.URL))
					return
				}

				options.invalidResourceHttpStatusCodeMu.Lock()
				defer options.invalidResourceHttpStatusCodeMu.Unlock()

				*options.invalidResourceHttpStatusCode = errors.Join(
					*options.invalidResourceHttpStatusCode,
					fmt.Errorf("%s - %d: %s", ev.Response.URL, ev.Response.Status, http.StatusText(int(ev.Response.Status))),
				)
			}
		}
	})
}

// isAllowedFileSubResource reports whether a file:// sub-resource URL is
// within at least one prefix. An empty prefix list rejects every
// file:// URL so routes that never populate the list (for example
// /forms/chromium/convert/url) default-deny reads from /tmp/, blocking
// cross-request enumeration.
func isAllowedFileSubResource(rawURL string, allowedFilePrefixes []string) bool {
	if len(allowedFilePrefixes) == 0 {
		return false
	}
	for _, prefix := range allowedFilePrefixes {
		if strings.HasPrefix(rawURL, "file://"+prefix) {
			return true
		}
	}
	return false
}

func shouldCheckResourceHttpStatusCode(rawURL string, ignoreDomains []string) bool {
	host := hostnameFromURL(rawURL)

	if len(ignoreDomains) > 0 && matchesAnyDomain(host, ignoreDomains) {
		return false
	}

	return true
}

func hostnameFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func normalizeDomains(domains []string) []string {
	normalized := make([]string, 0, len(domains))

	for _, domain := range domains {
		d := normalizeDomain(domain)
		if d == "" {
			continue
		}
		normalized = append(normalized, d)
	}

	return normalized
}

func normalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return ""
	}

	// Accept "example.com", "*.example.com", ".example.com", "https://example.com/path",
	// or "example.com:443".
	if strings.Contains(d, "://") || strings.HasPrefix(d, "//") {
		u, err := url.Parse(d)
		if err == nil && u.Hostname() != "" {
			d = strings.ToLower(u.Hostname())
		}
	} else {
		// Make it parseable as a URL to extract the hostname and drop any port/path.
		u, err := url.Parse("https://" + d)
		if err == nil && u.Hostname() != "" {
			d = strings.ToLower(u.Hostname())
		}
	}

	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")

	return d
}

func matchesAnyDomain(host string, domains []string) bool {
	if host == "" || len(domains) == 0 {
		return false
	}

	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

// hashLoadingBlockedReasonV1 records a closed diagnostic code only.
// Zero means absent;255 means a value outside the pinned protocol enum.
// These observations never change resource-loading policy.
func hashLoadingBlockedReasonV1(reason network.BlockedReason) uint8 {
	switch reason {
	case "":
		return 0
	case network.BlockedReasonOther:
		return 1
	case network.BlockedReasonCsp:
		return 2
	case network.BlockedReasonMixedContent:
		return 3
	case network.BlockedReasonOrigin:
		return 4
	case network.BlockedReasonInspector:
		return 5
	case network.BlockedReasonIntegrity:
		return 6
	case network.BlockedReasonSubresourceFilter:
		return 7
	case network.BlockedReasonContentType:
		return 8
	case network.BlockedReasonCoepFrameResourceNeedsCoepHeader:
		return 9
	case network.BlockedReasonCoopSandboxedIframeCannotNavigateToCoopPage:
		return 10
	case network.BlockedReasonCorpNotSameOrigin:
		return 11
	case network.BlockedReasonCorpNotSameOriginAfterDefaultedToSameOriginByCoep:
		return 12
	case network.BlockedReasonCorpNotSameOriginAfterDefaultedToSameOriginByDip:
		return 13
	case network.BlockedReasonCorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip:
		return 14
	case network.BlockedReasonCorpNotSameSite:
		return 15
	case network.BlockedReasonSriMessageSignatureMismatch:
		return 16
	default:
		return 255
	}
}

type eventLoadingFailedOptions struct {
	failOnResourceLoadingFailed bool
	mainNavigation              *hashNavigation
	loadingFailed               *error
	loadingFailedMu             *sync.RWMutex
	resourceLoadingFailed       *error
	resourceLoadingFailedMu     *sync.RWMutex
	cancelOnMainPageError       context.CancelFunc
}

// listenForEventLoadingFailed listens for an event indicating that the main
// page or one or more resources failed to load.
// See:
// https://github.com/gotenberg/gotenberg/issues/913.
// https://github.com/gotenberg/gotenberg/issues/959.
// https://github.com/gotenberg/gotenberg/issues/1021.
func listenForEventLoadingFailed(ctx context.Context, logger *slog.Logger, options eventLoadingFailedOptions) {
	chromedp.ListenTarget(ctx, func(ev any) {
		if failure, ok := ev.(*network.EventLoadingFailed); ok {
			recordEventLoadingFailed(ctx, logger, options, failure)
		}
	})
}

// recordEventLoadingFailed shares the event handler with deterministic tests.
// Only the positively identified main request may abort navigation. A failed
// subresource is recorded and rejected by the existing final strict check;
// callback code must never invoke chromedp's joining cancellation.
func recordEventLoadingFailed(ctx context.Context, logger *slog.Logger, options eventLoadingFailedOptions, ev *network.EventLoadingFailed) {
	logger.DebugContext(ctx, fmt.Sprintf("event EventLoadingFailed fired: %+v", ev.ErrorText), "request_id", string(ev.RequestID), "resource_type", string(ev.Type), "hash_loading_canceled", ev.Canceled, "hash_loading_blocked_reason", int(hashLoadingBlockedReasonV1(ev.BlockedReason)), "hash_loading_cors_present", ev.CorsErrorStatus != nil)

	// Preserve the established classification for permissive conversions;
	// strict rendering also records unclassified loading failures below.
	knownErrors := []string{
		"net::ERR_CONNECTION_CLOSED",
		"net::ERR_CONNECTION_RESET",
		"net::ERR_CONNECTION_REFUSED",
		"net::ERR_CONNECTION_ABORTED",
		"net::ERR_CONNECTION_FAILED",
		"net::ERR_NAME_NOT_RESOLVED",
		"net::ERR_INTERNET_DISCONNECTED",
		"net::ERR_ADDRESS_UNREACHABLE",
		"net::ERR_BLOCKED_BY_CLIENT",
		"net::ERR_BLOCKED_BY_RESPONSE",
		"net::ERR_FILE_NOT_FOUND",
		"net::ERR_HTTP2_PROTOCOL_ERROR",
		// Chromium can display and print partial markup after a
		// truncated response. Refuse conversion on framing failures.
		"net::ERR_CONTENT_LENGTH_MISMATCH",
		"net::ERR_INCOMPLETE_CHUNKED_ENCODING",
		"net::ERR_INVALID_CHUNKED_ENCODING",
	}
	errorText := ev.ErrorText
	if !slices.Contains(knownErrors, errorText) {
		if !options.failOnResourceLoadingFailed {
			logger.DebugContext(ctx, "skip unclassified resource loading failure")
			return
		}
		// Strict contractual rendering must refuse policy denials and future
		// Chromium failure reasons too. Do not expose arbitrary protocol text.
		errorText = "resource loading failed"
	}

	if ev.Type == network.ResourceTypeDocument && (options.mainNavigation == nil || options.mainNavigation.isMainRequest(ev.RequestID)) {
		logger.DebugContext(ctx, "event EventLoadingFailed fired for main page")

		options.loadingFailedMu.Lock()
		defer options.loadingFailedMu.Unlock()

		*options.loadingFailed = fmt.Errorf("%s", errorText)

		// Cancel the task context so that any in-flight wait
		// operations abort immediately.
		// See https://github.com/gotenberg/gotenberg/issues/1492.
		if options.cancelOnMainPageError != nil {
			options.cancelOnMainPageError()
		}

		return
	}

	logger.DebugContext(ctx, "event EventLoadingFailed fired for a resource")

	options.resourceLoadingFailedMu.Lock()
	defer options.resourceLoadingFailedMu.Unlock()

	*options.resourceLoadingFailed = errors.Join(
		*options.resourceLoadingFailed,
		fmt.Errorf("resource %s: %s", ev.Type, errorText),
	)
}

// listenForEventExceptionThrown listens for exceptions in the console and
// appends those exceptions to the given error pointer.
// See https://github.com/gotenberg/gotenberg/issues/262.
func listenForEventExceptionThrown(ctx context.Context, logger *slog.Logger, consoleExceptions *error, consoleExceptionsMu *sync.RWMutex) {
	chromedp.ListenTarget(ctx, func(ev any) {
		if ev, ok := ev.(*runtime.EventExceptionThrown); ok {
			logger.DebugContext(ctx, fmt.Sprintf("event EventExceptionThrown fired: %+v", ev.ExceptionDetails))

			consoleExceptionsMu.Lock()
			defer consoleExceptionsMu.Unlock()

			*consoleExceptions = errors.Join(*consoleExceptions, fmt.Errorf("\n%+v", ev.ExceptionDetails))
		}
	})
}
