package chromium

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cdprotobrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/dlclark/regexp2"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

type browser interface {
	gotenberg.Process
	pdf(ctx context.Context, logger *slog.Logger, url, outputPath string, options PdfOptions, aggregate *networkAggregate) error
	screenshot(ctx context.Context, logger *slog.Logger, url, outputPath string, options ScreenshotOptions, aggregate *networkAggregate) error
}

type browserArguments struct {
	taskObservation *hashTaskObserver
	// Executor args.
	binPath                  string
	allowInsecureLocalhost   bool
	ignoreCertificateErrors  bool
	disableWebSecurity       bool
	allowFileAccessFromFiles bool
	hostResolverRules        string
	proxyServer              string
	enableEnvironmentProxy   bool
	wsUrlReadTimeout         time.Duration
	hyphenDataDirPath        string

	// Tasks specific.
	allowList         []*regexp2.Regexp
	denyList          []*regexp2.Regexp
	denyPrivateIPs    bool
	denyPublicIPs     bool
	clearCache        bool
	clearCookies      bool
	clearStorage      bool
	disableJavaScript bool
}

type chromiumBrowser struct {
	initialCtx             context.Context
	ctx                    context.Context
	cancelFunc             func() error
	closeFunc              func() error
	userProfileDirPath     string
	ctxMu                  sync.RWMutex
	isStarted              atomic.Bool
	hashCleanupUnconfirmed atomic.Bool
	// startMu serializes Start calls. The supervisor's runWithDeadline
	// abandons a Start goroutine when the request deadline expires while
	// Chromium's startup handshake is still hanging; the abandoned goroutine
	// keeps running, holding the resources it acquired (the pinning proxy).
	// Serializing here prevents a second, overlapping Start from colliding
	// with the in-flight one on the shared pinning proxy.
	// See https://github.com/gotenberg/gotenberg/issues/1599.
	startMu        sync.Mutex
	lifetimeCancel context.CancelFunc
	retirement     *hashBrowserRetirement
	startup        *hashBrowserStartup
	proxyOwned     bool

	arguments    browserArguments
	pinningProxy *pinningProxy
}

func newChromiumBrowser(arguments browserArguments) browser {
	b := &chromiumBrowser{
		initialCtx:   context.Background(),
		arguments:    arguments,
		pinningProxy: newPinningProxy(arguments.allowList, arguments.denyList, arguments.denyPrivateIPs, arguments.denyPublicIPs, arguments.enableEnvironmentProxy),
	}
	b.isStarted.Store(false)

	return b
}

func (b *chromiumBrowser) Start(logger *slog.Logger) error {
	// Refuse to run while a previous Start is still in flight. That previous
	// Start may be a goroutine the supervisor abandoned after the request
	// deadline expired while the Chromium startup handshake was hanging; it
	// still owns its startup attempt. A separate handshake deadline and retained
	// retirement prevent another Start from overlapping that generation's proxy
	// and latch Chromium into a permanent "pinning proxy already started"
	// state. See https://github.com/gotenberg/gotenberg/issues/1599.
	if !b.startMu.TryLock() {
		return errors.New("browser start already in progress")
	}
	defer b.startMu.Unlock()

	if b.retirement != nil {
		if err := b.hashReconcileRetirementLocked(); err != nil {
			return err
		}
	}
	if b.isStarted.Load() || b.startup != nil || b.userProfileDirPath != "" {
		return errors.New("browser is already started")
	}
	if b.arguments.wsUrlReadTimeout <= 0 {
		return errors.New("chromium start timeout must be positive")
	}
	b.arguments.taskObservation.observe(hashTaskStartupBefore)
	startup := &hashBrowserStartup{done: make(chan struct{}), observation: newHashStartupObserver(logger)}
	b.startup = startup

	debug := &debugLogger{logger: logger, startup: startup.observation}
	// Chromium puts a Unix socket below TMPDIR. The filesystem's nested UUID
	// path exceeds its socket-path limit when TMPDIR is the owned profile.
	// MkdirTemp creates an exclusive, short, mode-0700 directory instead.
	profile, err := os.MkdirTemp("", "hcr-")
	if err != nil {
		return b.hashFailSetupLocked(logger, fmt.Errorf("could not create user profile directory: %w", err))
	}
	b.userProfileDirPath = profile
	// See https://github.com/gotenberg/gotenberg/issues/1293.
	err = os.Symlink(b.arguments.hyphenDataDirPath, fmt.Sprintf("%s/hyphen-data", b.userProfileDirPath))
	if err != nil {
		return b.hashFailSetupLocked(logger, fmt.Errorf("create symlink to hyphen-data directory: %w", err))
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.CombinedOutput(debug),
		chromedp.ExecPath(b.arguments.binPath),
		chromedp.NoSandbox,
		// See:
		// https://github.com/puppeteer/puppeteer/issues/661
		// https://github.com/puppeteer/puppeteer/issues/2410
		chromedp.Flag("font-render-hinting", "none"),
		chromedp.UserDataDir(b.userProfileDirPath),
		// See https://github.com/gotenberg/gotenberg/issues/831.
		chromedp.Flag("disable-pdf-tagging", true),
		// See https://github.com/gotenberg/gotenberg/issues/1177.
		chromedp.Flag("no-zygote", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		// See https://github.com/gotenberg/gotenberg/issues/1293.
		chromedp.Flag("disable-component-update", false),
	)

	if b.arguments.allowInsecureLocalhost {
		// See https://github.com/gotenberg/gotenberg/issues/488.
		opts = append(opts, chromedp.Flag("allow-insecure-localhost", true))
	}

	if b.arguments.ignoreCertificateErrors {
		opts = append(opts, chromedp.IgnoreCertErrors)
	}

	if b.arguments.disableWebSecurity {
		opts = append(opts, chromedp.Flag("disable-web-security", true))
	}

	if b.arguments.allowFileAccessFromFiles {
		// See https://github.com/gotenberg/gotenberg/issues/356.
		opts = append(opts, chromedp.Flag("allow-file-access-from-files", true))
	}

	if b.arguments.hostResolverRules != "" {
		// See https://github.com/gotenberg/gotenberg/issues/488.
		opts = append(opts, chromedp.Flag("host-resolver-rules", b.arguments.hostResolverRules))
	}

	if b.arguments.proxyServer != "" {
		// See https://github.com/gotenberg/gotenberg/issues/376.
		opts = append(opts, chromedp.ProxyServer(b.arguments.proxyServer))
	}

	// Default: route Chromium through the internal pinning proxy so that
	// Chromium never performs its own DNS lookup for the navigation URL
	// or any sub-resource. The proxy resolves and validates each URL
	// once per request and dials the pinned IP, closing the DNS
	// rebinding window between Gotenberg's validation and Chromium's
	// connect.
	//
	// Skip when the operator has configured their own egress proxy or
	// custom host-resolver mappings: those deployments take
	// responsibility for outbound safety themselves and routing through
	// an internal proxy would override their configuration.
	if b.arguments.proxyServer == "" && b.arguments.hostResolverRules == "" {
		err = b.pinningProxy.Start(logger)
		if err != nil {
			return b.hashFailSetupLocked(logger, fmt.Errorf("start pinning proxy: %w", err))
		}
		b.proxyOwned = true
		opts = append(opts, chromedp.ProxyServer(b.pinningProxy.URL()))

		if b.arguments.denyPrivateIPs || b.arguments.denyPublicIPs {
			// Chromium implicitly bypasses the proxy for loopback and
			// link-local destinations. A WebSocket handshake is never surfaced
			// as a fetch.EventRequestPaused, so listenForEventRequestPaused
			// cannot filter it; the pinning proxy is the only layer that sees
			// it. Left alone, a page could open a WebSocket to 127.0.0.1, ::1,
			// localhost, or the link-local cloud metadata endpoint
			// (169.254.169.254) and reach it unfiltered. "<-loopback>" removes
			// the implicit bypass so those handshakes also traverse the pinning
			// proxy and go through [gotenberg.DecideOutbound] like every other
			// request.
			//
			// Gated on the IP-class policy: it is the control this closes, and
			// under it loopback and link-local HTTP sub-resources are already
			// blocked by listenForEventRequestPaused before they would reach
			// the proxy, so this adds only the missing WebSocket coverage. When
			// the policy is off, loopback is not restricted, and routing it
			// through the proxy would merely change how an unreachable loopback
			// sub-resource reports its failure.
			opts = append(opts, chromedp.Flag("proxy-bypass-list", "<-loopback>"))
		}
	}

	// See https://github.com/gotenberg/gotenberg/issues/524.
	opts = append(opts, chromedp.WSURLReadTimeout(b.arguments.wsUrlReadTimeout))

	// Keep Chromium's TMPDIR scratch files within this exact owned profile.
	// No global TMPDIR mutation or cleanup of another browser's temp prefixes.
	opts = append(opts, chromedp.Env("TMPDIR="+b.userProfileDirPath), chromedp.ModifyCmdFunc(startup.captureCommand))
	lifetimeCtx, lifetimeCancel := context.WithCancel(b.initialCtx)
	allocatorCtx, allocatorCancel := chromedp.NewExecAllocator(lifetimeCtx, opts...)
	ctx, cancel := chromedp.NewContext(allocatorCtx, chromedp.WithDebugf(debug.Printf))

	b.ctxMu.Lock()

	// We have to keep the context around, as we need it to create new tabs
	// later.
	b.ctx = ctx
	b.lifetimeCancel = lifetimeCancel
	b.closeFunc = func() error {
		// Cancel closes this exact browser gracefully, but may still block joining
		// its allocator after its deadline. Keep that wait in the sole retirement
		// worker, with raw lifetime cancellation as its finite fallback.
		closeCtx, closeCancel := context.WithTimeout(ctx, hashBrowserCloseTimeout)
		deadline, _ := closeCtx.Deadline()
		stopForce := context.AfterFunc(closeCtx, lifetimeCancel)
		closeErr := chromedp.Cancel(closeCtx)
		// Cancel can return nil after a deadline forced an abrupt root shutdown.
		// A successful graceful Cancel cancels ctx itself, so ordinary Canceled
		// is expected; only a timely successful close permits profile retirement.
		confirmed := closeErr == nil && !errors.Is(closeCtx.Err(), context.DeadlineExceeded) && time.Now().Before(deadline)
		stopForce()
		closeCancel()
		if !confirmed {
			return errHashBrowserShutdown
		}
		return nil
	}
	b.cancelFunc = func() error {
		return startup.join(cancel, allocatorCancel)
	}
	b.ctxMu.Unlock()

	// Only the startup goroutine writes this attempt's result/command. It never
	// publishes browser health or replaces mutable generation handles.
	deadline := time.Now().Add(b.arguments.wsUrlReadTimeout)
	go func() {
		startup.err = chromedp.Run(ctx)
		startup.observation.finish(true, startup.err != nil)
		close(startup.done)
	}()
	if err := hashWaitForStartup(ctx, startup, deadline); err != nil {
		return b.hashFailStartupLocked(logger, fmt.Errorf("run exec allocator: %w", err))
	}

	b.ctxMu.Lock()
	if !time.Now().Before(deadline) || ctx.Err() != nil || lifetimeCtx.Err() != nil {
		b.ctxMu.Unlock()
		cause := ctx.Err()
		if cause == nil {
			cause = lifetimeCtx.Err()
		}
		if cause == nil {
			cause = context.DeadlineExceeded
		}
		return b.hashFailStartupLocked(logger, cause)
	}
	b.isStarted.Store(true)
	b.hashCleanupUnconfirmed.Store(false)
	b.ctxMu.Unlock()
	b.arguments.taskObservation.observe(hashTaskStartupReady)
	startup.observation.reportOutcome(true)

	return nil
}

// A retirement owns one allocator waiter. Repeated Stop calls reuse it; a
// timed-out caller cannot overwrite its handles or launch a replacement.
type hashBrowserRetirement struct {
	done chan struct{}
	err  error // published only by closing done
}

const hashBrowserStopTimeout = 5 * time.Second
const hashBrowserCloseTimeout = 2 * time.Second

var errHashBrowserShutdown = errors.New("hash chromium shutdown unconfirmed")

func (b *chromiumBrowser) Stop(logger *slog.Logger) error {
	// Serialize the complete lifecycle, including delayed allocator retirement.
	// An in-flight startup cannot be treated as a confirmed stopped browser.
	if !b.startMu.TryLock() {
		hashObserveBrowserShutdown(logger, hashShutdownLifecycleBusy)
		return errHashBrowserShutdown
	}
	defer b.startMu.Unlock()
	if !b.isStarted.Load() && b.retirement == nil && b.startup == nil && b.userProfileDirPath == "" {
		return nil
	}
	b.hashBeginRetirementLocked(logger)
	return b.hashAwaitRetirementLocked(logger)
}

// hashReadinessUnavailable is a read-only post-start supervisor observation.
// The historical cleanup latch can remain set after a clean no-child startup
// failure, so the supervisor must retain its separate pre-first-start policy.
func (b *chromiumBrowser) hashReadinessUnavailable() bool {
	return b.hashCleanupUnconfirmed.Load()
}

func (b *chromiumBrowser) Healthy(logger *slog.Logger) bool {
	// Good to know: the supervisor does not call this method if no first start
	// or if the process is restarting.

	if !b.isStarted.Load() || b.hashCleanupUnconfirmed.Load() {
		// Non-started browser but not restarting?
		return false
	}

	b.ctxMu.RLock()
	defer b.ctxMu.RUnlock()

	// Create a timeout based on the existing browser context (b.ctx).
	// IMPORTANT: We do NOT call chromedp.NewContext here.
	// We want to execute this against the main browser connection,
	// avoiding the creation of a new target (tab).
	if !b.isStarted.Load() || b.hashCleanupUnconfirmed.Load() || b.ctx == nil || chromedp.FromContext(b.ctx) == nil || chromedp.FromContext(b.ctx).Browser == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
	defer cancel()

	// Check if the browser is responsive by asking for its version.
	// This involves a simple JSON payload roundtrip over the websocket.
	// See https://github.com/gotenberg/gotenberg/issues/1169.
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		_, _, _, _, _, err := cdprotobrowser.GetVersion().Do(ctx)
		return err
	}))
	if err != nil {
		logger.ErrorContext(context.Background(), fmt.Sprintf("browser health check failed: %s", err))
		return false
	}

	return true
}

func (b *chromiumBrowser) pdf(ctx context.Context, logger *slog.Logger, url, outputPath string, options PdfOptions, aggregate *networkAggregate) error {
	if options.hashSignatureMeasure != nil {
		options.hashSignatureMeasure.report = nil
		if !b.arguments.disableJavaScript {
			return errHashFitIsolation
		}
		if options.hashManualFit != nil || options.EmulatedMediaType != "print" || !options.hashSignatureMeasure.valid() {
			return errHashSignatureMeasure
		}
	}
	if options.hashManualFit != nil {
		options.hashManualFit.capability = nil
		if !b.arguments.disableJavaScript {
			return errHashFitIsolation
		}
		if !options.hashManualFit.valid() {
			return errHashFitCapability
		}
	}
	// Note: no error wrapping because it leaks on errors we want to display to
	// the end user.
	return b.do(ctx, logger, url, options.Options, aggregate, chromedp.Tasks{
		network.Enable(),
		fetch.Enable(),
		runtime.Enable(),
		clearCacheActionFunc(logger, b.arguments.clearCache),
		clearCookiesActionFunc(logger, b.arguments.clearCookies),
		clearStorageActionFunc(logger, b.arguments.clearStorage, url),
		disableJavaScriptActionFunc(logger, b.arguments.disableJavaScript),
		setCookiesActionFunc(logger, options.Cookies),
		userAgentOverride(logger, options.UserAgent),
		navigateActionFunc(logger, url, options.SkipNetworkIdleEvent, options.SkipNetworkAlmostIdleEvent),
		hideDefaultWhiteBackgroundActionFunc(logger, options.OmitBackground, options.PrintBackground),
		forceExactColorsActionFunc(logger, options.PrintBackground),
		emulateMediaTypeActionFunc(logger, options.EmulatedMediaType, options.EmulatedMediaFeatures),
		waitForExpressionBeforePrintActionFunc(logger, b.arguments.disableJavaScript, options.WaitForExpression),
		waitForSelectorVisibleBeforePrintActionFunc(logger, options.WaitForSelector),
		waitDelayBeforePrintActionFunc(logger, b.arguments.disableJavaScript, options.WaitDelay),
		// PDF specific.
		hashManualSignatureFitAction(options.hashManualFit),
		hashSignatureMeasurementAction(options.hashSignatureMeasure),
		hashNavigationBarrierAction(),
		printToPdfActionFunc(ctx, logger, outputPath, options),
		hashNavigationBarrierAction(),
		// Teardown.
		page.Close(),
	})
}

func (b *chromiumBrowser) screenshot(ctx context.Context, logger *slog.Logger, url, outputPath string, options ScreenshotOptions, aggregate *networkAggregate) error {
	// Note: no error wrapping because it leaks on errors we want to display to
	// the end user.
	return b.do(ctx, logger, url, options.Options, aggregate, chromedp.Tasks{
		network.Enable(),
		fetch.Enable(),
		runtime.Enable(),
		clearCacheActionFunc(logger, b.arguments.clearCache),
		clearCookiesActionFunc(logger, b.arguments.clearCookies),
		clearStorageActionFunc(logger, b.arguments.clearStorage, url),
		disableJavaScriptActionFunc(logger, b.arguments.disableJavaScript),
		setCookiesActionFunc(logger, options.Cookies),
		userAgentOverride(logger, options.UserAgent),
		navigateActionFunc(logger, url, options.SkipNetworkIdleEvent, options.SkipNetworkAlmostIdleEvent),
		hideDefaultWhiteBackgroundActionFunc(logger, options.OmitBackground, true),
		forceExactColorsActionFunc(logger, true),
		emulateMediaTypeActionFunc(logger, options.EmulatedMediaType, options.EmulatedMediaFeatures),
		waitForExpressionBeforePrintActionFunc(logger, b.arguments.disableJavaScript, options.WaitForExpression),
		waitForSelectorVisibleBeforePrintActionFunc(logger, options.WaitForSelector),
		waitDelayBeforePrintActionFunc(logger, b.arguments.disableJavaScript, options.WaitDelay),
		// Screenshot specific.
		setDeviceMetricsOverride(logger, options.Width, options.Height, options.DeviceScaleFactor),
		hashNavigationBarrierAction(),
		captureScreenshotActionFunc(logger, outputPath, options),
		hashNavigationBarrierAction(),
		// Teardown.
		page.Close(),
	})
}

func (b *chromiumBrowser) do(ctx context.Context, logger *slog.Logger, url string, options Options, aggregate *networkAggregate, tasks chromedp.Tasks) (result error) {
	if !b.isStarted.Load() {
		return errors.New("browser not started, cannot handle tasks")
	}
	if b.hashCleanupUnconfirmed.Load() {
		return errHashTabCleanup
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("context has no deadline")
	}

	// We validate the "main" URL against our allowed / deny lists, and
	// against the IP-based outbound URL guard. See [gotenberg.FilterOutboundURL].
	err := gotenberg.FilterOutboundURL(ctx, url, b.arguments.allowList, b.arguments.denyList, deadline,
		gotenberg.WithDenyPrivateIPs(b.arguments.denyPrivateIPs),
		gotenberg.WithDenyPublicIPs(b.arguments.denyPublicIPs),
	)
	if err != nil {
		return fmt.Errorf("filter URL: %w", err)
	}

	b.ctxMu.RLock()
	defer b.ctxMu.RUnlock()
	if !b.isStarted.Load() || b.ctx == nil || chromedp.FromContext(b.ctx) == nil || chromedp.FromContext(b.ctx).Browser == nil {
		return errors.New("browser not started, cannot handle tasks")
	}
	if b.hashCleanupUnconfirmed.Load() {
		return errHashTabCleanup
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(b.ctx, time.Until(deadline))
	defer timeoutCancel()

	// Record ownership before attachment. chromedp's internal targetID is not
	// exposed until attachment succeeds, so relying on c.Target misses a tab
	// cancelled between creation and attachment. Allocation uses a bounded
	// browser-owned context so early caller cancellation cannot lose its ID.
	b.arguments.taskObservation.observe(hashTaskTargetBefore)
	allocationCtx, allocationCancel := context.WithTimeout(b.ctx, min(2*time.Second, time.Until(deadline)))
	ownedTarget, allocationErr := b.hashAllocateTarget(allocationCtx, chromedp.FromContext(b.ctx).Browser, logger)
	allocationCancel()
	allocationPhase := hashTaskTargetAllocated
	if allocationErr != nil || ownedTarget == "" {
		allocationPhase = hashTaskTargetAllocationFailed
	}
	b.arguments.taskObservation.observe(allocationPhase)
	if allocationErr != nil || ownedTarget == "" {
		// An allocation failure can have an unknown outcome. Refuse further
		// work and make the supervisor's health check drain/restart this owned
		// browser; never claim that no target was created.
		return errors.Join(ctx.Err(), errHashTabCleanup)
	}
	taskCtx, taskCancel := chromedp.NewContext(timeoutCtx, chromedp.WithTargetID(ownedTarget))
	// Event listeners must never call NewContext's joining cancelWait while
	// the target event loop is delivering that same event. Abort tasks with a
	// plain cancel; the deferred owner alone joins and confirms target cleanup.
	taskCtx, taskAbort := context.WithCancel(taskCtx)
	defer func() {
		taskAbort()
		taskCancel()
		// A CloseTarget acknowledgement can precede removal from Chrome's
		// target registry. Confirm this exact tab is gone before returning.
		// Cleanup has its own finite bound; never reuse the cancelled tab.
		cleanupPhase := hashTaskTargetCleanupJoined
		if b.hashWaitForTargetCleanup(ownedTarget) != nil {
			cleanupPhase = hashTaskTargetCleanupUnconfirmed
			b.hashCleanupUnconfirmed.Store(true)
			result = errors.Join(result, errHashTabCleanup)
		}
		b.arguments.taskObservation.observe(cleanupPhase)
		if result == nil && ctx.Err() != nil {
			result = ctx.Err()
		}
	}()
	// The browser deadline alone does not propagate an early caller cancel.
	// Bridge it without reparenting the shared browser connection.
	stopCallerCancel := context.AfterFunc(ctx, taskAbort)
	defer stopCallerCancel()
	// Observe before listeners which may cancel this task on a failure. Retain
	// the conversion's exact main request through navigation and final output.
	navigation := newHashNavigation(options.SkipNetworkIdleEvent, options.SkipNetworkAlmostIdleEvent)
	navigation.abort = taskAbort
	taskCtx = context.WithValue(taskCtx, hashNavigationContextKey{}, navigation)
	chromedp.ListenTarget(taskCtx, navigation.observe)

	// Accumulate per-conversion network activity for telemetry.
	listenForNetworkActivity(taskCtx, aggregate)

	// We validate all other requests against our allowed / deny lists.
	// If a request does not pass the validation, we make it fail. It also set
	// the extra HTTP headers, if any.
	// See https://github.com/gotenberg/gotenberg/issues/1011.
	listenForEventRequestPaused(taskCtx, logger, eventRequestPausedOptions{
		allowList:           b.arguments.allowList,
		denyList:            b.arguments.denyList,
		denyPrivateIPs:      b.arguments.denyPrivateIPs,
		denyPublicIPs:       b.arguments.denyPublicIPs,
		allowedFilePrefixes: options.AllowedFilePrefixes,
		extraHttpHeaders:    options.ExtraHttpHeaders,
	})

	// WebSocket handshakes never surface as fetch.EventRequestPaused, so
	// listenForEventRequestPaused above cannot filter them. Validate them
	// against the same allow / deny lists and IP-class policy.
	// See https://github.com/gotenberg/gotenberg/issues/1011.
	listenForEventWebSocketCreated(taskCtx, logger, eventWebSocketCreatedOptions{
		allowList:      b.arguments.allowList,
		denyList:       b.arguments.denyList,
		denyPrivateIPs: b.arguments.denyPrivateIPs,
		denyPublicIPs:  b.arguments.denyPublicIPs,
	})

	var (
		invalidHttpStatusCode           error
		invalidHttpStatusCodeMu         sync.RWMutex
		invalidResourceHttpStatusCode   error
		invalidResourceHttpStatusCodeMu sync.RWMutex
	)

	// See:
	// https://github.com/gotenberg/gotenberg/issues/613.
	// https://github.com/gotenberg/gotenberg/issues/1021.
	if len(options.FailOnHttpStatusCodes) != 0 || len(options.FailOnResourceHttpStatusCodes) != 0 {
		listenForEventResponseReceived(taskCtx, logger, eventResponseReceivedOptions{
			mainNavigation:                  navigation,
			mainPageUrl:                     url,
			failOnHttpStatusCodes:           options.FailOnHttpStatusCodes,
			invalidHttpStatusCode:           &invalidHttpStatusCode,
			invalidHttpStatusCodeMu:         &invalidHttpStatusCodeMu,
			failOnResourceOnHttpStatusCode:  options.FailOnResourceHttpStatusCodes,
			ignoreResourceHttpStatusDomains: options.IgnoreResourceHttpStatusDomains,
			invalidResourceHttpStatusCode:   &invalidResourceHttpStatusCode,
			invalidResourceHttpStatusCodeMu: &invalidResourceHttpStatusCodeMu,
			cancelOnMainPageError:           taskAbort,
		})
	}

	var (
		consoleExceptions   error
		consoleExceptionsMu sync.RWMutex
	)

	// See https://github.com/gotenberg/gotenberg/issues/262.
	if options.FailOnConsoleExceptions && !b.arguments.disableJavaScript {
		listenForEventExceptionThrown(taskCtx, logger, &consoleExceptions, &consoleExceptionsMu)
	}

	var (
		loadingFailed           error
		loadingFailedMu         sync.RWMutex
		resourceLoadingFailed   error
		resourceLoadingFailedMu sync.RWMutex
	)

	// See:
	// https://github.com/gotenberg/gotenberg/issues/913.
	// https://github.com/gotenberg/gotenberg/issues/959.
	// https://github.com/gotenberg/gotenberg/issues/1021.
	listenForEventLoadingFailed(taskCtx, logger, eventLoadingFailedOptions{
		failOnResourceLoadingFailed: options.FailOnResourceLoadingFailed,
		mainNavigation:              navigation,
		loadingFailed:               &loadingFailed,
		loadingFailedMu:             &loadingFailedMu,
		resourceLoadingFailed:       &resourceLoadingFailed,
		resourceLoadingFailedMu:     &resourceLoadingFailedMu,
		cancelOnMainPageError:       taskAbort,
	})

	runErr := chromedp.Run(taskCtx, tasks...)

	// Check event-driven errors first, they take priority over chromedp.Run
	// errors because they carry the actual root cause (e.g., HTTP 500 from
	// the main page). When we cancel taskCtx on a main page error,
	// chromedp.Run returns a context error that is less informative.
	// See https://github.com/gotenberg/gotenberg/issues/1492.

	// See https://github.com/gotenberg/gotenberg/issues/613.
	invalidHttpStatusCodeMu.RLock()
	defer invalidHttpStatusCodeMu.RUnlock()

	if invalidHttpStatusCode != nil {
		return fmt.Errorf("%v: %w", invalidHttpStatusCode, ErrInvalidHttpStatusCode)
	}

	// See https://github.com/gotenberg/gotenberg/issues/1021.
	invalidResourceHttpStatusCodeMu.RLock()
	defer invalidResourceHttpStatusCodeMu.RUnlock()

	if invalidResourceHttpStatusCode != nil {
		return fmt.Errorf("%v: %w", invalidResourceHttpStatusCode, ErrInvalidResourceHttpStatusCode)
	}

	// See:
	// https://github.com/gotenberg/gotenberg/issues/913.
	// https://github.com/gotenberg/gotenberg/issues/959.
	loadingFailedMu.RLock()
	defer loadingFailedMu.RUnlock()

	if loadingFailed != nil {
		return fmt.Errorf("%v: %w", loadingFailed, ErrLoadingFailed)
	}
	if _, navigationErr := navigation.state(); navigationErr != nil {
		return navigationErr
	}

	if runErr != nil {
		errMessage := runErr.Error()

		if strings.Contains(errMessage, "Printing failed (-32000)") {
			return ErrPrintingFailed
		}

		if strings.Contains(errMessage, "Show invalid printer settings error (-32000)") || strings.Contains(errMessage, "content area is empty (-32602)") {
			return ErrInvalidPrinterSettings
		}

		if strings.Contains(errMessage, "Page range syntax error") {
			return ErrPageRangesSyntaxError
		}

		if strings.Contains(errMessage, "Page range exceeds page count (-32000)") {
			return ErrPageRangesExceedsPageCount
		}

		if strings.Contains(errMessage, "rpcc: message too large") {
			return ErrRpccMessageTooLarge
		}

		return fmt.Errorf("handle tasks: %w", runErr)
	}

	// See https://github.com/gotenberg/gotenberg/issues/262.
	consoleExceptionsMu.RLock()
	defer consoleExceptionsMu.RUnlock()

	if consoleExceptions != nil {
		return fmt.Errorf("%v: %w", consoleExceptions, ErrConsoleExceptions)
	}

	// See https://github.com/gotenberg/gotenberg/issues/1021.
	if options.FailOnResourceLoadingFailed {
		resourceLoadingFailedMu.RLock()
		defer resourceLoadingFailedMu.RUnlock()
		if resourceLoadingFailed != nil {
			return fmt.Errorf("%v: %w", resourceLoadingFailed, ErrResourceLoadingFailed)
		}
	}

	return nil
}

var errHashTabCleanup = errors.New("hash chromium tab cleanup unconfirmed")

type hashTabAllocationReason string

const (
	hashTabAllocationDeadline hashTabAllocationReason = "allocation_deadline"
	hashTabAllocationCanceled hashTabAllocationReason = "allocation_canceled"
	hashTabAllocationProtocol hashTabAllocationReason = "allocation_protocol"
	hashTabAllocationEmpty    hashTabAllocationReason = "allocation_empty"
)

// Only closed classifications and booleans leave this failed allocation. The
// actual error and any returned target ID remain private to the existing owner.
func hashObserveTabAllocation(logger *slog.Logger, ctx context.Context, err error, emptyID bool) {
	if logger == nil {
		return
	}
	reason := hashTabAllocationProtocol
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		reason = hashTabAllocationDeadline
	case errors.Is(err, context.Canceled):
		reason = hashTabAllocationCanceled
	case err == nil:
		reason = hashTabAllocationEmpty
	}
	ctxErr := ctx.Err()
	logger.ErrorContext(context.Background(), "hash chromium tab allocation unconfirmed",
		slog.Int("schema", 1), slog.String("reason", string(reason)),
		slog.Bool("command_error", err != nil), slog.Bool("empty_target_id", emptyID),
		slog.Bool("context_deadline", errors.Is(ctxErr, context.DeadlineExceeded)),
		slog.Bool("context_canceled", errors.Is(ctxErr, context.Canceled)))
}

// Private protocol phases take an executor explicitly; production supplies only
// the captured owned browser. Fault executors exist only in tagged tests.
func (b *chromiumBrowser) hashAllocateTarget(ctx context.Context, executor cdp.Executor, loggers ...*slog.Logger) (target.ID, error) {
	id, err := target.CreateTarget("about:blank").Do(cdp.WithExecutor(ctx, executor))
	if err != nil || id == "" {
		b.hashCleanupUnconfirmed.Store(true)
		if len(loggers) == 1 {
			hashObserveTabAllocation(loggers[0], ctx, err, id == "")
		}
		return "", errHashTabCleanup
	}
	return id, nil
}

func (b *chromiumBrowser) hashWaitForTargetCleanup(id target.ID) error {
	ctx, cancel := context.WithTimeout(b.ctx, 2*time.Second)
	defer cancel()
	return b.hashConfirmTargetCleanup(ctx, id, chromedp.FromContext(b.ctx).Browser)
}

func (b *chromiumBrowser) hashConfirmTargetCleanup(ctx context.Context, id target.ID, executor cdp.Executor) (result error) {
	defer func() {
		if result != nil {
			b.hashCleanupUnconfirmed.Store(true)
		}
	}()
	ctx = cdp.WithExecutor(ctx, executor)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var infos []*target.Info
		infos, err := target.GetTargets().Do(ctx)
		if err != nil {
			return errHashTabCleanup
		}
		found := false
		for _, info := range infos {
			if info.TargetID == id {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		// Also close pre-attachment targets; taskCancel cannot own those.
		// Close acknowledgement alone is insufficient, hence the next poll.
		_ = target.CloseTarget(id).Do(ctx)
		select {
		case <-ctx.Done():
			return errHashTabCleanup
		case <-ticker.C:
		}
	}
}

// Interface guards.
var (
	_ gotenberg.Process = (*chromiumBrowser)(nil)
	_ browser           = (*chromiumBrowser)(nil)
)
