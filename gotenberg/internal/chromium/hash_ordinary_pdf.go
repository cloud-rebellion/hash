// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"

	"github.com/bright-interaction/hash/gotenberg/internal/hashapi"
	"github.com/bright-interaction/hash/gotenberg/internal/ordinarypage"
	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// Ordinary fields share the existing private renderer credential. This route
// does not accept caller HTML, generic conversion options or arbitrary assets.
func (mod *Chromium) hashOrdinaryPDFRouteFromEnvironment() (*api.Route, error) {
	token, configured := os.LookupEnv("HASH_SIGNATURE_FIT_TOKEN")
	if !configured || token == "" {
		return nil, nil
	}
	route, err := ordinarypage.RouteV1(token, mod.hashSignatureAPITimeout, mod.prepareHashOrdinaryPDF)
	if err != nil {
		return nil, ordinarypage.ErrUnavailableV1
	}
	return &route, nil
}

// The before and after snapshots and native print all use the same target and
// navigation generation. Package integrity is separate from strict PDF worker
// inspection and from the application authority/static-basis sealing gates.
func (b *chromiumBrowser) hashPrepareOrdinaryPDF(ctx context.Context, logger *slog.Logger, u, dir string, seal *ordinarypage.SealV1) (*ordinarypage.PackageV1, error) {
	if !b.arguments.disableJavaScript {
		return nil, errHashFitIsolation
	}
	plan, err := seal.Plan()
	if err != nil {
		return nil, ordinarypage.ErrUnavailableV1
	}
	width, height, err := plan.Geometry.ViewportPointsV1()
	if err != nil || ordinarypage.MaxPDFBytesV1 != hashSignaturePDFLimit {
		return nil, ordinarypage.ErrUnavailableV1
	}
	var candidate *ordinarypage.PackageV1
	var before []byte
	options := DefaultOptions()
	options.AllowedFilePrefixes = []string{dir}
	options.EmulatedMediaType = "print"
	options.OmitBackground = true
	options.FailOnResourceLoadingFailed = true
	err = b.do(ctx, logger, u, options, nil, chromedp.Tasks{
		network.Enable(), fetch.Enable(), runtime.Enable(),
		clearCacheActionFunc(logger, b.arguments.clearCache),
		clearCookiesActionFunc(logger, b.arguments.clearCookies),
		clearStorageActionFunc(logger, b.arguments.clearStorage, u),
		disableJavaScriptActionFunc(logger, true), navigateActionFunc(logger, u, true, true),
		hideDefaultWhiteBackgroundActionFunc(logger, true, true),
		emulateMediaTypeActionFunc(logger, "print", nil),
		chromedp.ActionFunc(func(task context.Context) error {
			if err := ordinarypage.MeasureV1(task, seal); err != nil {
				return err
			}
			var err error
			before, err = ordinarypage.SnapshotV1(task, seal)
			return err
		}),
		chromedp.ActionFunc(func(task context.Context) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := hashNavigationBarrierAction().Do(task); err != nil {
				return err
			}
			// The shared stream reader bounds every read, closes the sole native
			// stream and taints this generation on uncertain stream disposal.
			pdf, err := b.hashPrintSignaturePDF(task, width, height)
			if err != nil {
				return err
			}
			if err := hashNavigationBarrierAction().Do(task); err != nil {
				return err
			}
			after, err := ordinarypage.SnapshotV1(task, seal)
			if err != nil || !bytes.Equal(before, after) {
				return ordinarypage.ErrUnavailableV1
			}
			protocol, product, revision, _, _, err := cdpbrowser.GetVersion().Do(task)
			if err != nil {
				return ordinarypage.ErrUnavailableV1
			}
			candidate, err = seal.FinishV1(task, pdf, after, ordinarypage.ChromiumVersionV1{Product: product, Revision: revision, Protocol: protocol})
			return err
		}), page.Close(),
	})
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	if candidate == nil {
		return nil, ordinarypage.ErrUnavailableV1
	}
	return candidate, nil
}

// Publication waits for b.do's owned-target registry/stream cleanup and for
// supervisor cancellation/lifecycle checks. Filesystem cleanup failure also
// refuses publication. PDF bytes need not be deterministic between fresh runs;
// the application must persist the first accepted original before external I/O.
func (mod *Chromium) prepareHashOrdinaryPDF(ctx context.Context, logger *slog.Logger, plan ordinarypage.PlanV1, font []byte) (*ordinarypage.PackageV1, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ordinarypage.ContextErrorV1(ctx)
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ordinarypage.ErrUnavailableV1
	}
	b, ok := mod.browser.(*chromiumBrowser)
	if !ok || mod.supervisor == nil {
		return nil, ordinarypage.ErrUnavailableV1
	}
	if !b.arguments.disableJavaScript {
		return nil, errHashFitIsolation
	}
	seal, err := ordinarypage.NewSealV1(plan, font)
	if err != nil {
		return nil, ordinarypage.ErrUnavailableV1
	}
	var candidate *ordinarypage.PackageV1
	err = mod.supervisor.Run(ctx, logger, func() (result error) {
		dir, err := os.MkdirTemp("", "hash-ordinary-seal-")
		if err != nil {
			return ordinarypage.ErrUnavailableV1
		}
		defer func() {
			if os.RemoveAll(dir) != nil {
				result = errors.Join(result, ordinarypage.ErrUnavailableV1)
			}
		}()
		path := filepath.Join(dir, "index.html")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return ordinarypage.ErrUnavailableV1
		}
		html := seal.HTML()
		n, writeErr := file.Write(html)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil || n != len(html) {
			return ordinarypage.ErrUnavailableV1
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		candidate, err = b.hashPrepareOrdinaryPDF(ctx, logger, (&url.URL{Scheme: "file", Path: path}).String(), dir, seal)
		return err
	})
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	if candidate == nil {
		return nil, ordinarypage.ErrUnavailableV1
	}
	return candidate, nil
}
