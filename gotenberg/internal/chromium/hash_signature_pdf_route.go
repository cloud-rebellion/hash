package chromium

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/gotenberg/internal/hashapi"
	"github.com/labstack/echo/v4"
)

const (
	hashSignaturePDFRoutePath       = "/hash/chromium/signature-pdf/v1"
	hashSignaturePDFRouteMIME       = "application/vnd.hash.signature-fit.v1"
	hashSignaturePDFRequestLimit    = 2 << 20
	hashSignaturePDFRouteReserve    = 10 * time.Second
	hashSignaturePDFRouteWriteLimit = 5 * time.Second
)

var errHashSignaturePDFRouteConfig = errors.New("hash signature PDF route configuration is invalid")

// This is the entire wire input. A canonical encoding is required, including
// every nested plan/target field and the pinned full font bytes. No public
// conversion options or caller-authored document can enter this route.
type hashSignaturePDFRequest struct {
	Schema    int                      `json:"schema"`
	Plan      hashSignatureMeasurePlan `json:"plan"`
	FontBytes []byte                   `json:"fontBytes"`
}

type hashSignaturePDFFactory func(context.Context, *slog.Logger, *hashSignatureMeasurePlan, []byte) (*hashSignaturePDFPackage, error)

func hashSignaturePDFTokenValid(token string) bool {
	if len(token) < 32 || len(token) > 128 {
		return false
	}
	for i := range token {
		if token[i] < 33 || token[i] > 126 {
			return false
		}
	}
	return true
}

func (mod *Chromium) hashSignaturePDFRouteFromEnvironment() (*api.Route, error) {
	token, configured := os.LookupEnv("HASH_SIGNATURE_FIT_TOKEN")
	if !configured || token == "" {
		return nil, nil
	}
	route, err := newHashSignaturePDFRoute(token, mod.hashSignatureAPITimeout, mod.prepareHashSignaturePDF)
	if err != nil {
		return nil, errHashSignaturePDFRouteConfig
	}
	return &route, nil
}

func newHashSignaturePDFRoute(token string, apiTimeout time.Duration, prepare hashSignaturePDFFactory) (api.Route, error) {
	// The API's global hard timeout is apiTimeout+5s. Finish work earlier than
	// apiTimeout: chromedp detaches/closes within 1s, the owned target-registry
	// confirmation has 2s, and response writes have at most 5s. The extra 2s
	// reserve does not claim a hard bound on filesystem/OS scheduling.
	if !hashSignaturePDFTokenValid(token) || apiTimeout < 15*time.Second || apiTimeout > time.Duration(1<<63-1)-5*time.Second || prepare == nil {
		return api.Route{}, errHashSignaturePDFRouteConfig
	}
	tokenSHA := sha256.Sum256([]byte(token))
	workLimit := min(60*time.Second, apiTimeout-hashSignaturePDFRouteReserve)
	return api.Route{
		Method: http.MethodPost, Path: hashSignaturePDFRoutePath,
		DisableTelemetry: true,
		Handler: func(c echo.Context) error {
			// The API's independent hard-timeout wrapper can return its pooled
			// Echo context. Snapshot raw request/writer once and never retain or
			// touch c/its response wrapper during or after the owned factory.
			r, w := c.Request(), c.Response().Writer
			started := time.Now()
			parent := r.Context()
			responseDeadline := started.Add(apiTimeout)
			if d, ok := parent.Deadline(); ok && d.Before(responseDeadline) {
				responseDeadline = d
			}
			refuse := func(status int) error {
				return writeHashSignaturePDFResponse(parent, w, responseDeadline, status, "text/plain; charset=utf-8", []byte("hash signature PDF request refused\n"))
			}
			headers := r.Header.Values("Authorization")
			if len(headers) != 1 || len(headers[0]) < 7 || headers[0][:7] != "Bearer " || !hashSignaturePDFTokenValid(headers[0][7:]) {
				return refuse(http.StatusUnauthorized)
			}
			suppliedSHA := sha256.Sum256([]byte(headers[0][7:]))
			if subtle.ConstantTimeCompare(suppliedSHA[:], tokenSHA[:]) != 1 {
				return refuse(http.StatusUnauthorized)
			}
			if parent.Err() != nil {
				return nil
			}
			if r.Method != http.MethodPost {
				return refuse(http.StatusMethodNotAllowed)
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Content-Encoding")) != 0 {
				return refuse(http.StatusBadRequest)
			}
			contentTypes := r.Header.Values("Content-Type")
			if len(contentTypes) != 1 || contentTypes[0] != "application/json" {
				return refuse(http.StatusUnsupportedMediaType)
			}
			if r.ContentLength > hashSignaturePDFRequestLimit {
				return refuse(http.StatusRequestEntityTooLarge)
			}
			ctx, cancel := context.WithTimeout(parent, workLimit)
			defer cancel()
			workDeadline, _ := ctx.Deadline()
			// Shorten the upstream connection read timeout, never extend it. If
			// the writer does not support deadlines, refuse before reading/factory.
			controller := http.NewResponseController(w)
			if controller.SetReadDeadline(workDeadline) != nil || controller.SetWriteDeadline(responseDeadline) != nil {
				return refuse(http.StatusServiceUnavailable)
			}
			if r.Body == nil {
				return refuse(http.StatusBadRequest)
			}
			raw, err := io.ReadAll(io.LimitReader(r.Body, hashSignaturePDFRequestLimit+1))
			if err != nil {
				return refuse(http.StatusBadRequest)
			}
			if len(raw) > hashSignaturePDFRequestLimit {
				return refuse(http.StatusRequestEntityTooLarge)
			}
			if ctx.Err() != nil {
				return refuse(http.StatusServiceUnavailable)
			}
			var in hashSignaturePDFRequest
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&in) != nil {
				return refuse(http.StatusBadRequest)
			}
			canonical, err := json.Marshal(in)
			if err != nil || !bytes.Equal(raw, canonical) || in.Schema != 1 || !in.Plan.valid() || len(in.FontBytes) < 1 || len(in.FontBytes) > hashSignatureFontLimit {
				return refuse(http.StatusBadRequest)
			}
			font, ok := hashPinnedMeasureFont(in.Plan.Font)
			if !ok || hashSealSHA(in.FontBytes) != font.sha {
				return refuse(http.StatusBadRequest)
			}
			// Production binds this directly to prepareHashSignaturePDF. It joins
			// owned conversion/target/source cleanup before returning a package.
			pack, err := prepare(ctx, slog.New(slog.DiscardHandler), &in.Plan, in.FontBytes)
			if err != nil || ctx.Err() != nil || pack == nil {
				return refuse(http.StatusServiceUnavailable)
			}
			parts := [][]byte{pack.report, pack.pdf, pack.html, pack.font, pack.snapshot}
			limits := []int{hashSignatureReportLimit, hashSignaturePDFLimit, hashSignatureHTMLLimit, hashSignatureFontLimit, hashSignatureSnapshotLimit}
			for i, part := range parts {
				if len(part) < 1 || len(part) > limits[i] {
					return refuse(http.StatusServiceUnavailable)
				}
			}
			body := pack.Bytes()
			if _, err := decodeHashSignaturePDFPackage(body, &in.Plan); err != nil || ctx.Err() != nil {
				return refuse(http.StatusServiceUnavailable)
			}
			return writeHashSignaturePDFResponse(parent, w, minTimeHashSignaturePDF(responseDeadline, workDeadline), http.StatusOK, hashSignaturePDFRouteMIME, body)
		},
	}, nil
}

func minTimeHashSignaturePDF(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func writeHashSignaturePDFResponse(ctx context.Context, w http.ResponseWriter, deadline time.Time, status int, contentType string, body []byte) error {
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return nil
	}
	writeDeadline := minTimeHashSignaturePDF(deadline, time.Now().Add(hashSignaturePDFRouteWriteLimit))
	if err := http.NewResponseController(w).SetWriteDeadline(writeDeadline); err != nil {
		return errors.New("hash signature PDF response unavailable")
	}
	if ctx.Err() != nil || !time.Now().Before(writeDeadline) {
		return nil
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	n, err := w.Write(body)
	if err != nil || n != len(body) {
		return errors.New("hash signature PDF response unavailable")
	}
	return nil
}
