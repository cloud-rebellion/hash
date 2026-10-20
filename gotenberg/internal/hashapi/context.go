package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/text/unicode/norm"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

var (
	// ErrContextAlreadyClosed happens when the context has been canceled.
	ErrContextAlreadyClosed = errors.New("context already closed")

	// ErrOutOfBoundsOutputPath happens when an output path is not within
	// context's working directory. It enforces having all the files in the
	// same directory.
	ErrOutOfBoundsOutputPath = errors.New("output path is not within context's working directory")
)

// Context is the request context for a "multipart/form-data" request.
type Context struct {
	dirPath        string
	values         map[string][]string
	files          map[string]string
	filesByField   map[string][]string
	diskToOriginal map[string]string
	outputPaths    []string
	cancelled      bool
	retired        atomic.Bool
	processCancel  context.CancelFunc
	cleanupOnce    sync.Once
	cleanupMu      sync.Mutex
	cleanupErr     error
	cleanups       []func() error
	fs             *gotenberg.FileSystem
	request        *http.Request
	outputFilename string
	staged         *hashStageBodyV2

	logger     *slog.Logger
	echoCtx    echo.Context
	mkdirAll   gotenberg.MkdirAll
	pathRename gotenberg.PathRename
	context.Context
}

type trackingReader struct {
	R            io.Reader
	AddReadBytes func(n int64) error
}

func (t *trackingReader) Read(p []byte) (int, error) {
	n, err := t.R.Read(p)
	if n > 0 {
		errAddRead := t.AddReadBytes(int64(n))
		if errAddRead != nil {
			return n, fmt.Errorf("add read bytes: %w", errAddRead)
		}
	}
	if err != nil {
		// It's a common practice in Go to return io.EOF unwrapped to signal
		// the end of a data stream. Wrapping it can lead to unexpected
		// behavior in standard library functions.
		return n, err
	}
	return n, nil
}

type downloadFrom struct {
	// Url is the URL to download a file from.
	Url string `json:"url"`

	// ExtraHttpHeaders are the HTTP headers to send alongside.
	ExtraHttpHeaders map[string]string `json:"extraHttpHeaders"`

	// Embedded routes the downloaded file as an embed. Deprecated: use
	// Field instead. Kept for backward compatibility.
	Embedded bool `json:"embedded"`

	// Field routes the downloaded file to a specific form field bucket.
	// Supported values: "watermark", "stamp". For embeds, prefer the
	// Embedded flag or set Field to "embedded".
	Field string `json:"field"`
}

// newContext returns a [Context] by parsing a "multipart/form-data" request.
func newContext(echoCtx echo.Context, logger *slog.Logger, fs *gotenberg.FileSystem, timeout time.Duration, bodyLimit int64, downloadFromCfg downloadFromConfig) (*Context, context.CancelFunc, error) {
	processCtx, processCancel := context.WithTimeout(echoCtx.Request().Context(), timeout)
	owner := hashRequestFromV2(echoCtx.Request())

	// We want to make sure the multipart/form-data does not exceed a given
	// limit. We consider: form fields (keys, values, files) and files
	// downloaded remotely ("download from" feature).
	var totalBytesRead atomic.Int64

	addReadBytes := func(n int64) error {
		newTotal := totalBytesRead.Add(n)
		if bodyLimit != 0 && newTotal > bodyLimit {
			return WrapError(
				fmt.Errorf("body limit reached (> %d)", bodyLimit),
				NewSentinelHttpError(http.StatusRequestEntityTooLarge, "The request body exceeds the configured size limit. Increase it with --api-body-limit, or send a smaller request."),
			)
		}
		return nil
	}

	ctx := &Context{
		outputPaths:   make([]string, 0),
		cancelled:     false,
		logger:        logger,
		echoCtx:       echoCtx,
		mkdirAll:      new(gotenberg.OsMkdirAll),
		pathRename:    new(gotenberg.OsPathRename),
		Context:       processCtx,
		processCancel: processCancel,
		fs:            fs,
		request:       echoCtx.Request(),
	}

	ctx.outputFilename, _ = echoCtx.Get("outputFilename").(string)
	var cancel context.CancelFunc
	if owner != nil {
		owner.addCleanup(ctx.retireCheckedV2)
		cancel = processCancel
		if err := ctx.stageMultipartV2(owner, echoCtx.Request().MultipartForm); err != nil {
			return nil, cancel, err
		}
	} else {
		// Compatibility constructor for direct package users/tests. Production
		// always has an owned request and uses cancellation without deletion.
		cancel = func() { processCancel(); _ = ctx.retireCheckedV2() }
	}

	var form *multipart.Form
	var err error
	if owner != nil {
		err = echoCtx.Request().ParseMultipartForm(hashMultipartEntityLimitV2)
		form = echoCtx.Request().MultipartForm
		if form != nil {
			ctx.cleanups = append(ctx.cleanups, form.RemoveAll)
		}
	} else {
		form, err = echoCtx.MultipartForm()
		if form != nil {
			defer func() { ctx.recordCleanupError(form.RemoveAll()) }()
		}
	}
	if err != nil {
		if errors.Is(err, http.ErrNotMultipart) {
			return nil, cancel, WrapError(
				fmt.Errorf("get multipart form: %w", err),
				NewSentinelHttpError(http.StatusUnsupportedMediaType, "Invalid 'Content-Type' header value: want 'multipart/form-data'"),
			)
		}

		if errors.Is(err, http.ErrMissingBoundary) {
			return nil, cancel, WrapError(
				fmt.Errorf("get multipart form: %w", err),
				NewSentinelHttpError(http.StatusUnsupportedMediaType, "Invalid 'Content-Type' header value: no boundary"),
			)
		}

		if strings.Contains(err.Error(), io.EOF.Error()) {
			return nil, cancel, WrapError(
				fmt.Errorf("get multipart form: %w", err),
				NewSentinelHttpError(http.StatusBadRequest, "Malformed body: it does not match the 'Content-Type' header boundaries"),
			)
		}

		return nil, cancel, fmt.Errorf("get multipart form: %w", err)
	}

	if ctx.staged != nil {
		closeErr := ctx.staged.Close()
		removeErr := os.Remove(ctx.staged.Name())
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		if closeErr != nil || removeErr != nil {
			cause := errors.Join(closeErr, removeErr)
			ctx.recordCleanupError(cause)
			return nil, cancel, fmt.Errorf("retire staging file: %w", cause)
		}
		echoCtx.Request().Body = http.NoBody
	}

	// This will ensure we do not exceed the body limit.
	var formValuesSize int64
	for key, valArray := range form.Value {
		formValuesSize += int64(len(key))
		for _, val := range valArray {
			formValuesSize += int64(len(val))
		}
	}
	err = addReadBytes(formValuesSize)
	if err != nil {
		return nil, cancel, fmt.Errorf("add read bytes: %w", err)
	}

	if owner == nil {
		dirPath, createErr := fs.MkdirAll()
		if createErr != nil {
			return nil, cancel, fmt.Errorf("create working directory: %w", createErr)
		}
		ctx.dirPath = dirPath
		ctx.cleanups = append(ctx.cleanups, func() error { return os.RemoveAll(dirPath) })
	}
	ctx.values = form.Value
	ctx.files = make(map[string]string)
	ctx.filesByField = make(map[string][]string)
	ctx.diskToOriginal = make(map[string]string)

	// First, try to download files listed in the "downloadFrom" form field, if
	// any.
	raw, ok := ctx.values["downloadFrom"]
	if !downloadFromCfg.disable && ok {
		var dls []downloadFrom
		err = json.Unmarshal([]byte(raw[0]), &dls)
		if err != nil {
			return nil, cancel, WrapError(
				fmt.Errorf("unmarshal json: %w", err),
				NewSentinelHttpError(http.StatusBadRequest, fmt.Sprintf("Invalid 'downloadFrom' form field value: %s", err)),
			)
		}

		// Each goroutine writes to its own results slot. The main
		// goroutine merges into ctx.files, ctx.diskToOriginal, and
		// ctx.filesByField after eg.Wait() to avoid concurrent map
		// writes.
		type downloadFromResult struct {
			filename, path, formField string
		}
		results := make([]downloadFromResult, len(dls))

		eg, downloadCtx := errgroup.WithContext(ctx)
		for i, dl := range dls {
			eg.Go(func() (err error) {
				deadline, ok := ctx.Deadline()
				if !ok {
					// Should not happen, as context is created with a timeout.
					return errors.New("context has no deadline")
				}

				if strings.TrimSpace(dl.Url) == "" {
					return WrapError(
						errors.New("empty download from URL"),
						NewSentinelHttpError(http.StatusBadRequest, fmt.Sprintf("Invalid 'downloadFrom' form field entry %d: URL must be set", i)),
					)
				}

				ipOpts := []gotenberg.DecideOption{
					gotenberg.WithDenyPrivateIPs(downloadFromCfg.denyPrivateIPs),
					gotenberg.WithDenyPublicIPs(downloadFromCfg.denyPublicIPs),
				}
				err = gotenberg.FilterOutboundURL(downloadCtx, dl.Url, downloadFromCfg.allowList, downloadFromCfg.denyList, deadline, ipOpts...)
				if err != nil {
					return fmt.Errorf("filter URL: %w", err)
				}

				dlCtx, dlSpan := gotenberg.Tracer().Start(downloadCtx, "GET Download From",
					trace.WithSpanKind(trace.SpanKindClient),
					trace.WithAttributes(semconv.ServerAddress(dl.Url)),
				)

				logger.DebugContext(dlCtx, fmt.Sprintf("download file from '%s'", dl.Url))

				req, err := retryablehttp.NewRequestWithContext(dlCtx, http.MethodGet, dl.Url, nil)
				if err != nil {
					dlSpan.RecordError(err)
					dlSpan.SetStatus(codes.Error, err.Error())
					dlSpan.End()
					return fmt.Errorf("create request to '%s': %w", dl.Url, err)
				}

				req.Header.Set("User-Agent", "Gotenberg")
				for key, value := range dl.ExtraHttpHeaders {
					req.Header.Set(key, value)
				}

				// Inject OTEL trace context into outbound request.
				otel.GetTextMapPropagator().Inject(dlCtx, propagation.HeaderCarrier(req.Header))

				// Propagate correlation ID header.
				if correlationIdHeader, ok := echoCtx.Get("correlationIdHeader").(string); ok {
					if correlationId, ok := echoCtx.Get("correlationId").(string); ok {
						req.Header.Set(correlationIdHeader, correlationId)
					}
				}

				client := &retryablehttp.Client{
					HTTPClient:   gotenberg.NewOutboundHttpClient(time.Until(deadline), downloadFromCfg.allowList, downloadFromCfg.denyList, downloadFromCfg.enableEnvironmentProxy, ipOpts...),
					RetryMax:     downloadFromCfg.maxRetry,
					RetryWaitMin: time.Duration(1) * time.Second,
					RetryWaitMax: time.Until(deadline),
					Logger:       gotenberg.NewLeveledLogger(logger),
					CheckRetry:   retryablehttp.DefaultRetryPolicy,
					Backoff:      retryablehttp.DefaultBackoff,
				}

				resp, err := client.Do(req)
				if err != nil {
					dlSpan.RecordError(err)
					dlSpan.SetStatus(codes.Error, err.Error())
					dlSpan.End()
					return WrapError(
						fmt.Errorf("download file from to '%s': %w", dl.Url, err),
						NewSentinelHttpError(http.StatusBadRequest, fmt.Sprintf("Unable to download file from '%s': %s", dl.Url, err)),
					)
				}
				defer func() {
					closeErr := resp.Body.Close()
					if closeErr != nil {
						cause := fmt.Errorf("close download response: %w", closeErr)
						ctx.recordCleanupError(cause)
						err = errors.Join(err, cause)
					}
				}()

				if resp.StatusCode != http.StatusOK {
					dlErr := fmt.Errorf("download file from to '%s': got status: '%s'", dl.Url, resp.Status)
					dlSpan.RecordError(dlErr)
					dlSpan.SetStatus(codes.Error, dlErr.Error())
					dlSpan.End()
					return WrapError(
						dlErr,
						NewSentinelHttpError(http.StatusBadRequest, fmt.Sprintf("Unable to download file from '%s': got status: '%s'", dl.Url, resp.Status)),
					)
				}

				contentDisposition := resp.Header.Get("Content-Disposition")
				if contentDisposition == "" {
					dlErr := fmt.Errorf("no 'Content-Disposition' header from '%s'", dl.Url)
					dlSpan.RecordError(dlErr)
					dlSpan.SetStatus(codes.Error, dlErr.Error())
					dlSpan.End()
					return WrapError(
						dlErr,
						NewSentinelHttpError(http.StatusBadRequest, fmt.Sprintf("No 'Content-Disposition' header from '%s'", dl.Url)),
					)
				}

				// FIXME: the implementation of this method might not be
				//  complete, as it fails to parse an empty mediatype.
				//  See: https://github.com/golang/go/issues/69551.
				_, params, err := mime.ParseMediaType(contentDisposition)
				if err != nil {
					dlErr := fmt.Errorf("parse 'Content-Disposition' header '%s' from '%s': %w", contentDisposition, dl.Url, err)
					dlSpan.RecordError(dlErr)
					dlSpan.SetStatus(codes.Error, dlErr.Error())
					dlSpan.End()
					return WrapError(
						dlErr,
						NewSentinelHttpError(http.StatusBadRequest, fmt.Sprintf("Invalid 'Content-Disposition' header '%s' from '%s': %s", contentDisposition, dl.Url, err)),
					)
				}

				filename, ok := params["filename"]
				if !ok {
					dlErr := fmt.Errorf("get filename from 'Content-Disposition' header '%s' from '%s'", contentDisposition, dl.Url)
					dlSpan.RecordError(dlErr)
					dlSpan.SetStatus(codes.Error, dlErr.Error())
					dlSpan.End()
					return WrapError(
						dlErr,
						NewSentinelHttpError(http.StatusBadRequest, fmt.Sprintf("Invalid 'Content-Disposition' header '%s' from '%s': no filename", contentDisposition, dl.Url)),
					)
				}

				// Strip path separators (including backslashes) and control
				// characters, then NFC-normalize. Defends against directory
				// traversal in the on-disk name and Windows-side Zip Slip
				// when the original filename is later embedded in an output
				// zip entry.
				// See: https://github.com/gotenberg/gotenberg/issues/662.
				filename = sanitizeFilename(filename)

				// Use a UUID-based name on disk to avoid filesystem
				// NAME_MAX limits with long filenames.
				// See: https://github.com/gotenberg/gotenberg/issues/1500.
				safeName := uuid.New().String() + filepath.Ext(filename)
				path := fmt.Sprintf("%s/%s", ctx.dirPath, safeName)

				out, err := os.Create(path)
				if err != nil {
					dlErr := fmt.Errorf("create local file: %w", err)
					dlSpan.RecordError(dlErr)
					dlSpan.SetStatus(codes.Error, dlErr.Error())
					dlSpan.End()
					return dlErr
				}
				defer func() {
					closeErr := out.Close()
					if closeErr != nil {
						cause := fmt.Errorf("close download file: %w", closeErr)
						ctx.recordCleanupError(cause)
						err = errors.Join(err, cause)
					}
				}()

				// This will ensure we do not exceed the body limit.
				reader := &trackingReader{R: resp.Body, AddReadBytes: addReadBytes}

				_, err = io.Copy(out, reader)
				if err != nil {
					dlErr := fmt.Errorf("copy downloaded file from '%s' to local file: %w", dl.Url, err)
					dlSpan.RecordError(dlErr)
					dlSpan.SetStatus(codes.Error, dlErr.Error())
					dlSpan.End()
					return dlErr
				}

				dlSpan.SetStatus(codes.Ok, "")
				dlSpan.End()

				var formField string
				switch {
				case dl.Field == "embedded" || dl.Embedded:
					formField = EmbedsFormField
				case dl.Field == "watermark":
					formField = WatermarkFormField
				case dl.Field == "stamp":
					formField = StampFormField
				}
				results[i] = downloadFromResult{filename: filename, path: path, formField: formField}

				return nil
			})
		}

		err = eg.Wait()
		if err != nil {
			return ctx, cancel, err
		}

		for _, r := range results {
			ctx.files[r.filename] = r.path
			ctx.diskToOriginal[r.path] = r.filename
			if r.formField != "" {
				ctx.filesByField[r.formField] = append(ctx.filesByField[r.formField], r.path)
			}
		}
	}

	copyToDisk := func(fh *multipart.FileHeader) (err error) {
		in, err := fh.Open()
		if err != nil {
			return fmt.Errorf("open multipart file: %w", err)
		}

		defer func() {
			closeErr := in.Close()
			if closeErr != nil {
				cause := fmt.Errorf("close multipart input: %w", closeErr)
				ctx.recordCleanupError(cause)
				err = errors.Join(err, cause)
			}
		}()

		// This will ensure we do not exceed the body limit.
		reader := &trackingReader{R: in, AddReadBytes: addReadBytes}

		// Strip path separators (including backslashes) and control
		// characters, then NFC-normalize. Defends against directory
		// traversal in the on-disk name and Windows-side Zip Slip when the
		// original filename is later embedded in an output zip entry.
		// See: https://github.com/gotenberg/gotenberg/issues/662.
		filename := sanitizeFilename(fh.Filename)

		// Use a UUID-based name on disk to avoid filesystem
		// NAME_MAX limits with long filenames.
		// See: https://github.com/gotenberg/gotenberg/issues/1500.
		safeName := uuid.New().String() + filepath.Ext(filename)
		path := fmt.Sprintf("%s/%s", ctx.dirPath, safeName)

		out, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create local file: %w", err)
		}
		defer func() {
			closeErr := out.Close()
			if closeErr != nil {
				cause := fmt.Errorf("close multipart output: %w", closeErr)
				ctx.recordCleanupError(cause)
				err = errors.Join(err, cause)
			}
		}()

		_, err = io.Copy(out, reader)
		if err != nil {
			return fmt.Errorf("copy multipart file to local file: %w", err)
		}

		ctx.files[filename] = path
		ctx.diskToOriginal[path] = filename

		return nil
	}

	// Then, copy the form files, if any.
	for fieldName, files := range form.File {
		for _, fh := range files {
			err = copyToDisk(fh)
			if err != nil {
				return ctx, cancel, fmt.Errorf("copy to disk: %w", err)
			}
			// Track files by field name
			filename := sanitizeFilename(fh.Filename)
			filePath := ctx.files[filename]
			ctx.filesByField[fieldName] = append(ctx.filesByField[fieldName], filePath)
		}
	}

	// Create symlinks from original filenames to UUID-based disk names
	// so that relative asset references (e.g., <img src="image.png">)
	// resolve correctly when Chromium navigates to a file:// URL.
	// Symlink creation is best-effort: it may fail for filenames that
	// exceed the filesystem NAME_MAX limit (the reason UUIDs were
	// introduced in the first place).
	for originalName, diskPath := range ctx.files {
		symlinkPath := fmt.Sprintf("%s/%s", ctx.dirPath, originalName)
		if symlinkPath == diskPath {
			continue
		}
		linkErr := os.Symlink(filepath.Base(diskPath), symlinkPath)
		if linkErr != nil {
			logger.DebugContext(context.Background(), fmt.Sprintf("skip symlink for '%s': %s", originalName, linkErr))
		}
	}

	ctx.Log().DebugContext(ctx, fmt.Sprintf("form fields: %+v", ctx.values))
	ctx.Log().DebugContext(ctx, fmt.Sprintf("form files: %+v", ctx.files))
	ctx.Log().DebugContext(ctx, fmt.Sprintf("form files by field: %+v", ctx.filesByField))
	ctx.Log().DebugContext(ctx, fmt.Sprintf("total bytes: %d", totalBytesRead.Load()))

	return ctx, cancel, nil
}

// Request returns the [http.Request].
func (ctx *Context) Request() *http.Request {
	if ctx.request != nil {
		return ctx.request
	}
	return ctx.echoCtx.Request()
}

// FormData return a [FormData].
func (ctx *Context) FormData() *FormData {
	return &FormData{
		values:         ctx.values,
		files:          ctx.files,
		filesByField:   ctx.filesByField,
		diskToOriginal: ctx.diskToOriginal,
		errors:         nil,
	}
}

// FileCount returns the number of files received in the request.
func (ctx *Context) FileCount() int {
	return len(ctx.files)
}

// OriginalFilename returns the original filename associated with a disk path.
// If no mapping exists, it falls back to [filepath.Base].
func (ctx *Context) OriginalFilename(diskPath string) string {
	if original, ok := ctx.diskToOriginal[diskPath]; ok {
		return original
	}
	return filepath.Base(diskPath)
}

// RegisterDiskPath associates a disk path with an original filename so that
// [Context.OriginalFilename] can resolve it later.
func (ctx *Context) RegisterDiskPath(diskPath, originalFilename string) {
	ctx.diskToOriginal[diskPath] = originalFilename
}

// DirPath returns the path to the request's working directory.
func (ctx *Context) DirPath() string {
	return ctx.dirPath
}

// GeneratePath generates a path within the context's working directory.
// It generates a new UUID-based filename. It does not create a file.
func (ctx *Context) GeneratePath(extension string) string {
	return fmt.Sprintf("%s/%s%s", ctx.dirPath, uuid.New().String(), extension)
}

// GeneratePathFromFilename generates a path within the context's working
// directory. It uses a UUID-based name on disk to avoid filesystem NAME_MAX
// limits but registers the given filename so that [Context.OriginalFilename]
// can resolve it. It does not create a file.
func (ctx *Context) GeneratePathFromFilename(filename string) string {
	safeName := uuid.New().String() + filepath.Ext(filename)
	path := fmt.Sprintf("%s/%s", ctx.dirPath, safeName)
	ctx.diskToOriginal[path] = filename
	return path
}

// CreateSubDirectory creates a subdirectory within the context's working
// directory.
func (ctx *Context) CreateSubDirectory(dirName string) (string, error) {
	path := fmt.Sprintf("%s/%s", ctx.dirPath, dirName)
	err := ctx.mkdirAll.MkdirAll(path, 0o755)
	if err != nil {
		return "", fmt.Errorf("create sub-directory %s: %w", path, err)
	}
	return path, nil
}

// Rename is just a wrapper around [os.Rename], as we need to mock this
// behavior in our tests.
func (ctx *Context) Rename(oldpath, newpath string) error {
	ctx.Log().DebugContext(ctx, fmt.Sprintf("rename %s to %s", oldpath, newpath))
	err := ctx.pathRename.Rename(oldpath, newpath)
	if err != nil {
		return fmt.Errorf("rename path: %w", err)
	}
	return nil
}

// AddOutputPaths adds the given paths. Those paths will be used later to build
// the output file.
func (ctx *Context) AddOutputPaths(paths ...string) error {
	if ctx.unavailableV2() {
		if ctx.Context != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrContextAlreadyClosed
	}

	for _, path := range paths {
		rel, relErr := filepath.Rel(ctx.dirPath, path)
		if relErr != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return ErrOutOfBoundsOutputPath
		}

		ctx.outputPaths = append(ctx.outputPaths, path)
	}

	return nil
}

// Log returns the context [slog.Logger].
func (ctx *Context) Log() *slog.Logger {
	return ctx.logger
}

// BuildOutputFile builds the output file according to the output paths
// registered in the context. If many output paths, an archive is created.
func (ctx *Context) BuildOutputFile() (string, error) {
	if ctx.unavailableV2() {
		if ctx.Context != nil && ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", ErrContextAlreadyClosed
	}

	if len(ctx.outputPaths) == 0 {
		return "", errors.New("no output path")
	}

	if len(ctx.outputPaths) == 1 {
		ctx.logger.DebugContext(ctx, fmt.Sprintf("only one output file '%s', skip archive creation", ctx.outputPaths[0]))
		return ctx.outputPaths[0], nil
	}

	return ctx.buildArchiveV2()
}

// OutputFilename returns the filename based on the given output path or the
// "Gotenberg-Output-Filename" header's value.
func (ctx *Context) OutputFilename(outputPath string) string {
	filename := ctx.outputFilename
	if ctx.request == nil {
		filename, _ = ctx.echoCtx.Get("outputFilename").(string)
	}

	if filename == "" {
		return ctx.OriginalFilename(outputPath)
	}

	return fmt.Sprintf("%s%s", filename, filepath.Ext(outputPath))
}

// sanitizeFilename strips path separators (including backslashes, which
// [filepath.Base] ignores on Linux) and control characters from a
// caller-supplied filename, then NFC-normalizes the result. This prevents a
// Windows-side Zip Slip when an output zip is extracted by a permissive
// extractor that interprets '\' as a path separator.
func sanitizeFilename(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	return norm.NFC.String(name)
}
