// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const hashMultipartEntityLimitV2 int64 = 24 << 20

func hashCleanupCallV2(f func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("owned cleanup panicked; retirement unconfirmed")
		}
	}()
	return f()
}
func (ctx *Context) recordCleanupError(err error) {
	if err == nil {
		return
	}
	ctx.cleanupMu.Lock()
	ctx.cleanupErr = errors.Join(ctx.cleanupErr, err)
	ctx.cleanupMu.Unlock()
}
func (ctx *Context) retireCheckedV2() error {
	ctx.cleanupOnce.Do(func() {
		ctx.retired.Store(true)
		if ctx.processCancel != nil {
			ctx.processCancel()
		}
		for i := len(ctx.cleanups) - 1; i >= 0; i-- {
			ctx.recordCleanupError(hashCleanupCallV2(ctx.cleanups[i]))
		}
	})
	ctx.cleanupMu.Lock()
	defer ctx.cleanupMu.Unlock()
	return ctx.cleanupErr
}
func (ctx *Context) unavailableV2() bool {
	return ctx.cancelled || ctx.retired.Load() || (ctx.Context != nil && ctx.Err() != nil)
}

type hashStageBodyV2 struct {
	*os.File
	once sync.Once
	err  error
}

func (s *hashStageBodyV2) Close() error { s.once.Do(func() { s.err = s.File.Close() }); return s.err }

type hashProcessingReaderV2 struct {
	ctx    context.Context
	source io.Reader
	input  bool
	now    func() time.Time // nil uses the process clock
}

// Deadline timestamps are authoritative even if the context timer callback has
// not yet been scheduled when a transport read deadline wakes the reader.
func hashProcessingCauseV2(ctx context.Context, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !now.Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
func (r hashProcessingReaderV2) Read(p []byte) (int, error) {
	now := r.now
	if now == nil {
		now = time.Now
	}
	if err := hashProcessingCauseV2(r.ctx, now()); err != nil {
		return 0, err
	}
	n, err := r.source.Read(p)
	if cause := hashProcessingCauseV2(r.ctx, now()); cause != nil {
		return n, cause
	}
	if r.input && err != nil && !errors.Is(err, io.EOF) {
		return n, WrapError(err, NewSentinelHttpError(http.StatusBadRequest, "Malformed request body"))
	}
	return n, err
}
func (ctx *Context) stageMultipartV2(owner *hashRequestV2, form *multipart.Form) error {
	request := ctx.echoCtx.Request()
	if form != nil {
		ctx.cleanups = append(ctx.cleanups, form.RemoveAll)
	}
	if !owner.reserveMultipart() {
		return NewSentinelHttpError(http.StatusTooManyRequests, "The renderer multipart queue is full. Retry shortly.")
	}
	if request.MultipartForm != nil || request.Form != nil || request.PostForm != nil {
		return NewSentinelHttpError(http.StatusBadRequest, "Pre-parsed multipart requests are not accepted")
	}
	if request.ContentLength > hashMultipartEntityLimitV2 {
		return NewSentinelHttpError(http.StatusRequestEntityTooLarge, "The complete multipart body exceeds24MiB")
	}
	media, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || media != "multipart/form-data" || params["boundary"] == "" {
		return NewSentinelHttpError(http.StatusUnsupportedMediaType, "Invalid multipart Content-Type or boundary")
	}
	// Retain the exact path BEFORE creation, including partial mkdir failure.
	ctx.dirPath = ctx.fs.NewDirPath()
	ctx.cleanups = append(ctx.cleanups, func() error { return os.RemoveAll(ctx.dirPath) })
	if err = ctx.mkdirAll.MkdirAll(ctx.dirPath, 0o700); err != nil {
		return fmt.Errorf("create owned workspace: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(ctx.dirPath, ".hash-entity.multipart"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create multipart staging file: %w", err)
	}
	staged := &hashStageBodyV2{File: file}
	ctx.staged = staged
	ctx.cleanups = append(ctx.cleanups, staged.Close)
	deadline, _ := ctx.Deadline()
	owner.stageDeadline(deadline)
	defer owner.stageDeadline(time.Time{})
	// Read the COMPLETE HTTP entity, including preamble/epilogue, before the
	// multipart parser can stop at its final boundary. Never buffer it all.
	n, copyErr := io.Copy(file, io.LimitReader(hashProcessingReaderV2{ctx: ctx, source: request.Body, input: true}, hashMultipartEntityLimitV2+1))
	if copyErr != nil {
		if errors.Is(copyErr, io.ErrUnexpectedEOF) {
			return WrapError(copyErr, NewSentinelHttpError(http.StatusBadRequest, "Malformed request body"))
		}
		return fmt.Errorf("stage complete multipart body: %w", copyErr)
	}
	if n > hashMultipartEntityLimitV2 {
		return NewSentinelHttpError(http.StatusRequestEntityTooLarge, "The complete multipart body exceeds24MiB")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind multipart body: %w", err)
	}
	request.Body = staged
	request.ContentLength = n
	// Parsing is performed once by newContext with the pinned in-memory
	// allowance; staged entity size bounds aggregate file bytes below it.
	return nil
}
