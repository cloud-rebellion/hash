// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package api

import (
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (ctx *Context) openOutputV2(path string) (file *os.File, err error) {
	rel, err := filepath.Rel(ctx.dirPath, path)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, ErrOutOfBoundsOutputPath
	}
	root, err := os.OpenRoot(ctx.dirPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			cause := fmt.Errorf("close output root: %w", closeErr)
			ctx.recordCleanupError(cause)
			err = errors.Join(err, cause)
			if file != nil {
				ctx.recordCleanupError(file.Close())
				file = nil
			}
		}
	}()
	info, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("output must be a regular owned file")
	}
	file, err = root.Open(rel)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() {
		closeErr := file.Close()
		ctx.recordCleanupError(closeErr)
		file = nil
		return nil, errors.Join(statErr, errors.New("opened output must be a regular owned file"), closeErr)
	}
	return file, nil
}
func (ctx *Context) sendOutputV2(c echo.Context, path string) (err error) {
	// A generated renderer attachment is one complete output. ServeContent
	// spawns an unjoined file reader for multi-range responses; refuse ranges
	// before opening the file rather than creating that producer.
	if len(c.Request().Header.Values("Range")) != 0 {
		return NewSentinelHttpError(http.StatusBadRequest, "Range requests are unsupported for generated renderer attachments")
	}
	file, err := ctx.openOutputV2(path)
	if err != nil {
		return fmt.Errorf("open response output: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			cause := fmt.Errorf("close response output: %w", closeErr)
			ctx.recordCleanupError(cause)
			err = errors.Join(err, cause)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	c.Response().Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": ctx.OutputFilename(path)}))
	before := c.Response().Size
	http.ServeContent(c.Response(), c.Request(), info.Name(), info.ModTime(), file)
	if c.Request().Method != http.MethodHead {
		if length := c.Response().Header().Get("Content-Length"); length != "" {
			expected, parseErr := strconv.ParseInt(length, 10, 64)
			if parseErr != nil || expected < 0 || c.Response().Size-before != expected {
				return errors.New("response output transfer incomplete")
			}
		}
	}
	return nil
}
