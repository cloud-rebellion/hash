// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package api

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
)

func (ctx *Context) buildArchiveV2() (result string, err error) {
	path := ctx.GeneratePath(".zip")
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create zip file: %w", err)
	}
	writer := zip.NewWriter(out)
	defer func() {
		zipErr := writer.Close()
		fileErr := out.Close()
		if zipErr != nil {
			ctx.recordCleanupError(fmt.Errorf("finalize zip: %w", zipErr))
		}
		if fileErr != nil {
			ctx.recordCleanupError(fmt.Errorf("close zip file: %w", fileErr))
		}
		err = errors.Join(err, zipErr, fileErr)
		if err != nil {
			result = ""
		}
	}()
	for _, source := range ctx.outputPaths {
		copyErr := func() (err error) {
			in, err := ctx.openOutputV2(source)
			if err != nil {
				return fmt.Errorf("open archive input: %w", err)
			}
			defer func() {
				if closeErr := in.Close(); closeErr != nil {
					cause := fmt.Errorf("close archive input: %w", closeErr)
					ctx.recordCleanupError(cause)
					err = errors.Join(err, cause)
				}
			}()
			info, err := in.Stat()
			if err != nil {
				return fmt.Errorf("stat archive input: %w", err)
			}
			if !info.Mode().IsRegular() {
				return errors.New("archive input must be a regular file")
			}
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = ctx.OriginalFilename(source)
			header.Method = zip.Deflate
			part, err := writer.CreateHeader(header)
			if err != nil {
				return err
			}
			_, err = io.Copy(part, hashProcessingReaderV2{ctx: ctx, source: in})
			return err
		}()
		if copyErr != nil {
			return "", fmt.Errorf("archive output files: %w", copyErr)
		}
	}
	return path, nil
}
