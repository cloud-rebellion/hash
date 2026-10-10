// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
)

const pdfWorkerTimeout = 15 * time.Second
const pdfWorkerHeaderLimit = 4096
const pdfWorkerProtocolVersion = 2
const pdfWorkerReadinessInterval = 10 * time.Second
const defaultPDFWorkerPath = "/usr/local/bin/hash-pdf-worker"

var ErrPDFWorkerUnavailable = errors.New("sanitize: isolated PDF worker unavailable")
var ErrPDFWorkerCapacity = errors.New("sanitize: isolated PDF worker capacity exceeded")
var activePDFWorker atomic.Pointer[pdfWorker]

type pdfWorker struct {
	path  string
	slots chan struct{}

	readinessMu    sync.Mutex
	readinessUntil time.Time
	readinessErr   error
	readinessDone  chan struct{}
}

type pdfWorkerRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	Operation       string `json:"operation"`
	Length          int    `json:"length"`
	Asset           string `json:"asset,omitempty"`
}

type pdfWorkerResponse struct {
	ProtocolVersion int     `json:"protocol_version"`
	Length          int     `json:"length"`
	Pages           int     `json:"pages,omitempty"`
	Report          *Report `json:"report,omitempty"`
	Error           string  `json:"error,omitempty"`
}

// ConfigurePDFWorker is called before server/worker admission. Outside explicit
// development the bundled, Linux-hardened executable is mandatory. A configured
// but broken worker never falls back to parsing customer bytes in the parent.
func ConfigurePDFWorker(ctx context.Context, path string, environment string) error {
	// Preserve a failed-closed state if startup configuration is invalid.
	activePDFWorker.Store(&pdfWorker{})
	if path == "" {
		if environment == "development" {
			activePDFWorker.Store(nil)
			return nil
		}
		path = defaultPDFWorkerPath
	}
	if !filepath.IsAbs(path) {
		return ErrPDFWorkerUnavailable
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return ErrPDFWorkerUnavailable
	}
	w := &pdfWorker{path: path, slots: make(chan struct{}, 2)}
	if _, _, err := w.run(ctx, pdfWorkerRequest{Operation: "probe"}, nil); err != nil {
		return fmt.Errorf("%w: startup probe failed", ErrPDFWorkerUnavailable)
	}
	w.readinessUntil = time.Now().Add(pdfWorkerReadinessInterval)
	activePDFWorker.Store(w)
	return nil
}

// CheckPDFWorker coalesces readiness probes and caches success and failure for
// ten seconds. Public health traffic cannot launch a parser per request or
// poison shared readiness by canceling its request. Startup still probes before
// admission; busy processing slots retain the previous readiness result.
func CheckPDFWorker(ctx context.Context) error {
	w := activePDFWorker.Load()
	if w == nil {
		return nil
	} // Only library tests / explicit development opt out.
	if w.path == "" {
		return ErrPDFWorkerUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.readinessMu.Lock()
	if time.Now().Before(w.readinessUntil) {
		err := w.readinessErr
		w.readinessMu.Unlock()
		return err
	}
	if w.readinessDone == nil {
		w.readinessDone = make(chan struct{})
		go w.refreshReadiness()
	}
	done := w.readinessDone
	w.readinessMu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		w.readinessMu.Lock()
		err := w.readinessErr
		w.readinessMu.Unlock()
		return err
	}
}

func (w *pdfWorker) refreshReadiness() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := w.run(ctx, pdfWorkerRequest{Operation: "probe"}, nil)
	w.readinessMu.Lock()
	defer w.readinessMu.Unlock()
	if !errors.Is(err, ErrPDFWorkerCapacity) {
		w.readinessErr = err
	}
	w.readinessUntil = time.Now().Add(pdfWorkerReadinessInterval)
	close(w.readinessDone)
	w.readinessDone = nil
}

func (w *pdfWorker) clean(ctx context.Context, asset, ct string, raw []byte) (Result, error) {
	response, body, err := w.run(ctx, pdfWorkerRequest{Operation: "clean", Asset: asset, Length: len(raw)}, raw)
	if err != nil {
		return Result{}, err
	}
	if response.Report == nil || response.Report.Asset != asset || response.Report.ContentType != ct || ValidatePDFResult(*response.Report, pdfSHA(raw), pdfSHA(body), int64(len(raw)), int64(len(body))) != nil {
		return Result{}, ErrPDFWorkerUnavailable
	}
	return Result{Bytes: body, Report: *response.Report}, nil
}

func (w *pdfWorker) run(parent context.Context, request pdfWorkerRequest, raw []byte) (pdfWorkerResponse, []byte, error) {
	if w.path == "" {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if len(raw) > MaxPDFBytes {
		return pdfWorkerResponse{}, nil, ErrPDFTooLarge
	}
	if err := parent.Err(); err != nil {
		return pdfWorkerResponse{}, nil, err
	}
	select {
	case w.slots <- struct{}{}:
		defer func() { <-w.slots }()
	default:
		return pdfWorkerResponse{}, nil, ErrPDFWorkerCapacity
	}
	ctx, cancel := context.WithTimeout(parent, pdfWorkerTimeout)
	defer cancel()
	request.ProtocolVersion = pdfWorkerProtocolVersion
	header, err := json.Marshal(request)
	if err != nil || len(header) >= pdfWorkerHeaderLimit {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	cmd := exec.CommandContext(ctx, w.path)
	// No service credentials, working files, sockets, or extra descriptors cross
	// this boundary. Linux syscall filtering is installed before reading stdin.
	cmd.Env = []string{"GOMAXPROCS=1", "GOMEMLIMIT=384MiB", "HOME=/nonexistent", "TMPDIR=/nonexistent"}
	cmd.Dir = "/"
	cmd.Stdin = io.MultiReader(bytes.NewReader(append(header, '\n')), bytes.NewReader(raw))
	cmd.WaitDelay = time.Second
	output := &pdfWorkerOutput{limit: MaxPDFBytes + pdfWorkerHeaderLimit}
	cmd.Stdout = output
	cmd.Stderr = io.Discard // PDF contents and parser diagnostics never reach logs.
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return pdfWorkerResponse{}, nil, ctx.Err()
		}
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	reader := bufio.NewReaderSize(bytes.NewReader(output.Bytes()), pdfWorkerHeaderLimit)
	var response pdfWorkerResponse
	if err := readPDFWorkerHeader(reader, &response); err != nil || response.ProtocolVersion != pdfWorkerProtocolVersion || response.Length < 0 || response.Length > MaxPDFBytes {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(reader, int64(response.Length)+1))
	if err != nil || len(body) != response.Length {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if response.Error != "" {
		if response.Length != 0 || response.Report != nil || response.Pages != 0 {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
		switch response.Error {
		case "too-large":
			return pdfWorkerResponse{}, nil, ErrPDFTooLarge
		case "too-many-pages":
			return pdfWorkerResponse{}, nil, ErrTooManyPages
		case "active-content":
			return pdfWorkerResponse{}, nil, ErrActivePDFContent
		case "invalid-pdf":
			return pdfWorkerResponse{}, nil, errors.New("sanitize: invalid PDF")
		default:
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
	}
	if request.Operation == "clean" && (response.Pages != 0 || response.Length < 1 || response.Report == nil || ValidatePDFResult(*response.Report, pdfSHA(raw), pdfSHA(body), int64(len(raw)), int64(len(body))) != nil) {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation == "pages" && (response.Pages < 1 || response.Pages > MaxPDFPages || response.Length != 0 || response.Report != nil) {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation == "probe" && (response.Pages != 1 || response.Length != 0 || response.Report != nil) {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	return response, body, nil
}

type pdfWorkerOutput struct {
	bytes.Buffer
	limit int
}

func (b *pdfWorkerOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, ErrPDFTooLarge
	}
	return b.Buffer.Write(p)
}

func readPDFWorkerHeader(reader *bufio.Reader, target any) error {
	header, err := reader.ReadSlice('\n')
	if err != nil || len(header) > pdfWorkerHeaderLimit {
		return ErrPDFWorkerUnavailable
	}
	if err := strictPDFWorkerJSON(header); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(header))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrPDFWorkerUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(header, &fields) != nil {
		return ErrPDFWorkerUnavailable
	}
	for key, value := range fields {
		allowed := false
		switch target.(type) {
		case *pdfWorkerRequest:
			allowed = key == "protocol_version" || key == "operation" || key == "length" || key == "asset"
		case *pdfWorkerResponse:
			allowed = key == "protocol_version" || key == "length" || key == "pages" || key == "report" || key == "error"
		}
		if !allowed || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrPDFWorkerUnavailable
		}
	}
	for _, key := range []string{"protocol_version", "length"} {
		if value, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrPDFWorkerUnavailable
		}
	}
	if response, ok := target.(*pdfWorkerResponse); ok && response.Report != nil {
		if _, err := DecodePDFReport(fields["report"]); err != nil {
			return ErrPDFWorkerUnavailable
		}
	}
	return nil
}

// encoding/json otherwise accepts duplicate object keys (including nested
// proof properties). At this trust boundary a conflicting header is refused.
func strictPDFWorkerJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return ErrPDFWorkerUnavailable
		}
		token, err := decoder.Token()
		if err != nil {
			return ErrPDFWorkerUnavailable
		}
		delim, nested := token.(json.Delim)
		if !nested {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return ErrPDFWorkerUnavailable
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrPDFWorkerUnavailable
		}
		_, err = decoder.Token()
		if err != nil {
			return ErrPDFWorkerUnavailable
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrPDFWorkerUnavailable
	}
	return nil
}

// ServePDFWorker serves exactly one bounded operation. The executable MUST
// install its resource limits and syscall policy before invoking this function.
// It is separate from CleanWithContext so it never recurses or bypasses scanning
// at an application entry point. No customer PDF is written to disk.
func ServePDFWorker(input io.Reader, output io.Writer) error {
	pdfapi.DisableConfigDir()
	reader := bufio.NewReaderSize(input, pdfWorkerHeaderLimit)
	var request pdfWorkerRequest
	if err := readPDFWorkerHeader(reader, &request); err != nil {
		return err
	}
	if request.ProtocolVersion != pdfWorkerProtocolVersion || request.Length < 0 || request.Length > MaxPDFBytes || len(request.Asset) > 128 {
		return ErrPDFWorkerUnavailable
	}
	if request.Operation != "probe" && request.Operation != "clean" && request.Operation != "pages" {
		return ErrPDFWorkerUnavailable
	}
	if request.Operation == "probe" && request.Length != 0 || request.Operation != "clean" && request.Asset != "" {
		return ErrPDFWorkerUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(reader, int64(request.Length)+1))
	if err != nil || len(raw) != request.Length {
		return ErrPDFWorkerUnavailable
	}
	response := pdfWorkerResponse{ProtocolVersion: pdfWorkerProtocolVersion}
	var body []byte
	switch request.Operation {
	case "probe":
		// Exercise the real parser/rewrite and the runtime's lazy timer/poller
		// setup under the policy; a zero-work echo can hide a broken syscall set.
		time.Sleep(time.Millisecond)
		var fixture bytes.Buffer
		err = pdfapi.Create(nil, strings.NewReader(`{"pages":{"1":{"content":{"text":[{"value":"Hash parser probe","anchor":"center","font":{"name":"Helvetica","size":12}}]}}}}`), &fixture, nil)
		if err == nil {
			var result Result
			result, err = cleanPDF("probe", "application/pdf", fixture.Bytes())
			if err == nil {
				response.Pages, err = pageCountInProcess(result.Bytes)
			}
		}
	case "clean":
		var result Result
		result, err = cleanPDF(request.Asset, "application/pdf", raw)
		if err == nil {
			response.Report = &result.Report
			body = result.Bytes
		}
	case "pages":
		response.Pages, err = pageCountInProcess(raw)
		if err == nil && response.Pages > MaxPDFPages {
			err = ErrTooManyPages
		}
	}
	if err != nil {
		switch {
		case errors.Is(err, ErrPDFTooLarge):
			response.Error = "too-large"
		case errors.Is(err, ErrTooManyPages):
			response.Error = "too-many-pages"
		case errors.Is(err, ErrActivePDFContent):
			response.Error = "active-content"
		default:
			response.Error = "invalid-pdf"
		}
		body = nil
		response.Pages, response.Report = 0, nil
	}
	response.Length = len(body)
	header, err := json.Marshal(response)
	if err != nil || len(header) >= pdfWorkerHeaderLimit {
		return ErrPDFWorkerUnavailable
	}
	if _, err := output.Write(append(header, '\n')); err != nil {
		return err
	}
	_, err = output.Write(body)
	return err
}
