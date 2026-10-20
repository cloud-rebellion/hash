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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
)

const pdfWorkerTimeout = 15 * time.Second
const pdfWorkerHeaderLimit = 4096
const pdfWorkerProtocolVersion = 3
const pdfWorkerReadinessInterval = 10 * time.Second
const defaultPDFWorkerPath = "/usr/local/bin/hash-pdf-worker"

var ErrPDFWorkerUnavailable = errors.New("sanitize: isolated PDF worker unavailable")
var ErrPDFWorkerCapacity = errors.New("sanitize: isolated PDF worker capacity exceeded")
var activePDFWorker atomic.Pointer[pdfWorker]

type pdfWorker struct {
	observer PDFWorkerObserverV1
	path     string
	slots    chan struct{}

	readinessMu    sync.Mutex
	readinessUntil time.Time
	readinessErr   error
	readinessDone  chan struct{}
}

type pdfWorkerRequest struct {
	ProtocolVersion      int                         `json:"protocol_version"`
	Operation            string                      `json:"operation"`
	Length               int                         `json:"length"`
	Asset                string                      `json:"asset,omitempty"`
	BodyLength           int                         `json:"body_length,omitempty"`
	SigningPageLength    int                         `json:"signing_page_length,omitempty"`
	SignatureLength      int                         `json:"signature_length,omitempty"`
	DisclosureLength     int                         `json:"disclosure_length,omitempty"`
	ProviderBindings     *PDFProviderOverlayBindings `json:"provider_bindings,omitempty"`
	ManualMetadataLength int                         `json:"manual_metadata_length,omitempty"`
}

type pdfWorkerResponse struct {
	ProtocolVersion  int                         `json:"protocol_version"`
	Length           int                         `json:"length"`
	Pages            int                         `json:"pages,omitempty"`
	Report           *Report                     `json:"report,omitempty"`
	Error            string                      `json:"error,omitempty"`
	Composition      *PDFCompositionManifest     `json:"composition,omitempty"`
	ProviderOverlay  *PDFProviderOverlayManifest `json:"provider_overlay,omitempty"`
	ManualOverlay    *PDFManualOverlayManifest   `json:"manual_overlay,omitempty"`
	ManualLayers     *PDFManualLayersManifest    `json:"manual_layers,omitempty"`
	ManualOperations string                      `json:"manual_operations,omitempty"`
}

// ConfigurePDFWorker is called before server/worker admission. Outside explicit
// development the bundled, Linux-hardened executable is mandatory. A configured
// but broken worker never falls back to parsing customer bytes in the parent.
func ConfigurePDFWorker(ctx context.Context, path string, environment string) error {
	return ConfigurePDFWorkerWithObserverV1(ctx, path, environment, nil)
}

// ConfigurePDFWorkerWithObserverV1 binds a fixed trusted parent observer at
// worker-instance birth. Child execution and development opt-out are unchanged.
func ConfigurePDFWorkerWithObserverV1(ctx context.Context, path string, environment string, observer PDFWorkerObserverV1) error {
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
	w := &pdfWorker{path: path, slots: make(chan struct{}, 2), observer: observer}
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

func (w *pdfWorker) composeSigningPage(ctx context.Context, asset string, bodyPDF, signingPagePDF []byte) (PDFCompositionResult, error) {
	if len(bodyPDF) == 0 || len(signingPagePDF) == 0 || len(bodyPDF) > MaxPDFBytes || len(signingPagePDF) > MaxPDFBytes-len(bodyPDF) || len(asset) > 128 {
		return PDFCompositionResult{}, errPDFComposition
	}
	raw := make([]byte, 0, len(bodyPDF)+len(signingPagePDF))
	raw = append(raw, bodyPDF...)
	raw = append(raw, signingPagePDF...)
	response, output, err := w.run(ctx, pdfWorkerRequest{Operation: pdfComposeSigningPageOperation, Asset: asset, Length: len(raw), BodyLength: len(bodyPDF), SigningPageLength: len(signingPagePDF)}, raw)
	if err != nil {
		return PDFCompositionResult{}, err
	}
	if response.Report == nil || response.Composition == nil || response.Report.Asset != asset || response.Composition.BodySHA256 != pdfSHA(bodyPDF) || response.Composition.SigningPageSHA256 != pdfSHA(signingPagePDF) {
		return PDFCompositionResult{}, ErrPDFWorkerUnavailable
	}
	result := PDFCompositionResult{Result: Result{Bytes: output, Report: *response.Report}, Composition: *response.Composition}
	if ValidatePDFCompositionResult(result) != nil {
		return PDFCompositionResult{}, ErrPDFWorkerUnavailable
	}
	return result, nil
}

func (w *pdfWorker) runBoundedV1(parent context.Context, request pdfWorkerRequest, raw []byte) (pdfWorkerResponse, []byte, error) {
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
		if response.Length != 0 || response.Report != nil || response.Pages != 0 || response.Composition != nil || response.ProviderOverlay != nil || response.ManualOverlay != nil || response.ManualLayers != nil || response.ManualOperations != "" {
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
			return pdfWorkerResponse{}, nil, ErrPDFInvalid
		case "invalid-provider-overlay":
			if request.Operation != pdfProviderOverlayOperation {
				return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
			}
			return pdfWorkerResponse{}, nil, ErrPDFProviderOverlay
		case "invalid-signing-page":
			if request.Operation != pdfComposeSigningPageOperation {
				return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
			}
			return pdfWorkerResponse{}, nil, ErrPDFSigningPageInvalid
		case "invalid-manual-overlay":
			if request.Operation != pdfManualInspectOperation && request.Operation != pdfManualOverlayOperation && request.Operation != pdfManualLayersOperation && request.Operation != pdfManualFragmentOperation {
				return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
			}
			return pdfWorkerResponse{}, nil, ErrPDFManualOverlay
		case "invalid-manual-layers":
			if request.Operation != pdfManualLayersOperation {
				return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
			}
			return pdfWorkerResponse{}, nil, ErrPDFManualLayers
		case "invalid-manual-fragment":
			if request.Operation != pdfManualLayersOperation && request.Operation != pdfManualFragmentOperation {
				return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
			}
			return pdfWorkerResponse{}, nil, ErrPDFManualFragment
		default:
			if request.Operation == pdfProviderOverlayOperation {
				return pdfWorkerResponse{}, nil, providerOverlayErrorFromCode(response.Error)
			}
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
	}
	if request.Operation != "probe" && response.ManualOperations != "" {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation != pdfProviderOverlayOperation && response.ProviderOverlay != nil {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation != pdfComposeSigningPageOperation && response.Composition != nil {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation != pdfManualOverlayOperation && response.ManualOverlay != nil {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation != pdfManualLayersOperation && response.ManualLayers != nil {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation == pdfManualFragmentOperation {
		n := request.ManualMetadataLength
		var descriptor manualFragmentRequestV1
		admission, err := DecodePDFManualFragmentAdmission(body)
		if n < 1 || n > manualMetadataLimit || n >= len(raw) || decodeManualLayersJSON(raw[:n], &descriptor) != nil || validateManualFragmentRequestV1(descriptor, raw[n:]) != nil || response.Pages != 0 || response.Report != nil || err != nil || admission.PDFSHA256 != descriptor.PDFSHA256 || admission.PDFBytes != descriptor.PDFBytes || admission.WidthPoints != descriptor.WidthPoints || admission.HeightPoints != descriptor.HeightPoints {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
	}
	if request.Operation == pdfManualLayersOperation {
		n := request.ManualMetadataLength
		var batch manualLayersBatchV1
		if n < 1 || n > manualMetadataLimit || n >= len(raw) || decodeManualLayersJSON(raw[:n], &batch) != nil || batch.SchemaVersion != 1 || validateManualLayerDescriptorsV1(batch.Layers, batch.Pages) != nil || response.Pages != 0 || response.Report == nil || response.ManualLayers == nil {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
		m := *response.ManualLayers
		if ValidatePDFManualLayersResult(PDFManualLayersResult{Result{body, *response.Report}, m}) != nil || m.DescriptorSHA256 != pdfSHA(raw[:n]) || m.SourceSHA256 != batch.SourceSHA256 || m.SourceBytes != batch.SourceBytes || m.GeometrySHA256 != batch.GeometrySHA256 || m.Pages != batch.Pages || m.Layers != len(batch.Layers) {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
	}
	if request.Operation == pdfManualInspectOperation {
		var geometry PDFManualGeometry
		if response.Pages != 0 || response.Report != nil || response.Length < 1 || decodeManualJSON(body, &geometry) != nil || validateManualGeometry(geometry, raw) != nil {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
	}
	if request.Operation == pdfManualOverlayOperation {
		n := request.ManualMetadataLength
		var batch manualOverlayBatch
		if n < 1 || n > manualMetadataLimit || n >= len(raw) || decodeManualJSON(raw[:n], &batch) != nil || response.Pages != 0 || response.Report == nil || response.ManualOverlay == nil || response.Report.Asset != "manual-stamped-pdf" {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
		m := *response.ManualOverlay
		if validateManualResult(PDFManualOverlayResult{Result{body, *response.Report}, m}) != nil || m.DescriptorSHA256 != pdfSHA(raw[:n]) || m.SourceSHA256 != batch.SourceSHA256 || m.SourceBytes != batch.SourceBytes || m.GeometrySHA256 != batch.GeometrySHA256 || m.Pages != batch.Pages || m.Overlays != len(batch.Overlays) {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
	}
	if request.Operation == "clean" && (response.Pages != 0 || response.Length < 1 || response.Report == nil || ValidatePDFResult(*response.Report, pdfSHA(raw), pdfSHA(body), int64(len(raw)), int64(len(body))) != nil) {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation == "pages" && (response.Pages < 1 || response.Pages > MaxPDFPages || response.Length != 0 || response.Report != nil) {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation == "probe" && (response.Pages != 1 || response.Length != 0 || response.Report != nil || response.ManualOperations != pdfManualOperationsCapabilityV1) {
		return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
	}
	if request.Operation == pdfComposeSigningPageOperation {
		if request.BodyLength < 1 || request.SigningPageLength < 1 || request.BodyLength > len(raw) || request.SigningPageLength != len(raw)-request.BodyLength || response.Pages != 0 || response.Length < 1 || response.Report == nil || response.Composition == nil {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
		result := PDFCompositionResult{Result: Result{Bytes: body, Report: *response.Report}, Composition: *response.Composition}
		if response.Report.Asset != request.Asset || response.Composition.BodySHA256 != pdfSHA(raw[:request.BodyLength]) || response.Composition.SigningPageSHA256 != pdfSHA(raw[request.BodyLength:]) || ValidatePDFCompositionResult(result) != nil {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
	}
	if request.Operation == pdfProviderOverlayOperation {
		if !validProviderRequest(request, len(raw)) || response.Pages != 0 || response.Length < 1 || response.Report == nil || response.ProviderOverlay == nil || response.Report.Asset != request.Asset {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
		m := response.ProviderOverlay
		b := request.BodyLength
		s := request.SignatureLength
		if m.BindingsSHA256 != PDFProviderOverlayBindingsSHA256(*request.ProviderBindings) || m.BaseSHA256 != pdfSHA(raw[:b]) || m.BaseBytes != int64(b) || m.SignatureSHA256 != pdfSHA(raw[b:b+s]) || m.DisclosureSHA256 != pdfSHA(raw[b+s:]) || ValidatePDFProviderOverlayResult(PDFProviderOverlayResult{Result: Result{Bytes: body, Report: *response.Report}, Overlay: *m}) != nil {
			return pdfWorkerResponse{}, nil, ErrPDFWorkerUnavailable
		}
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
			allowed = key == "protocol_version" || key == "operation" || key == "length" || key == "asset" || key == "body_length" || key == "signing_page_length" || key == "signature_length" || key == "disclosure_length" || key == "provider_bindings" || key == "manual_metadata_length"
		case *pdfWorkerResponse:
			allowed = key == "protocol_version" || key == "length" || key == "pages" || key == "report" || key == "error" || key == "composition" || key == "provider_overlay" || key == "manual_overlay" || key == "manual_layers" || key == "manual_operations"
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
	if request, ok := target.(*pdfWorkerRequest); ok {
		_, manual := fields["manual_metadata_length"]
		if request.Operation == pdfManualOverlayOperation || request.Operation == pdfManualLayersOperation || request.Operation == pdfManualFragmentOperation {
			if !manual || request.ManualMetadataLength < 1 || request.ManualMetadataLength > manualMetadataLimit || request.ManualMetadataLength >= request.Length {
				return ErrPDFWorkerUnavailable
			}
		} else if manual {
			return ErrPDFWorkerUnavailable
		}
		if _, exists := fields["operation"]; !exists {
			return ErrPDFWorkerUnavailable
		}
		_, body := fields["body_length"]
		_, suffix := fields["signing_page_length"]
		if request.Operation == pdfComposeSigningPageOperation {
			if !body || !suffix {
				return ErrPDFWorkerUnavailable
			}
		} else if request.Operation == pdfProviderOverlayOperation {
			if !body || suffix || !validProviderRequest(*request, request.Length) {
				return ErrPDFWorkerUnavailable
			}
		} else if body || suffix {
			return ErrPDFWorkerUnavailable
		}
		_, signature := fields["signature_length"]
		_, disclosure := fields["disclosure_length"]
		_, bindings := fields["provider_bindings"]
		if request.Operation != pdfProviderOverlayOperation && (signature || disclosure || bindings) {
			return ErrPDFWorkerUnavailable
		}
		if request.Operation == pdfProviderOverlayOperation && (!signature || !disclosure || !bindings || !providerExactJSONShape(fields["provider_bindings"], reflect.TypeOf(PDFProviderOverlayBindings{}))) {
			return ErrPDFWorkerUnavailable
		}
	}
	if response, ok := target.(*pdfWorkerResponse); ok && response.Report != nil {
		if _, err := DecodePDFReport(fields["report"]); err != nil {
			return ErrPDFWorkerUnavailable
		}
	}
	if response, ok := target.(*pdfWorkerResponse); ok && response.Composition != nil {
		if _, err := DecodePDFCompositionManifest(fields["composition"]); err != nil {
			return ErrPDFWorkerUnavailable
		}
	}
	if response, ok := target.(*pdfWorkerResponse); ok && response.ProviderOverlay != nil {
		if _, err := DecodePDFProviderOverlayManifest(fields["provider_overlay"]); err != nil {
			return ErrPDFWorkerUnavailable
		}
	}
	if response, ok := target.(*pdfWorkerResponse); ok && response.ManualOverlay != nil {
		var manifest PDFManualOverlayManifest
		if decodeManualJSON(fields["manual_overlay"], &manifest) != nil || validateManualManifest(manifest) != nil {
			return ErrPDFWorkerUnavailable
		}
	}
	if response, ok := target.(*pdfWorkerResponse); ok && response.ManualLayers != nil {
		if _, err := DecodePDFManualLayersManifest(fields["manual_layers"]); err != nil {
			return ErrPDFWorkerUnavailable
		}
	}
	return nil
}

func validProviderRequest(r pdfWorkerRequest, n int) bool {
	return r.ProviderBindings != nil && validProviderBindings(*r.ProviderBindings) && r.BodyLength > 0 && r.SignatureLength > 0 && r.DisclosureLength > 0 && r.BodyLength <= n && r.SignatureLength <= n-r.BodyLength && r.DisclosureLength == n-r.BodyLength-r.SignatureLength && r.SigningPageLength == 0
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
	if request.Operation != "probe" && request.Operation != "clean" && request.Operation != "pages" && request.Operation != pdfComposeSigningPageOperation && request.Operation != pdfProviderOverlayOperation && request.Operation != pdfManualInspectOperation && request.Operation != pdfManualOverlayOperation && request.Operation != pdfManualLayersOperation && request.Operation != pdfManualFragmentOperation {
		return ErrPDFWorkerUnavailable
	}
	if request.Operation == "probe" && request.Length != 0 || request.Operation != "clean" && request.Operation != pdfComposeSigningPageOperation && request.Operation != pdfProviderOverlayOperation && request.Asset != "" {
		return ErrPDFWorkerUnavailable
	}
	if request.Operation == pdfComposeSigningPageOperation && (request.BodyLength < 1 || request.SigningPageLength < 1 || request.BodyLength > request.Length || request.SigningPageLength != request.Length-request.BodyLength) {
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
				if err == nil {
					err = probeManualOperationsV1(result.Bytes)
				}
				if err == nil {
					response.ManualOperations = pdfManualOperationsCapabilityV1
				}
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
	case pdfManualInspectOperation:
		var geometry PDFManualGeometry
		geometry, err = manualGeometryInProcess(raw)
		if err == nil {
			body, err = json.Marshal(geometry)
			if len(body) > manualMetadataLimit {
				err = ErrPDFManualOverlay
			}
		}
	case pdfManualOverlayOperation:
		var result PDFManualOverlayResult
		result, err = manualOverlayInProcess(raw, request.ManualMetadataLength)
		if err == nil {
			response.Report, response.ManualOverlay = &result.Report, &result.Overlay
			body = result.Bytes
		}
	case pdfManualFragmentOperation:
		var admission PDFManualFragmentAdmission
		admission, err = manualFragmentInProcess(raw, request.ManualMetadataLength)
		if err == nil {
			body, err = json.Marshal(admission)
			if len(body) > manualMetadataLimit {
				err = ErrPDFManualFragment
			}
		}
	case pdfManualLayersOperation:
		var result PDFManualLayersResult
		result, err = manualLayersInProcess(raw, request.ManualMetadataLength)
		if err == nil {
			response.Report, response.ManualLayers = &result.Report, &result.Layers
			body = result.Bytes
		}
	case pdfProviderOverlayOperation:
		var result PDFProviderOverlayResult
		b, s := request.BodyLength, request.SignatureLength
		result, err = providerOverlayInProcess(request.Asset, raw[:b], raw[b:b+s], raw[b+s:], *request.ProviderBindings)
		if err == nil {
			response.Report, response.ProviderOverlay = &result.Report, &result.Overlay
			body = result.Bytes
		}
	case pdfComposeSigningPageOperation:
		var result PDFCompositionResult
		result, err = composeSigningPageInProcess(request.Asset, raw[:request.BodyLength], raw[request.BodyLength:])
		if err == nil {
			response.Report, response.Composition = &result.Report, &result.Composition
			body = result.Bytes
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
		case errors.Is(err, ErrPDFProviderOverlay):
			response.Error = providerOverlayErrorCode(err)
		case errors.Is(err, ErrPDFSigningPageInvalid):
			response.Error = "invalid-signing-page"
		case errors.Is(err, ErrPDFManualLayers):
			response.Error = "invalid-manual-layers"
		case errors.Is(err, ErrPDFManualFragment):
			response.Error = "invalid-manual-fragment"
		case errors.Is(err, ErrPDFManualOverlay):
			response.Error = "invalid-manual-overlay"
		default:
			response.Error = "invalid-pdf"
		}
		body = nil
		response.Pages, response.Report, response.Composition, response.ProviderOverlay, response.ManualOverlay, response.ManualLayers, response.ManualOperations = 0, nil, nil, nil, nil, nil, ""
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
