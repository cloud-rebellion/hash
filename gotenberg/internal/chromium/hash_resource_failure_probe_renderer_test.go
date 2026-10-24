//go:build renderer_e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/gotenberg/internal/ordinarypage"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// A trusted, test-only logger observes the existing strict failure path.
// Network codes use a pinned Chromium main net/base/net_error_list.h snapshot,
// recorded with its BSD license in strict-resource-catalog-188e. This is a
// closed diagnostic taxonomy, not a claim about the installed release source.
// Reports retain closed enums only. A test-only early target listener holds
// at most32 transient request IDs of128bytes, never URLs/bodies, and clears
// them on completion/failure or observer retirement. No IDs enter reports.
type hashClosedResourceObservationV1 struct {
	code                                 int16
	kind                                 uint8
	empty                                bool
	canceled                             bool
	blocked                              uint8
	cors                                 bool
	metadata                             uint8
	requestClass, requestKind, initiator uint8
}

type hashClosedResourceHandlerV1 struct {
	mu                                                                                            sync.Mutex
	records                                                                                       [32]hashClosedResourceObservationV1
	count                                                                                         int
	dropped                                                                                       bool
	requestCapture, attachAttempted, attached, attachUnavailable, observerClosed, requestsDropped bool
	requestTotal                                                                                  int
	pending                                                                                       [32]hashClosedRequestPendingV1
}

type hashClosedRequestPendingV1 struct {
	id                     network.RequestID
	class, kind, initiator uint8
}

func hashClosedRequestClassV1(raw, document string) uint8 {
	switch {
	case strings.HasPrefix(raw, "data:font/woff2;base64,"):
		return 2 // Prefix classification only; not font validation.
	case strings.HasPrefix(raw, "data:"):
		return 3
	case raw == "about:blank":
		return 4
	case strings.HasPrefix(raw, "file:"):
		if len(raw) <= 4096 && len(document) <= 4096 {
			if raw == document {
				return 1
			} // Equality, not ownership authority.
			base, _, fragment := strings.Cut(raw, "#")
			doc, _, _ := strings.Cut(document, "#")
			if fragment && base != "" && base == doc {
				return 10
			}
		}
		return 5
	case strings.HasPrefix(raw, "http:"):
		return 6
	case strings.HasPrefix(raw, "https:"):
		return 7
	case strings.HasPrefix(raw, "blob:"):
		return 8
	case raw == "":
		return 9
	default:
		return 255
	}
}

func hashClosedRequestKindV1(kind network.ResourceType) uint8 {
	switch kind {
	case network.ResourceTypeDocument:
		return 1
	case network.ResourceTypeStylesheet:
		return 2
	case network.ResourceTypeImage:
		return 3
	case network.ResourceTypeMedia:
		return 4
	case network.ResourceTypeFont:
		return 5
	case network.ResourceTypeScript:
		return 6
	case network.ResourceTypeOther:
		return 7
	default:
		return 0
	}
}

func hashClosedInitiatorV1(initiator *network.Initiator) uint8 {
	if initiator == nil {
		return 0
	}
	switch initiator.Type {
	case network.InitiatorTypeParser:
		return 1
	case network.InitiatorTypeScript:
		return 2
	case network.InitiatorTypePreload:
		return 3
	case network.InitiatorTypeSignedExchange:
		return 4
	case network.InitiatorTypePreflight:
		return 5
	case network.InitiatorTypeOther:
		return 6
	default:
		return 255
	}
}

// Install only at the synchronous setup log before chromedp.Run. Registering
// from a later event callback could reacquire target.listenersMu and deadlock.
func (h *hashClosedResourceHandlerV1) installRequestObserver(ctx context.Context) {
	h.mu.Lock()
	if !h.requestCapture || h.attachAttempted || h.observerClosed {
		h.mu.Unlock()
		return
	}
	h.attachAttempted = true
	h.mu.Unlock()
	c := chromedp.FromContext(ctx)
	if c == nil || c.Target != nil {
		h.mu.Lock()
		h.attachUnavailable = true
		h.mu.Unlock()
		return
	}
	chromedp.ListenTarget(ctx, h.observeRequest)
	h.mu.Lock()
	h.attached = true
	h.mu.Unlock()
}

func (h *hashClosedResourceHandlerV1) observeRequest(event any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.requestCapture || h.observerClosed {
		return
	}
	switch e := event.(type) {
	case *network.EventRequestWillBeSent:
		if e == nil || e.Request == nil || len(e.RequestID) == 0 || len(e.RequestID) > 128 {
			h.requestsDropped = true
			return
		}
		slot := -1
		for i := range h.pending {
			if h.pending[i].id == e.RequestID {
				slot = i
				break
			}
		}
		if slot < 0 {
			if h.requestTotal == len(h.pending) {
				h.requestsDropped = true
				return
			}
			for i := range h.pending {
				if h.pending[i].id == "" {
					slot = i
					break
				}
			}
			if slot < 0 {
				h.requestsDropped = true
				return
			}
			h.requestTotal++
		}
		h.pending[slot] = hashClosedRequestPendingV1{
			id:    network.RequestID(strings.Clone(string(e.RequestID))),
			class: hashClosedRequestClassV1(e.Request.URL, e.DocumentURL),
			kind:  hashClosedRequestKindV1(e.Type), initiator: hashClosedInitiatorV1(e.Initiator),
		}
	case *network.EventLoadingFinished:
		if e == nil {
			return
		}
		for i := range h.pending {
			if h.pending[i].id == e.RequestID {
				h.pending[i] = hashClosedRequestPendingV1{}
				break
			}
		}
	}
}

func (h *hashClosedResourceHandlerV1) closeRequestObserver() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observerClosed = true
	for i := range h.pending {
		h.pending[i] = hashClosedRequestPendingV1{}
	}
	for _, entry := range h.pending {
		if entry != (hashClosedRequestPendingV1{}) {
			return false
		}
	}
	return true
}

func hashClosedRequestObserverPrivacyV1(t *testing.T) {
	limited := &hashClosedResourceHandlerV1{requestCapture: true}
	limited.observeRequest(&network.EventRequestWillBeSent{
		RequestID: network.RequestID(strings.Repeat("x", 129)), Request: &network.Request{URL: "PRIVATE-CANARY"},
	})
	if limited.requestTotal != 0 || !limited.requestsDropped {
		t.Fatal("oversized request identifier entered bounded storage")
	}
	for _, entry := range limited.pending {
		if entry != (hashClosedRequestPendingV1{}) {
			t.Fatal("oversized request identifier retained")
		}
	}
	h := &hashClosedResourceHandlerV1{requestCapture: true}
	logger := slog.New(h)
	const id network.RequestID = "PRIVATE-CANARY"
	h.observeRequest(&network.EventRequestWillBeSent{
		RequestID: id, DocumentURL: "file:///tmp/PRIVATE-CANARY/index.html",
		Request:   &network.Request{URL: "file:///tmp/PRIVATE-CANARY/index.html"},
		Type:      network.ResourceTypeOther,
		Initiator: &network.Initiator{Type: network.InitiatorTypeParser, URL: "PRIVATE-CANARY"},
	})
	var resourceErr error
	var resourceMu sync.RWMutex
	recordEventLoadingFailed(context.Background(), logger, eventLoadingFailedOptions{
		failOnResourceLoadingFailed: true, resourceLoadingFailed: &resourceErr,
		resourceLoadingFailedMu: &resourceMu,
	}, &network.EventLoadingFailed{
		RequestID: id, ErrorText: "", Type: network.ResourceTypeOther, BlockedReason: network.BlockedReasonOrigin,
	})
	if resourceErr == nil || h.count != 1 || h.records[0] != (hashClosedResourceObservationV1{
		kind: 7, empty: true, blocked: 4, metadata: 7, requestClass: 1, requestKind: 7, initiator: 1,
	}) {
		t.Fatal("closed correlation or strict failure changed")
	}
	for _, entry := range h.pending {
		if entry.id != "" {
			t.Fatal("failed request identifier retained")
		}
	}
	for i := 0; i < 33; i++ {
		requestID := network.RequestID(strings.Repeat("x", i+1))
		h.observeRequest(&network.EventRequestWillBeSent{
			RequestID: requestID, DocumentURL: "PRIVATE-CANARY",
			Request: &network.Request{URL: "https://PRIVATE-CANARY.invalid/PRIVATE-CANARY"},
		})
		h.observeRequest(&network.EventLoadingFinished{RequestID: requestID})
	}
	if h.requestTotal != 32 || !h.requestsDropped {
		t.Fatal("request lifetime bound changed")
	}
	h.observeRequest(&network.EventRequestWillBeSent{
		RequestID: network.RequestID(strings.Repeat("x", 129)), Request: &network.Request{URL: "PRIVATE-CANARY"},
	})
	if !h.closeRequestObserver() {
		t.Fatal("bounded request retirement failed")
	}
	closing := &hashClosedResourceHandlerV1{requestCapture: true}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			closing.observeRequest(&network.EventRequestWillBeSent{RequestID: "PRIVATE-CANARY", Request: &network.Request{URL: "PRIVATE-CANARY"}})
		}()
	}
	if !closing.closeRequestObserver() {
		t.Fatal("concurrent request retirement failed")
	}
	wg.Wait()
	closing.observeRequest(&network.EventRequestWillBeSent{RequestID: "POST-CLOSE-PRIVATE", Request: &network.Request{URL: "PRIVATE-CANARY"}})
	if !closing.observerClosed || closing.requestsDropped {
		t.Fatal("close witness used a capacity refusal")
	}
	for _, entry := range closing.pending {
		if entry != (hashClosedRequestPendingV1{}) {
			t.Fatal("closed request observer retained a value")
		}
	}
}

func (*hashClosedResourceHandlerV1) Enabled(context.Context, slog.Level) bool { return true }
func (h *hashClosedResourceHandlerV1) WithAttrs([]slog.Attr) slog.Handler     { return h }
func (h *hashClosedResourceHandlerV1) WithGroup(string) slog.Handler          { return h }

func (h *hashClosedResourceHandlerV1) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "no extra HTTP headers" {
		h.installRequestObserver(ctx)
	}
	const prefix = "event EventLoadingFailed fired: "
	if !strings.HasPrefix(r.Message, prefix) {
		return nil
	}
	var observation hashClosedResourceObservationV1
	var requestID network.RequestID
	observation.empty = r.Message == prefix
	switch strings.TrimPrefix(r.Message, prefix) {
	case "net::ERR_IO_PENDING":
		observation.code = -1
	case "net::ERR_FAILED":
		observation.code = -2
	case "net::ERR_ABORTED":
		observation.code = -3
	case "net::ERR_INVALID_ARGUMENT":
		observation.code = -4
	case "net::ERR_INVALID_HANDLE":
		observation.code = -5
	case "net::ERR_FILE_NOT_FOUND":
		observation.code = -6
	case "net::ERR_TIMED_OUT":
		observation.code = -7
	case "net::ERR_FILE_TOO_BIG":
		observation.code = -8
	case "net::ERR_UNEXPECTED":
		observation.code = -9
	case "net::ERR_ACCESS_DENIED":
		observation.code = -10
	case "net::ERR_NOT_IMPLEMENTED":
		observation.code = -11
	case "net::ERR_INSUFFICIENT_RESOURCES":
		observation.code = -12
	case "net::ERR_OUT_OF_MEMORY":
		observation.code = -13
	case "net::ERR_UPLOAD_FILE_CHANGED":
		observation.code = -14
	case "net::ERR_SOCKET_NOT_CONNECTED":
		observation.code = -15
	case "net::ERR_FILE_EXISTS":
		observation.code = -16
	case "net::ERR_FILE_PATH_TOO_LONG":
		observation.code = -17
	case "net::ERR_FILE_NO_SPACE":
		observation.code = -18
	case "net::ERR_FILE_VIRUS_INFECTED":
		observation.code = -19
	case "net::ERR_BLOCKED_BY_CLIENT":
		observation.code = -20
	case "net::ERR_NETWORK_CHANGED":
		observation.code = -21
	case "net::ERR_BLOCKED_BY_ADMINISTRATOR":
		observation.code = -22
	case "net::ERR_SOCKET_IS_CONNECTED":
		observation.code = -23
	case "net::ERR_UPLOAD_STREAM_REWIND_NOT_SUPPORTED":
		observation.code = -25
	case "net::ERR_CONTEXT_SHUT_DOWN":
		observation.code = -26
	case "net::ERR_BLOCKED_BY_RESPONSE":
		observation.code = -27
	case "net::ERR_CLEARTEXT_NOT_PERMITTED":
		observation.code = -29
	case "net::ERR_BLOCKED_BY_CSP":
		observation.code = -30
	case "net::ERR_BLOCKED_BY_ORB":
		observation.code = -32
	case "net::ERR_NETWORK_ACCESS_REVOKED":
		observation.code = -33
	case "net::ERR_BLOCKED_BY_FINGERPRINTING_PROTECTION":
		observation.code = -34
	case "net::ERR_BLOCKED_IN_INCOGNITO_BY_ADMINISTRATOR":
		observation.code = -35
	case "net::ERR_LOCAL_NETWORK_PERMISSION_MISSING":
		observation.code = -36
	case "net::ERR_STRICT_ECH_REQUIRED":
		observation.code = -37
	case "net::ERR_CONNECTION_CLOSED":
		observation.code = -100
	case "net::ERR_CONNECTION_RESET":
		observation.code = -101
	case "net::ERR_CONNECTION_REFUSED":
		observation.code = -102
	case "net::ERR_CONNECTION_ABORTED":
		observation.code = -103
	case "net::ERR_CONNECTION_FAILED":
		observation.code = -104
	case "net::ERR_NAME_NOT_RESOLVED":
		observation.code = -105
	case "net::ERR_INTERNET_DISCONNECTED":
		observation.code = -106
	case "net::ERR_SSL_PROTOCOL_ERROR":
		observation.code = -107
	case "net::ERR_ADDRESS_INVALID":
		observation.code = -108
	case "net::ERR_ADDRESS_UNREACHABLE":
		observation.code = -109
	case "net::ERR_SSL_CLIENT_AUTH_CERT_NEEDED":
		observation.code = -110
	case "net::ERR_TUNNEL_CONNECTION_FAILED":
		observation.code = -111
	case "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH":
		observation.code = -113
	case "net::ERR_SSL_RENEGOTIATION_REQUESTED":
		observation.code = -114
	case "net::ERR_PROXY_AUTH_UNSUPPORTED":
		observation.code = -115
	case "net::ERR_BAD_SSL_CLIENT_AUTH_CERT":
		observation.code = -117
	case "net::ERR_CONNECTION_TIMED_OUT":
		observation.code = -118
	case "net::ERR_HOST_RESOLVER_QUEUE_TOO_LARGE":
		observation.code = -119
	case "net::ERR_SOCKS_CONNECTION_FAILED":
		observation.code = -120
	case "net::ERR_SOCKS_CONNECTION_HOST_UNREACHABLE":
		observation.code = -121
	case "net::ERR_ALPN_NEGOTIATION_FAILED":
		observation.code = -122
	case "net::ERR_SSL_NO_RENEGOTIATION":
		observation.code = -123
	case "net::ERR_WINSOCK_UNEXPECTED_WRITTEN_BYTES":
		observation.code = -124
	case "net::ERR_SSL_DECOMPRESSION_FAILURE_ALERT":
		observation.code = -125
	case "net::ERR_SSL_BAD_RECORD_MAC_ALERT":
		observation.code = -126
	case "net::ERR_PROXY_AUTH_REQUESTED":
		observation.code = -127
	case "net::ERR_PROXY_CONNECTION_FAILED":
		observation.code = -130
	case "net::ERR_MANDATORY_PROXY_CONFIGURATION_FAILED":
		observation.code = -131
	case "net::ERR_PRECONNECT_MAX_SOCKET_LIMIT":
		observation.code = -133
	case "net::ERR_SSL_CLIENT_AUTH_PRIVATE_KEY_ACCESS_DENIED":
		observation.code = -134
	case "net::ERR_SSL_CLIENT_AUTH_CERT_NO_PRIVATE_KEY":
		observation.code = -135
	case "net::ERR_PROXY_CERTIFICATE_INVALID":
		observation.code = -136
	case "net::ERR_NAME_RESOLUTION_FAILED":
		observation.code = -137
	case "net::ERR_NETWORK_ACCESS_DENIED":
		observation.code = -138
	case "net::ERR_TEMPORARILY_THROTTLED":
		observation.code = -139
	case "net::ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED":
		observation.code = -141
	case "net::ERR_MSG_TOO_BIG":
		observation.code = -142
	case "net::ERR_WS_PROTOCOL_ERROR":
		observation.code = -145
	case "net::ERR_ADDRESS_IN_USE":
		observation.code = -147
	case "net::ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN":
		observation.code = -150
	case "net::ERR_CLIENT_AUTH_CERT_TYPE_UNSUPPORTED":
		observation.code = -151
	case "net::ERR_SSL_DECRYPT_ERROR_ALERT":
		observation.code = -153
	case "net::ERR_WS_THROTTLE_QUEUE_TOO_LARGE":
		observation.code = -154
	case "net::ERR_SSL_SERVER_CERT_CHANGED":
		observation.code = -156
	case "net::ERR_SSL_UNRECOGNIZED_NAME_ALERT":
		observation.code = -159
	case "net::ERR_SOCKET_SET_RECEIVE_BUFFER_SIZE_ERROR":
		observation.code = -160
	case "net::ERR_SOCKET_SET_SEND_BUFFER_SIZE_ERROR":
		observation.code = -161
	case "net::ERR_SOCKET_RECEIVE_BUFFER_SIZE_UNCHANGEABLE":
		observation.code = -162
	case "net::ERR_SOCKET_SEND_BUFFER_SIZE_UNCHANGEABLE":
		observation.code = -163
	case "net::ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT":
		observation.code = -164
	case "net::ERR_ICANN_NAME_COLLISION":
		observation.code = -166
	case "net::ERR_SSL_SERVER_CERT_BAD_FORMAT":
		observation.code = -167
	case "net::ERR_CT_STH_PARSING_FAILED":
		observation.code = -168
	case "net::ERR_CT_STH_INCOMPLETE":
		observation.code = -169
	case "net::ERR_UNABLE_TO_REUSE_CONNECTION_FOR_PROXY_AUTH":
		observation.code = -170
	case "net::ERR_CT_CONSISTENCY_PROOF_PARSING_FAILED":
		observation.code = -171
	case "net::ERR_SSL_OBSOLETE_CIPHER":
		observation.code = -172
	case "net::ERR_WS_UPGRADE":
		observation.code = -173
	case "net::ERR_READ_IF_READY_NOT_IMPLEMENTED":
		observation.code = -174
	case "net::ERR_NO_BUFFER_SPACE":
		observation.code = -176
	case "net::ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS":
		observation.code = -177
	case "net::ERR_EARLY_DATA_REJECTED":
		observation.code = -178
	case "net::ERR_WRONG_VERSION_ON_EARLY_DATA":
		observation.code = -179
	case "net::ERR_TLS13_DOWNGRADE_DETECTED":
		observation.code = -180
	case "net::ERR_SSL_KEY_USAGE_INCOMPATIBLE":
		observation.code = -181
	case "net::ERR_INVALID_ECH_CONFIG_LIST":
		observation.code = -182
	case "net::ERR_ECH_NOT_NEGOTIATED":
		observation.code = -183
	case "net::ERR_ECH_FALLBACK_CERTIFICATE_INVALID":
		observation.code = -184
	case "net::ERR_PROXY_UNABLE_TO_CONNECT_TO_DESTINATION":
		observation.code = -186
	case "net::ERR_PROXY_DELEGATE_CANCELED_CONNECT_REQUEST":
		observation.code = -187
	case "net::ERR_PROXY_DELEGATE_CANCELED_CONNECT_RESPONSE":
		observation.code = -188
	case "net::ERR_CONTROL_MSG_TOO_BIG":
		observation.code = -189
	case "net::ERR_MULTICAST_NOT_ALLOWED":
		observation.code = -190
	case "net::ERR_CERT_COMMON_NAME_INVALID":
		observation.code = -200
	case "net::ERR_CERT_DATE_INVALID":
		observation.code = -201
	case "net::ERR_CERT_AUTHORITY_INVALID":
		observation.code = -202
	case "net::ERR_CERT_CONTAINS_ERRORS":
		observation.code = -203
	case "net::ERR_CERT_NO_REVOCATION_MECHANISM":
		observation.code = -204
	case "net::ERR_CERT_UNABLE_TO_CHECK_REVOCATION":
		observation.code = -205
	case "net::ERR_CERT_REVOKED":
		observation.code = -206
	case "net::ERR_CERT_INVALID":
		observation.code = -207
	case "net::ERR_CERT_WEAK_SIGNATURE_ALGORITHM":
		observation.code = -208
	case "net::ERR_CERT_NON_UNIQUE_NAME":
		observation.code = -210
	case "net::ERR_CERT_WEAK_KEY":
		observation.code = -211
	case "net::ERR_CERT_NAME_CONSTRAINT_VIOLATION":
		observation.code = -212
	case "net::ERR_CERT_VALIDITY_TOO_LONG":
		observation.code = -213
	case "net::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED":
		observation.code = -214
	case "net::ERR_CERT_KNOWN_INTERCEPTION_BLOCKED":
		observation.code = -217
	case "net::ERR_CERT_SELF_SIGNED_LOCAL_NETWORK":
		observation.code = -219
	case "net::ERR_CERT_END":
		observation.code = -220
	case "net::ERR_INVALID_URL":
		observation.code = -300
	case "net::ERR_DISALLOWED_URL_SCHEME":
		observation.code = -301
	case "net::ERR_UNKNOWN_URL_SCHEME":
		observation.code = -302
	case "net::ERR_INVALID_REDIRECT":
		observation.code = -303
	case "net::ERR_TOO_MANY_REDIRECTS":
		observation.code = -310
	case "net::ERR_UNSAFE_REDIRECT":
		observation.code = -311
	case "net::ERR_UNSAFE_PORT":
		observation.code = -312
	case "net::ERR_INVALID_RESPONSE":
		observation.code = -320
	case "net::ERR_INVALID_CHUNKED_ENCODING":
		observation.code = -321
	case "net::ERR_METHOD_NOT_SUPPORTED":
		observation.code = -322
	case "net::ERR_UNEXPECTED_PROXY_AUTH":
		observation.code = -323
	case "net::ERR_EMPTY_RESPONSE":
		observation.code = -324
	case "net::ERR_RESPONSE_HEADERS_TOO_BIG":
		observation.code = -325
	case "net::ERR_PAC_SCRIPT_FAILED":
		observation.code = -327
	case "net::ERR_REQUEST_RANGE_NOT_SATISFIABLE":
		observation.code = -328
	case "net::ERR_MALFORMED_IDENTITY":
		observation.code = -329
	case "net::ERR_CONTENT_DECODING_FAILED":
		observation.code = -330
	case "net::ERR_NETWORK_IO_SUSPENDED":
		observation.code = -331
	case "net::ERR_NO_SUPPORTED_PROXIES":
		observation.code = -336
	case "net::ERR_HTTP2_PROTOCOL_ERROR":
		observation.code = -337
	case "net::ERR_INVALID_AUTH_CREDENTIALS":
		observation.code = -338
	case "net::ERR_UNSUPPORTED_AUTH_SCHEME":
		observation.code = -339
	case "net::ERR_ENCODING_DETECTION_FAILED":
		observation.code = -340
	case "net::ERR_MISSING_AUTH_CREDENTIALS":
		observation.code = -341
	case "net::ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS":
		observation.code = -342
	case "net::ERR_MISCONFIGURED_AUTH_ENVIRONMENT":
		observation.code = -343
	case "net::ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS":
		observation.code = -344
	case "net::ERR_RESPONSE_BODY_TOO_BIG_TO_DRAIN":
		observation.code = -345
	case "net::ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_LENGTH":
		observation.code = -346
	case "net::ERR_INCOMPLETE_HTTP2_HEADERS":
		observation.code = -347
	case "net::ERR_PAC_NOT_IN_DHCP":
		observation.code = -348
	case "net::ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_DISPOSITION":
		observation.code = -349
	case "net::ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION":
		observation.code = -350
	case "net::ERR_HTTP2_SERVER_REFUSED_STREAM":
		observation.code = -351
	case "net::ERR_HTTP2_PING_FAILED":
		observation.code = -352
	case "net::ERR_CONTENT_LENGTH_MISMATCH":
		observation.code = -354
	case "net::ERR_INCOMPLETE_CHUNKED_ENCODING":
		observation.code = -355
	case "net::ERR_QUIC_PROTOCOL_ERROR":
		observation.code = -356
	case "net::ERR_RESPONSE_HEADERS_TRUNCATED":
		observation.code = -357
	case "net::ERR_QUIC_HANDSHAKE_FAILED":
		observation.code = -358
	case "net::ERR_HTTP2_INADEQUATE_TRANSPORT_SECURITY":
		observation.code = -360
	case "net::ERR_HTTP2_FLOW_CONTROL_ERROR":
		observation.code = -361
	case "net::ERR_HTTP2_FRAME_SIZE_ERROR":
		observation.code = -362
	case "net::ERR_HTTP2_COMPRESSION_ERROR":
		observation.code = -363
	case "net::ERR_PROXY_AUTH_REQUESTED_WITH_NO_CONNECTION":
		observation.code = -364
	case "net::ERR_HTTP_1_1_REQUIRED":
		observation.code = -365
	case "net::ERR_PROXY_HTTP_1_1_REQUIRED":
		observation.code = -366
	case "net::ERR_PAC_SCRIPT_TERMINATED":
		observation.code = -367
	case "net::ERR_INVALID_HTTP_RESPONSE":
		observation.code = -370
	case "net::ERR_CONTENT_DECODING_INIT_FAILED":
		observation.code = -371
	case "net::ERR_HTTP2_RST_STREAM_NO_ERROR_RECEIVED":
		observation.code = -372
	case "net::ERR_TOO_MANY_RETRIES":
		observation.code = -375
	case "net::ERR_HTTP2_STREAM_CLOSED":
		observation.code = -376
	case "net::ERR_HTTP_RESPONSE_CODE_FAILURE":
		observation.code = -379
	case "net::ERR_QUIC_CERT_ROOT_NOT_KNOWN":
		observation.code = -380
	case "net::ERR_QUIC_GOAWAY_REQUEST_CAN_BE_RETRIED":
		observation.code = -381
	case "net::ERR_TOO_MANY_ACCEPT_CH_RESTARTS":
		observation.code = -382
	case "net::ERR_INCONSISTENT_IP_ADDRESS_SPACE":
		observation.code = -383
	case "net::ERR_CACHED_IP_ADDRESS_SPACE_BLOCKED_BY_LOCAL_NETWORK_ACCESS_POLICY":
		observation.code = -384
	case "net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS":
		observation.code = -385
	case "net::ERR_ZSTD_WINDOW_SIZE_TOO_BIG":
		observation.code = -386
	case "net::ERR_DICTIONARY_LOAD_FAILED":
		observation.code = -387
	case "net::ERR_UNEXPECTED_CONTENT_DICTIONARY_HEADER":
		observation.code = -388
	case "net::ERR_CACHE_MISS":
		observation.code = -400
	case "net::ERR_CACHE_READ_FAILURE":
		observation.code = -401
	case "net::ERR_CACHE_WRITE_FAILURE":
		observation.code = -402
	case "net::ERR_CACHE_OPERATION_NOT_SUPPORTED":
		observation.code = -403
	case "net::ERR_CACHE_OPEN_FAILURE":
		observation.code = -404
	case "net::ERR_CACHE_CREATE_FAILURE":
		observation.code = -405
	case "net::ERR_CACHE_RACE":
		observation.code = -406
	case "net::ERR_CACHE_CHECKSUM_READ_FAILURE":
		observation.code = -407
	case "net::ERR_CACHE_CHECKSUM_MISMATCH":
		observation.code = -408
	case "net::ERR_CACHE_LOCK_TIMEOUT":
		observation.code = -409
	case "net::ERR_CACHE_AUTH_FAILURE_AFTER_READ":
		observation.code = -410
	case "net::ERR_CACHE_ENTRY_NOT_SUITABLE":
		observation.code = -411
	case "net::ERR_CACHE_DOOM_FAILURE":
		observation.code = -412
	case "net::ERR_CACHE_OPEN_OR_CREATE_FAILURE":
		observation.code = -413
	case "net::ERR_CACHE_COMPRESSION_FAILURE":
		observation.code = -414
	case "net::ERR_INSECURE_RESPONSE":
		observation.code = -501
	case "net::ERR_NO_PRIVATE_KEY_FOR_CERT":
		observation.code = -502
	case "net::ERR_ADD_USER_CERT_FAILED":
		observation.code = -503
	case "net::ERR_INVALID_SIGNED_EXCHANGE":
		observation.code = -504
	case "net::ERR_INVALID_WEB_BUNDLE":
		observation.code = -505
	case "net::ERR_TRUST_TOKEN_OPERATION_FAILED":
		observation.code = -506
	case "net::ERR_TRUST_TOKEN_OPERATION_SUCCESS_WITHOUT_SENDING_REQUEST":
		observation.code = -507
	case "net::ERR_HTTPENGINE_PROVIDER_IN_USE":
		observation.code = -508
	case "net::ERR_PKCS12_IMPORT_BAD_PASSWORD":
		observation.code = -701
	case "net::ERR_PKCS12_IMPORT_FAILED":
		observation.code = -702
	case "net::ERR_IMPORT_CA_CERT_NOT_CA":
		observation.code = -703
	case "net::ERR_IMPORT_CERT_ALREADY_EXISTS":
		observation.code = -704
	case "net::ERR_IMPORT_CA_CERT_FAILED":
		observation.code = -705
	case "net::ERR_IMPORT_SERVER_CERT_FAILED":
		observation.code = -706
	case "net::ERR_PKCS12_IMPORT_INVALID_MAC":
		observation.code = -707
	case "net::ERR_PKCS12_IMPORT_INVALID_FILE":
		observation.code = -708
	case "net::ERR_PKCS12_IMPORT_UNSUPPORTED":
		observation.code = -709
	case "net::ERR_KEY_GENERATION_FAILED":
		observation.code = -710
	case "net::ERR_PRIVATE_KEY_EXPORT_FAILED":
		observation.code = -712
	case "net::ERR_SELF_SIGNED_CERT_GENERATION_FAILED":
		observation.code = -713
	case "net::ERR_CERT_DATABASE_CHANGED":
		observation.code = -714
	case "net::ERR_CERT_VERIFIER_CHANGED":
		observation.code = -716
	case "net::ERR_DNS_MALFORMED_RESPONSE":
		observation.code = -800
	case "net::ERR_DNS_SERVER_REQUIRES_TCP":
		observation.code = -801
	case "net::ERR_DNS_TIMED_OUT":
		observation.code = -803
	case "net::ERR_DNS_CACHE_MISS":
		observation.code = -804
	case "net::ERR_DNS_SEARCH_EMPTY":
		observation.code = -805
	case "net::ERR_DNS_SORT_ERROR":
		observation.code = -806
	case "net::ERR_DNS_SECURE_RESOLVER_HOSTNAME_RESOLUTION_FAILED":
		observation.code = -808
	case "net::ERR_DNS_NAME_HTTPS_ONLY":
		observation.code = -809
	case "net::ERR_DNS_REQUEST_CANCELLED":
		observation.code = -810
	case "net::ERR_DNS_NO_MATCHING_SUPPORTED_ALPN":
		observation.code = -811
	case "net::ERR_DNS_SECURE_PROBE_RECORD_INVALID":
		observation.code = -814
	case "net::ERR_DNS_CACHE_INVALIDATION_IN_PROGRESS":
		observation.code = -815
	case "net::ERR_DNS_FORMAT_ERROR":
		observation.code = -816
	case "net::ERR_DNS_SERVER_FAILURE":
		observation.code = -817
	case "net::ERR_DNS_NOT_IMPLEMENTED":
		observation.code = -818
	case "net::ERR_DNS_REFUSED":
		observation.code = -819
	case "net::ERR_DNS_OTHER_FAILURE":
		observation.code = -820
	case "net::ERR_DNS_DIRECT_ONLY":
		observation.code = -821
	case "net::ERR_BLOB_INVALID_CONSTRUCTION_ARGUMENTS":
		observation.code = -900
	case "net::ERR_BLOB_OUT_OF_MEMORY":
		observation.code = -901
	case "net::ERR_BLOB_FILE_WRITE_FAILED":
		observation.code = -902
	case "net::ERR_BLOB_SOURCE_DIED_IN_TRANSIT":
		observation.code = -903
	case "net::ERR_BLOB_DEREFERENCED_WHILE_BUILDING":
		observation.code = -904
	case "net::ERR_BLOB_REFERENCED_BLOB_BROKEN":
		observation.code = -905
	case "net::ERR_BLOB_REFERENCED_FILE_UNAVAILABLE":
		observation.code = -906
	}
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "request_id":
			if a.Value.Kind() == slog.KindString && len(a.Value.String()) <= 128 {
				requestID = network.RequestID(a.Value.String())
			}
		case "hash_loading_canceled":
			if a.Value.Kind() == slog.KindBool {
				observation.canceled = a.Value.Bool()
				observation.metadata |= 1
			}
		case "hash_loading_cors_present":
			if a.Value.Kind() == slog.KindBool {
				observation.cors = a.Value.Bool()
				observation.metadata |= 2
			}
		case "hash_loading_blocked_reason":
			if a.Value.Kind() == slog.KindInt64 {
				value := a.Value.Int64()
				if (value >= 0 && value <= 16) || value == 255 {
					observation.blocked = uint8(value)
					observation.metadata |= 4
				}
			}
		}
		if a.Key != "resource_type" || a.Value.Kind() != slog.KindString {
			return true
		}
		switch a.Value.String() {
		case "Document":
			observation.kind = 1
		case "Stylesheet":
			observation.kind = 2
		case "Image":
			observation.kind = 3
		case "Media":
			observation.kind = 4
		case "Font":
			observation.kind = 5
		case "Script":
			observation.kind = 6
		case "Other":
			observation.kind = 7
		default:
			observation.kind = 0
		}
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.requestCapture && !h.observerClosed && requestID != "" {
		for i := range h.pending {
			if h.pending[i].id == requestID {
				observation.requestClass, observation.requestKind, observation.initiator = h.pending[i].class, h.pending[i].kind, h.pending[i].initiator
				h.pending[i] = hashClosedRequestPendingV1{}
				break
			}
		}
	}
	if h.count == len(h.records) {
		h.dropped = true
		return nil
	}
	h.records[h.count] = observation
	h.count++
	return nil
}

func TestHashGenuineClosedResourceObservationPrivacyV1(t *testing.T) {
	hashClosedRequestObserverPrivacyV1(t)
	h := &hashClosedResourceHandlerV1{}
	logger := slog.New(h).With("request_id", "PRIVATE-CANARY").WithGroup("PRIVATE-CANARY")
	logger.Debug("unrelated PRIVATE-CANARY", "resource_type", "PRIVATE-CANARY")
	logger.Debug("event EventLoadingFailed fired: ", "request_id", "PRIVATE-CANARY", "resource_type", "PRIVATE-CANARY")
	logger.Debug("event EventLoadingFailed fired: PRIVATE-CANARY", "request_id", "PRIVATE-CANARY", "resource_type", "PRIVATE-CANARY")
	logger.Debug("event EventLoadingFailed fired: net::ERR_ABORTED", "request_id", "PRIVATE-CANARY", "resource_type", "Other")
	if h.count != 3 || h.records[0] != (hashClosedResourceObservationV1{empty: true}) || h.records[1] != (hashClosedResourceObservationV1{}) || h.records[2] != (hashClosedResourceObservationV1{code: -3, kind: 7}) {
		t.Fatal("closed classification or unrelated/private-data suppression changed")
	}
	// Exercise the actual production event recorder, including absent/unknown
	// reasons and both booleans. Private CORS fields never enter the handler.
	reasons := []struct {
		reason network.BlockedReason
		code   uint8
	}{
		{"", 0},
		{network.BlockedReasonOther, 1},
		{network.BlockedReasonCsp, 2},
		{network.BlockedReasonMixedContent, 3},
		{network.BlockedReasonOrigin, 4},
		{network.BlockedReasonInspector, 5},
		{network.BlockedReasonIntegrity, 6},
		{network.BlockedReasonSubresourceFilter, 7},
		{network.BlockedReasonContentType, 8},
		{network.BlockedReasonCoepFrameResourceNeedsCoepHeader, 9},
		{network.BlockedReasonCoopSandboxedIframeCannotNavigateToCoopPage, 10},
		{network.BlockedReasonCorpNotSameOrigin, 11},
		{network.BlockedReasonCorpNotSameOriginAfterDefaultedToSameOriginByCoep, 12},
		{network.BlockedReasonCorpNotSameOriginAfterDefaultedToSameOriginByDip, 13},
		{network.BlockedReasonCorpNotSameOriginAfterDefaultedToSameOriginByCoepAndDip, 14},
		{network.BlockedReasonCorpNotSameSite, 15},
		{network.BlockedReasonSriMessageSignatureMismatch, 16},
		{network.BlockedReason("PRIVATE-CANARY"), 255},
	}
	for i, test := range reasons {
		var resourceErr error
		var resourceMu sync.RWMutex
		var cors *network.CorsErrorStatus
		if i%2 != 0 {
			cors = &network.CorsErrorStatus{FailedParameter: "PRIVATE-CANARY"}
		}
		recordEventLoadingFailed(context.Background(), logger, eventLoadingFailedOptions{
			failOnResourceLoadingFailed: true, resourceLoadingFailed: &resourceErr,
			resourceLoadingFailedMu: &resourceMu,
		}, &network.EventLoadingFailed{
			ErrorText: "PRIVATE-CANARY", Type: network.ResourceTypeOther,
			Canceled: i%2 == 0, BlockedReason: test.reason, CorsErrorStatus: cors,
		})
		want := hashClosedResourceObservationV1{kind: 7, canceled: i%2 == 0, blocked: test.code, cors: cors != nil, metadata: 7}
		if resourceErr == nil || h.records[3+i] != want {
			t.Fatal("actual recorder closed metadata or strict refusal changed")
		}
	}
	if h.count != 3+len(reasons) {
		t.Fatal("closed metadata witnesses changed finite record count")
	}
	concurrentStart := h.count
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Debug("event EventLoadingFailed fired: net::ERR_BLOCKED_BY_CSP", "resource_type", "Font")
		}()
	}
	wg.Wait()
	if h.count != len(h.records) || !h.dropped {
		t.Fatal("finite concurrent observation bound changed")
	}
	for _, record := range h.records[concurrentStart:] {
		if record != (hashClosedResourceObservationV1{code: -30, kind: 5}) {
			t.Fatal("concurrent fixed observation changed")
		}
	}
}

// Only closed diagnostic attributes are added to the production event log;
// all original thirteen scenarios and failure policy remain unchanged.
// This additional probe invokes the same genuine ordinary producer
// with its original strict resource policy and twenty-second request budget.
// A producer refusal remains a failed test; observations never waive it.
func TestHashGenuineStrictResourceFailureDiagnosticV1(t *testing.T) {
	mod, browser := hashPublicFixtureModule(t)
	initial := hashBrowserTargets(t, browser)
	baseline, err := hashTargetSnapshot(browser)
	if err != nil {
		t.Fatal("genuine original target baseline unavailable")
	}
	font := hashOrdinaryGenuineFont(t)
	handler := &hashClosedResourceHandlerV1{requestCapture: true}
	logger := slog.New(handler)
	plan := hashOrdinaryPlan()
	plan.Fields = []ordinarypage.FieldV1{
		hashOrdinaryField(1, "text", "  Á O'Neill <script> ${name} \" & Å B  \r\nNext\nThird\rFourth  ", "10", "5", "80", "18"),
		hashOrdinaryField(2, "text", strings.Repeat("Wrap Å & <b> Á  ", 30), "10", "30", "28", "55"),
	}
	plan = hashOrdinaryBindPlan(t, plan)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pack, producerErr := mod.prepareHashOrdinaryPDF(ctx, logger, plan, font)
	retired := handler.closeRequestObserver()
	handler.mu.Lock()
	count, dropped, records := handler.count, handler.dropped, handler.records
	attached, unavailable, total, requestDropped := handler.attached, handler.attachUnavailable, handler.requestTotal, handler.requestsDropped
	handler.mu.Unlock()
	t.Logf("closed-resource-observations count=%d dropped=%t", count, dropped)
	t.Logf("closed-request-observer attached=%t unavailable=%t total=%d dropped=%t retired=%t", attached, unavailable, total, requestDropped, retired)
	for i := 0; i < count; i++ {
		t.Logf("closed-resource-observation code=%d kind=%d empty=%t canceled=%t blocked=%d cors=%t metadata=%d request_class=%d request_kind=%d initiator=%d", records[i].code, records[i].kind, records[i].empty, records[i].canceled, records[i].blocked, records[i].cors, records[i].metadata, records[i].requestClass, records[i].requestKind, records[i].initiator)
	}
	hashOrdinaryAssertJoined(t, mod, browser, initial, baseline)
	if producerErr != nil || pack == nil {
		t.Fatal("genuine original strict ordinary producer refused; closed facts recorded")
	}
	if _, err := ordinarypage.DecodeWithContextV1(ctx, pack.Bytes(), plan); err != nil {
		t.Fatal("genuine original package decoding unavailable")
	}
}
