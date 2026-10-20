// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// logShipMinDefault is the default floor for shipping a log line to Flare.
// warn+ keeps volume sane (info/debug stay local stderr); override with
// FLARE_LOG_LEVEL=debug|info|warn|error (or off to disable).
const logShipMinDefault = slog.LevelWarn

const (
	logShipBuffer    = 512             // records buffered before drop-on-full
	logShipBatch     = 50              // flush at this many records
	logShipFlushEach = 3 * time.Second // or at least this often
	logShipMaxPerMin = 300             // hard per-minute cap: bounds any storm or loop
	logShipMaxAttrs  = 8 << 10         // drop a record's attrs beyond this many bytes
)

var logShipOnce sync.Once

// installLogShipper wraps the current default slog handler so warn+ records are
// also shipped to Flare's native logs endpoint, giving the estate a real logs
// pillar without a new dependency. Best-effort: the app's own stderr logging is
// untouched, a full buffer drops rather than blocks, and a per-minute cap bounds
// any storm. Called once from InitFlare after sentry.Init; no-op when FLARE_DSN
// is unset/unparseable or FLARE_LOG_LEVEL=off.
var installedLogShipper *logShipper

func installLogShipper(service string) {
	installLogShipperWithContext(context.Background(), service, "development", "development")
}
func installLogShipperWithContext(ctx context.Context, service, release, environment string) *logShipper {
	logShipOnce.Do(func() { installedLogShipper = installLogShipperOnce(ctx, service, release, environment) })
	return installedLogShipper
}
func installLogShipperOnce(ctx context.Context, service, release, environment string) *logShipper {
	if strings.EqualFold(os.Getenv("FLARE_LOG_LEVEL"), "off") || service == "flare" {
		return nil
	}
	base, key, ok := parseDSNForLogs(os.Getenv("FLARE_DSN"))
	if !ok {
		return nil
	}
	owned, cancel := context.WithCancel(ctx)
	sh := &logShipper{endpoint: base, key: key, service: service, release: release, environment: environment, ch: make(chan nativeLogLine, logShipBuffer), client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ctx: owned, cancel: cancel, done: make(chan struct{})}
	// A concrete stderr fallback is essential: wrapping slog.defaultHandler and
	// SetDefault would recurse through the standard logger and deadlock.
	next := slog.Default().Handler()
	if fmt.Sprintf("%T", next) == "*slog.defaultHandler" {
		next = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	slog.SetDefault(slog.New(&flareSlogHandler{next: next, shipper: sh, minLvl: logShipLevel()}))
	go sh.run()
	return sh
}

// sensitiveLogKeyParts are case-insensitive substrings whose attribute values
// are redacted before shipping a log record to the shared Flare logs store.
// Bare "key" is intentionally excluded (too broad: keyboard, monkey, ...).
var sensitiveLogKeyParts = []string{
	"password", "passwd", "secret", "token", "authorization", "bearer",
	"cookie", "credential", "api_key", "apikey", "access_key", "accesskey",
	"private_key", "privatekey", "vault_key", "new_value", "jwt", "session_id", "dsn",
}

// piiLogKeyParts are substrings whose values are signer/recipient PII. Shipping
// them to the shared multi-tenant Flare logs store is a GDPR data egress, so
// they are redacted the same way secrets are. Unambiguous substrings only.
var piiLogKeyParts = []string{
	"email", "recipient", "personnummer", "user_agent", "useragent",
	"signer_ip", "signer_ua", "phone",
}

// piiLogKeyExact are short, ambiguous keys matched only exactly (substring would
// false-hit "total"/"sector" for "to", "recipient" already covered, etc.).
var piiLogKeyExact = map[string]bool{"to": true, "ip": true}

func isSensitiveLogKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitiveLogKeyParts {
		if strings.Contains(k, s) {
			return true
		}
	}
	for _, s := range piiLogKeyParts {
		if strings.Contains(k, s) {
			return true
		}
	}
	return piiLogKeyExact[k]
}

func logShipLevel() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("FLARE_LOG_LEVEL"))) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "error":
		return slog.LevelError
	case "warn", "warning":
		return slog.LevelWarn
	}
	return logShipMinDefault
}

// parseDSNForLogs turns a Sentry-style DSN ({scheme}://{key}@{host}/{dsnID})
// into the native-logs endpoint URL and the ingest key.
func parseDSNForLogs(dsn string) (endpoint, key string, ok bool) {
	public, _, valid := publicDSN(dsn, "development")
	if !valid {
		return "", "", false
	}
	u, err := url.Parse(public)
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	id := parts[len(parts)-1]
	base := ""
	if len(parts) > 1 {
		base = "/" + strings.Join(parts[:len(parts)-1], "/")
	}
	return u.Scheme + "://" + u.Host + base + "/api/" + id + "/logs", u.User.Username(), true
}

type nativeLogLine struct {
	Severity   string          `json:"severity"`
	Body       string          `json:"body"`
	Attributes json.RawMessage `json:"attributes,omitempty"`
	TraceID    string          `json:"trace_id,omitempty"`
	Timestamp  string          `json:"timestamp"`
}

type logShipper struct {
	endpoint    string
	key         string
	service     string
	release     string
	environment string
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	closeCtx    context.Context
	failed      atomic.Int64
	rejected    atomic.Int64
	ch          chan nativeLogLine
	dropped     atomic.Int64
	client      *http.Client

	mu          sync.Mutex
	windowStart time.Time
	windowCount int
}

// allow admits at most logShipMaxPerMin records per fixed minute window,
// bounding any warn storm or self-referential loop before it does work.
func (s *logShipper) allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.windowStart) >= time.Minute {
		s.windowStart = now
		s.windowCount = 0
	}
	if s.windowCount >= logShipMaxPerMin {
		return false
	}
	s.windowCount++
	return true
}

// enqueue is non-blocking: a full buffer drops the line so logging never stalls
// the app on a slow or unreachable Flare.
func (s *logShipper) enqueue(l nativeLogLine) {
	if s.ctx != nil && s.ctx.Err() != nil {
		s.dropped.Add(1)
		return
	}
	select {
	case s.ch <- l:
	default:
		s.dropped.Add(1)
	}
}
func (s *logShipper) beginClose(ctx context.Context) {
	s.mu.Lock()
	if s.closeCtx == nil {
		s.closeCtx = ctx
	}
	s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}
func (s *logShipper) run() {
	defer close(s.done)
	ticker := time.NewTicker(logShipFlushEach)
	defer ticker.Stop()
	batch := make([]nativeLogLine, 0, logShipBatch)
	flush := func(ctx context.Context) {
		if len(batch) == 0 {
			return
		}
		count := len(batch)
		body, err := json.Marshal(batch)
		batch = batch[:0]
		if err != nil {
			s.failed.Add(int64(count))
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
		if err != nil {
			s.failed.Add(int64(count))
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Flare-Key", s.key)
		resp, err := s.client.Do(req)
		if err != nil {
			s.failed.Add(int64(count))
			return
		}
		defer resp.Body.Close()
		var result struct {
			Accepted int `json:"accepted"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 || err != nil || result.Accepted < 0 || result.Accepted > count {
			s.failed.Add(int64(count))
			return
		}
		if result.Accepted < count {
			s.rejected.Add(int64(count - result.Accepted))
		}
	}
	for {
		select {
		case <-s.ctx.Done():
			s.mu.Lock()
			cleanup := s.closeCtx
			s.mu.Unlock()
			var cancel context.CancelFunc
			if cleanup == nil {
				cleanup, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
			}
			// A producer sees ctx cancellation before enqueue. Drain at most the
			// original fixed queue capacity, using ONE finite cleanup budget.
			for n := 0; n < logShipBuffer; n++ {
				select {
				case line := <-s.ch:
					batch = append(batch, line)
					if len(batch) >= logShipBatch {
						flush(cleanup)
					}
				default:
					flush(cleanup)
					return
				}
			}
			flush(cleanup)
			return
		case line := <-s.ch:
			batch = append(batch, line)
			if len(batch) >= logShipBatch {
				flush(s.ctx)
			}
		case <-ticker.C:
			flush(s.ctx)
		}
	}
}

// flareSlogHandler tees warn+ records to the log shipper while passing every
// record through to the wrapped handler (stderr).
type flareSlogHandler struct {
	next    slog.Handler
	shipper *logShipper
	minLvl  slog.Level
	attrs   []slog.Attr
	groups  []string
}

func (h *flareSlogHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *flareSlogHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= h.minLvl && h.shipper != nil {
		h.ship(ctx, r)
	}
	return h.next.Handle(ctx, r)
}

func (h *flareSlogHandler) ship(ctx context.Context, r slog.Record) {
	if !h.shipper.allow() {
		h.shipper.dropped.Add(1)
		return
	}
	operation := logOperation(r.Message)
	attributes := map[string]any{"service": h.shipper.service, "release": h.shipper.release, "environment": h.shipper.environment, "operation": operation, "category": "operational_log"}
	traceID := ""
	// Raw message/Any maps/structs/errors are deliberately NOT serialized.
	// Only fixed enum values and bounded numeric primitives cross this boundary.
	add := func(a slog.Attr) {
		// Keep the key scrub before the fixed allowlist, including future additions.
		key := a.Key
		if isSensitiveLogKey(key) {
			return
		}
		if a.Key == "operation" && a.Value.Kind() == slog.KindString && validOperation(Operation(a.Value.String())) {
			attributes["operation"] = a.Value.String()
			return
		}
		if a.Key == "outcome" && a.Value.Kind() == slog.KindString && validOutcome(Outcome(a.Value.String())) {
			attributes["outcome"] = a.Value.String()
			return
		}
		if a.Key == "trace_id" && a.Value.Kind() == slog.KindString && validHexID(a.Value.String(), 32) {
			traceID = a.Value.String()
			return
		}
		switch a.Key {
		case "count", "status", "duration_ms", "attempts":
			if a.Value.Kind() == slog.KindInt64 {
				value := a.Value.Int64()
				if value >= 0 && value <= 86400000 {
					attributes[a.Key] = value
				}
			}
		}
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(func(a slog.Attr) bool { add(a); return true })
	if ctx != nil {
		if span := contextSpan(ctx); span != nil {
			traceID = span.TraceID.String()
		}
	}
	raw, _ := json.Marshal(attributes)
	h.shipper.enqueue(nativeLogLine{Severity: strings.ToLower(r.Level.String()), Body: "Hash operational log", Attributes: raw, TraceID: traceID, Timestamp: r.Time.UTC().Format(time.RFC3339)})
}
func logOperation(message string) string {
	for _, item := range []struct{ prefix, operation string }{{"reminders:", "reminder"}, {"reminder:", "reminder"}, {"email_dispatch:", "email_dispatch"}, {"finalize_retry:", "evidence"}, {"document finalization failed", "evidence"}, {"webhook", "webhook"}, {"mcp ", "mcp"}, {"health check failed", "health"}, {"internal error serving request", "http"}, {"http handler panicked", "http"}, {"send_sealing:", "signing"}} {
		if strings.HasPrefix(message, item.prefix) {
			return item.operation
		}
	}
	return "application"
}
func validHexID(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (h *flareSlogHandler) WithAttrs(as []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(as))
	merged = append(merged, h.attrs...)
	merged = append(merged, as...)
	return &flareSlogHandler{next: h.next.WithAttrs(as), shipper: h.shipper, minLvl: h.minLvl, attrs: merged, groups: h.groups}
}

func (h *flareSlogHandler) WithGroup(name string) slog.Handler {
	groups := append(append([]string{}, h.groups...), name)
	return &flareSlogHandler{next: h.next.WithGroup(name), shipper: h.shipper, minLvl: h.minLvl, attrs: h.attrs, groups: groups}
}

// The value-level egress scrub.
//
// isSensitiveLogKey above gates on the attribute KEY, and that is not enough on
// its own. The key used everywhere in Go error logging is "error", which is not
// and must not be a sensitive key, yet the value under it is routinely a
// *url.Error whose exported URL field carries the endpoint and its ?token=
// query. So the single most common line in the estate,
//
//	slog.Error("webhook delivery failed", "error", err)
//
// shipped credentials to the shared Flare logs store in cleartext. That store is
// a different trust boundary from the process that logged them. The same applies
// to the record's own message, which is free text an author formats by hand.
//
// This is deliberately self-contained: logship.go is a vendored copy in a dozen
// separate Go modules with no shared package between them, and a fix that
// depends on one project's helper is a fix the other eleven cannot take.
var (
	scrubLogPEM = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
	// Userinfo in a URL: scheme://user:password@host
	scrubLogURLCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/\s:@"]+:[^/\s@"]+@`)
	// A credential-bearing query parameter, the shape *url.Error hands over.
	scrubLogQuery = regexp.MustCompile(`(?i)([?&](?:token|key|api[_-]?key|apikey|secret|password|passwd|pwd|sig|signature|access[_-]?token|refresh[_-]?token|auth|session|code)=)[^&\s"']+`)
	// Bearer / Basic / Token authorization values.
	scrubLogBearer = regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._\-+/=]{8,}`)
	// key=value / key: value assignments with a credential-looking name.
	scrubLogAssign = regexp.MustCompile(`(?i)\b(token|api[_-]?key|apikey|secret|password|passwd|pwd|access[_-]?token|refresh[_-]?token|authorization)\b(\s*[:=]\s*)["']?[^\s"',;&)}]+`)
)

// scrubLogText redacts credential shapes from one free-text value.
//
// Redaction, not destruction: the host and path of a failing URL survive, so an
// operator can still tell which call broke. Only the secret is replaced.
func scrubLogText(s string) string {
	if s == "" {
		return s
	}
	s = redactCredentialPath(s)
	s = scrubLogPEM.ReplaceAllString(s, "[private-key]")
	s = scrubLogURLCreds.ReplaceAllString(s, "${1}[redacted]@")
	s = scrubLogQuery.ReplaceAllString(s, "${1}[secret]")
	s = scrubLogBearer.ReplaceAllString(s, "${1} [secret]")
	s = scrubLogAssign.ReplaceAllString(s, "${1}${2}[secret]")
	return s
}

// scrubLogJSON walks a marshalled attribute document and applies scrubLogText to
// STRING LEAVES ONLY, then re-marshals.
//
// Never run the text scrub over serialized JSON directly. The assignment rule
// matches `"password":"x"` shapes across the quoting, and a text rewrite of a
// serialized document can leave it unparseable; walking the structure cannot.
// Numbers are decoded as literal text, because decoding into float64 silently
// rounds every integer above 2^53, so a 19-digit id would reach the operator as
// 1.7123456789012346e+18.
func scrubLogJSON(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		// Not JSON. Scrub as text and return a JSON string, still valid to embed.
		if out, merr := json.Marshal(scrubLogText(string(raw))); merr == nil {
			return out
		}
		return []byte(`"[unserializable]"`)
	}
	out, err := json.Marshal(scrubLogValue(v))
	if err != nil {
		// Fail closed: dropping the attrs beats shipping an unscrubbed document.
		return []byte(`{"_scrub_error":"redacted"}`)
	}
	return out
}

// scrubLogValue rewrites string leaves. Object KEYS are left alone: they are
// attribute names, isSensitiveLogKey already handled the sensitive ones, and
// rewriting a key would change what the operator is searching on.
func scrubLogValue(v any) any {
	switch t := v.(type) {
	case string:
		return scrubLogText(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = scrubLogValue(val)
		}
		return out
	case []any:
		for i := range t {
			t[i] = scrubLogValue(t[i])
		}
		return t
	default:
		return v
	}
}
