// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package chromium

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var hashStartupTraceCommands = [...]struct {
	method  string
	session bool
}{
	{"Target.setDiscoverTargets", false}, {"Target.attachToTarget", false},
	{"Runtime.enable", true}, {"Runtime.evaluate", true}, {"Log.enable", true},
	{"Network.enable", true}, {"Inspector.enable", true}, {"Page.enable", true},
	{"DOM.enable", true}, {"CSS.enable", true}, {"Target.setDiscoverTargets", true},
	{"Target.setAutoAttach", true}, {"Page.setLifecycleEventsEnabled", true},
}

const hashStartupSensitiveCanary = "private-document-recipient-session-canary"

func hashStartupJSON(t *testing.T, v any) []byte {
	t.Helper()
	p, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func hashStartupRequestBytes(t *testing.T, i int, id int64) []byte {
	c := hashStartupTraceCommands[i]
	v := map[string]any{"id": id, "method": c.method, "params": map[string]any{"private": hashStartupSensitiveCanary}}
	if c.session {
		v["sessionId"] = hashStartupSensitiveCanary
	}
	return hashStartupJSON(t, v)
}
func hashStartupReplyBytes(t *testing.T, i int, id int64, failed bool) []byte {
	v := map[string]any{"id": id}
	if failed {
		v["error"] = map[string]any{"message": hashStartupSensitiveCanary}
	} else {
		v["result"] = map[string]any{"private": hashStartupSensitiveCanary}
	}
	if hashStartupTraceCommands[i].session {
		v["sessionId"] = hashStartupSensitiveCanary
	}
	return hashStartupJSON(t, v)
}
func hashStartupCount(s hashStartupSnapshot, stage hashStartupStage, command hashStartupCommand) int {
	n := 0
	for _, r := range s.Records[:s.Count] {
		if r.Stage == stage && (command == hashStartupNoCommand || r.Command == command) {
			n++
		}
	}
	return n
}
func hashStartupCompleteTrace(t *testing.T, o *hashStartupObserver) {
	t.Helper()
	o.commandPrepared()
	o.childOutput([]byte("DevTools li"))
	o.childOutput([]byte("stening on ws://" + hashStartupSensitiveCanary + "\n"))
	for i := range hashStartupTraceCommands {
		o.protocol("-> %s", hashStartupRequestBytes(t, i, int64(i+101)))
		o.protocol("<- %s", hashStartupReplyBytes(t, i, int64(i+101), false))
	}
}
func TestHashStartupObservationFullTraceAndFrozenPrivacy(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	o := newHashStartupObserver(logger)
	hashStartupCompleteTrace(t, o)
	o.finish(true, false)
	if logs.Len() != 0 {
		t.Fatal("passive callbacks or completion performed diagnostic I/O")
	}
	s := o.snapshot()
	if !s.Finished || !s.RunJoined || s.Failed || s.Flags != 0 || s.Count != 31 || s.Frames != 26 {
		t.Fatalf("unexpected complete trace: %+v", s)
	}
	for i := range hashStartupTraceCommands {
		if hashStartupCount(s, hashStartupRequest, hashStartupCommand(i)) != 1 || hashStartupCount(s, hashStartupReply, hashStartupCommand(i)) != 1 {
			t.Fatalf("missing distinct command %d", i)
		}
	}
	for i, r := range s.Records[:s.Count] {
		if int(r.Sequence) != i+1 || r.ElapsedMS < 0 {
			t.Fatal("noncanonical observation order")
		}
	}
	o.mu.Lock()
	slots := o.slots
	o.mu.Unlock()
	if slots != [hashStartupCommandCount]hashStartupSlot{} {
		t.Fatal("finished observer retained correlation IDs")
	}
	o.protocol("-> %s", hashStartupRequestBytes(t, 0, 999))
	o.childOutput([]byte(hashStartupSensitiveCanary))
	o.finish(true, true)
	if !reflect.DeepEqual(s, o.snapshot()) {
		t.Fatal("late callbacks or duplicate completion changed frozen observation")
	}
	o.reportOutcome(false) // a nil Run result does not prove the outer deadline check succeeded
	text := logs.String()
	if strings.Contains(text, hashStartupSensitiveCanary) || strings.Contains(fmt.Sprint(s), hashStartupSensitiveCanary) || strings.Contains(text, "ws://") {
		t.Fatal("startup diagnostics retained payload or identifier")
	}
	if !strings.Contains(text, "\"started\":false") || !strings.Contains(text, "\"initial_run_joined\":true") || !strings.Contains(text, "\"initial_run_failed\":false") {
		t.Fatal("outer outcome was conflated with Run completion: ", text)
	}
	before := logs.Len()
	o.reportOutcome(true)
	if logs.Len() != before {
		t.Fatal("duplicate report exceeded one bounded snapshot")
	}
}
func TestHashStartupObservationAnchoredSplitMarkerAndDiscardedGap(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chunks []string
		want   bool
	}{
		{"split", []string{"DevTools li", "stening on ws://private\n"}, true},
		{"line prefix required", []string{"noise DevTools listening on ws://private\n"}, false},
		{"new line", []string{"noise\nDevTools listening on ws://private\n"}, true},
		{"failed prefix", []string{"DDevTools listening on ws://private\n"}, false},
		{"CRLF", []string{"noise\r\nDevTools listening on ws://private\n"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newHashStartupObserver(nil)
			for _, p := range tc.chunks {
				o.childOutput([]byte(p))
			}
			if got := hashStartupCount(o.snapshot(), hashStartupDevTools, hashStartupNoCommand) == 1; got != tc.want {
				t.Fatal("marker classification", got)
			}
		})
	}
	o := newHashStartupObserver(nil)
	prefix := "DevTools li"
	first := bytes.Repeat([]byte("x"), hashStartupFrameBytes-len(prefix)-1)
	first = append(first, '\n')
	first = append(first, []byte(prefix)...)
	first = append(first, []byte("discarded-gap")...)
	o.childOutput(first)
	o.childOutput([]byte("stening on ws://private\n"))
	s := o.snapshot()
	if s.Flags&hashStartupOutputLimited == 0 || hashStartupCount(s, hashStartupDevTools, hashStartupNoCommand) != 0 {
		t.Fatal("invented marker across unobserved output")
	}
	o.childOutput([]byte("DevTools listening on ws://private\n"))
	if hashStartupCount(o.snapshot(), hashStartupDevTools, hashStartupNoCommand) != 1 {
		t.Fatal("observed newline did not restore line prefix tracking")
	}
}
func TestHashStartupObservationRefusesFalseReplies(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		flag hashStartupFlags
	}{
		{"malformed", []byte("{"), hashStartupMalformed}, {"nonobject", []byte("[]"), hashStartupMalformed},
		{"duplicate id", []byte("{\"id\":7,\"id\":8,\"result\":{}}"), hashStartupMalformed},
		{"escaped duplicate id", []byte("{\"id\":7,\"\\u0069d\":8,\"result\":{}}"), hashStartupMalformed},
		{"duplicate result", []byte("{\"id\":7,\"result\":{},\"result\":{}}"), hashStartupMalformed},
		{"both outcomes", []byte("{\"id\":7,\"result\":{},\"error\":{}}"), hashStartupMalformed},
		{"no outcome", []byte("{\"id\":7}"), hashStartupMalformed},
		{"scalar result", []byte("{\"id\":7,\"result\":true}"), hashStartupMalformed},
		{"scalar error", []byte("{\"id\":7,\"error\":\"private\"}"), hashStartupMalformed},
		{"overflow", []byte("{\"id\":9223372036854775808,\"result\":{}}"), hashStartupMalformed},
		{"negative", []byte("{\"id\":-1,\"result\":{}}"), hashStartupMalformed},
		{"string id", []byte("{\"id\":\"7\",\"result\":{}}"), hashStartupMalformed},
		{"id on event", []byte("{\"id\":7,\"method\":\"Target.targetCreated\"}"), hashStartupMalformed},
		{"unknown id", []byte("{\"id\":8,\"result\":{}}"), hashStartupCorrelation},
		{"wrong scope", []byte("{\"id\":7,\"sessionId\":\"private\",\"result\":{}}"), hashStartupCorrelation},
		{"invalid UTF8", bytes.ReplaceAll([]byte("{\"id\":7,\"result\":{\"private\":\"X\"}}"), []byte("X"), []byte{0xff}), hashStartupMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := newHashStartupObserver(nil)
			o.protocol("-> %s", hashStartupRequestBytes(t, 0, 7))
			o.protocol("<- %s", tc.raw)
			s := o.snapshot()
			if s.Flags&tc.flag == 0 || hashStartupCount(s, hashStartupReply, hashStartupNoCommand) != 0 || s.RunJoined {
				t.Fatalf("false positive reply: %+v", s)
			}
		})
	}
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint("valid reply error=", failed), func(t *testing.T) {
			o := newHashStartupObserver(nil)
			o.protocol("-> %s", hashStartupRequestBytes(t, 0, 7))
			o.protocol("<- %s", hashStartupReplyBytes(t, 0, 7, failed))
			s := o.snapshot()
			if s.Flags != 0 || hashStartupCount(s, hashStartupReply, hashStartupDiscoverBrowser) != 1 || s.Records[s.Count-1].Failed != failed || s.RunJoined {
				t.Fatal("protocol reply was not distinguished from Run completion")
			}
			o.protocol("<- %s", hashStartupReplyBytes(t, 0, 7, false))
			if hashStartupCount(o.snapshot(), hashStartupReply, hashStartupNoCommand) != 1 || o.snapshot().Flags&hashStartupCorrelation == 0 {
				t.Fatal("duplicate reply published twice")
			}
		})
	}
	o := newHashStartupObserver(nil)
	o.protocol("-> %s", hashStartupRequestBytes(t, 0, 7))
	o.protocol("-> %s", hashStartupRequestBytes(t, 1, 7))
	o.protocol("<- %s", hashStartupReplyBytes(t, 0, 7, false))
	s := o.snapshot()
	if s.Flags&hashStartupCorrelation == 0 || hashStartupCount(s, hashStartupReply, hashStartupAttach) != 0 || hashStartupCount(s, hashStartupRequest, hashStartupNoCommand) != 1 {
		t.Fatal("duplicate ID overwrote correlation slot")
	}
	o = newHashStartupObserver(nil)
	o.protocol("-> %s", hashStartupRequestBytes(t, 3, 7))
	o.protocol("<- %s", hashStartupJSON(t, map[string]any{"id": 7, "sessionId": hashStartupSensitiveCanary, "result": map[string]any{"exceptionDetails": map[string]any{"text": hashStartupSensitiveCanary}}}))
	if o.snapshot().RunJoined || o.snapshot().Records[o.snapshot().Count-1].Failed {
		t.Fatal("protocol result was treated as semantic JavaScript success or Run completion")
	}
}
func TestHashStartupObservationBoundsAndBorrowedBuffers(t *testing.T) {
	o := newHashStartupObserver(nil)
	raw := hashStartupRequestBytes(t, 0, 7)
	before := bytes.Clone(raw)
	o.protocol("-> %s", raw)
	if !bytes.Equal(raw, before) {
		t.Fatal("observer modified borrowed protocol input")
	}
	for i := range raw {
		raw[i] = 'x'
	}
	o.protocol("<- %s", hashStartupReplyBytes(t, 0, 7, false))
	if hashStartupCount(o.snapshot(), hashStartupReply, hashStartupDiscoverBrowser) != 1 {
		t.Fatal("observer retained borrowed input for correlation")
	}
	o = newHashStartupObserver(nil)
	o.protocol("-> %s", bytes.Repeat([]byte("x"), hashStartupFrameBytes+1))
	if o.snapshot().Flags&hashStartupOversize == 0 || hashStartupCount(o.snapshot(), hashStartupRequest, hashStartupNoCommand) != 0 {
		t.Fatal("oversized frame parsed")
	}
	event := hashStartupJSON(t, map[string]any{"method": "Target.targetCreated", "params": map[string]any{}})
	for range hashStartupFrameLimit + 10 {
		o.protocol("<- %s", event)
	}
	s := o.snapshot()
	if s.Frames != hashStartupFrameLimit || s.Flags&hashStartupFramesLimited == 0 {
		t.Fatal("protocol frame budget not retained")
	}
	o = newHashStartupObserver(nil)
	for range 20 {
		o.childOutput(bytes.Repeat([]byte("x"), hashStartupFrameBytes+1))
	}
	s = o.snapshot()
	if s.OutputBytes != hashStartupOutputLimit || s.Flags&hashStartupOutputLimited == 0 {
		t.Fatal("output budget exceeded")
	}
	o = newHashStartupObserver(nil)
	o.protocol("<- %s", []byte("{"))
	hashStartupCompleteTrace(t, o)
	o.finish(true, false)
	s = o.snapshot()
	if s.Count != hashStartupRecordLimit || s.Flags&hashStartupMalformed == 0 || !s.RunJoined {
		t.Fatal("fixed record budget displaced original completion")
	}
	o = newHashStartupObserver(nil)
	o.protocol("ping control ignored", hashStartupSensitiveCanary)
	if o.snapshot().Count != 0 {
		t.Fatal("unrelated debug format was parsed")
	}
	o.protocol("-> %s", hashStartupSensitiveCanary)
	if o.snapshot().Flags&hashStartupHookShape == 0 {
		t.Fatal("wrong hook argument shape was parsed")
	}
}
func TestHashStartupObservationHeldRunSetupAndOriginalError(t *testing.T) {
	o := newHashStartupObserver(nil)
	o.commandPrepared()
	o.childOutput([]byte("DevTools listening on ws://private\n"))
	o.protocol("-> %s", hashStartupRequestBytes(t, 0, 7))
	s := o.snapshot()
	if s.Finished || s.RunJoined || hashStartupCount(s, hashStartupReply, hashStartupNoCommand) != 0 {
		t.Fatal("held response classified ready")
	}
	sentinel := errors.New("original controlled startup failure")
	startup := &hashBrowserStartup{done: make(chan struct{}), err: sentinel, observation: o}
	o.finish(true, true)
	close(startup.done)
	if err := hashWaitForStartup(context.Background(), startup, time.Now().Add(time.Second)); err != sentinel {
		t.Fatal("observer changed original startup error identity")
	}
	o = newHashStartupObserver(nil)
	o.finish(false, true)
	s = o.snapshot()
	if !s.Finished || s.RunJoined || !s.Failed || s.Records[0].Stage != hashStartupSetupFailed {
		t.Fatal("setup failure invented a Run")
	}
	(*hashStartupObserver)(nil).commandPrepared()
	(*hashStartupObserver)(nil).childOutput(nil)
	(*hashStartupObserver)(nil).protocol("-> %s", nil)
	(*hashStartupObserver)(nil).finish(false, true)
	(*hashStartupObserver)(nil).reportOutcome(false)
}
func TestHashStartupObservationConcurrentAttemptsAndFreeze(t *testing.T) {
	a, b := newHashStartupObserver(nil), newHashStartupObserver(nil)
	a.protocol("-> %s", hashStartupRequestBytes(t, 0, 7))
	b.protocol("<- %s", hashStartupReplyBytes(t, 0, 7, false))
	if hashStartupCount(b.snapshot(), hashStartupReply, hashStartupNoCommand) != 0 || hashStartupCount(a.snapshot(), hashStartupReply, hashStartupNoCommand) != 0 {
		t.Fatal("attempts correlated with each other")
	}
	request, reply := hashStartupRequestBytes(t, 0, 7), hashStartupReplyBytes(t, 0, 7, false)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				a.commandPrepared()
				a.childOutput([]byte("DevTools listening on ws://private\n"))
				a.protocol("-> %s", request)
				a.protocol("<- %s", reply)
				_ = a.snapshot()
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); a.finish(true, false) }()
	wg.Wait()
	a.finish(true, false)
	s := a.snapshot()
	if !s.Finished || s.Count > hashStartupRecordLimit || s.Frames > hashStartupFrameLimit {
		t.Fatal("concurrent observation escaped fixed budget")
	}
	a.protocol("-> %s", request)
	a.childOutput(reply)
	if !reflect.DeepEqual(s, a.snapshot()) {
		t.Fatal("late callback mutated frozen attempt")
	}
}
func TestHashStartupObservationCaptureAndLegacyDebugForwarding(t *testing.T) {
	var logs bytes.Buffer
	o := newHashStartupObserver(slog.New(slog.NewJSONHandler(&logs, nil)))
	s := &hashBrowserStartup{observation: o}
	cmd := exec.Command("controlled-unstarted-executable", hashStartupSensitiveCanary)
	s.captureCommand(cmd)
	if s.command != cmd || cmd.Process != nil || cmd.Args[1] != hashStartupSensitiveCanary || logs.Len() != 0 {
		t.Fatal("command preparation observation started or altered command")
	}
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	debug := &debugLogger{logger: logger, startup: o}
	raw := []byte("legacy-output")
	n, err := debug.Write(raw)
	debug.Printf("legacy-format-%d", 7)
	if n != len(raw) || err != nil || !strings.Contains(logs.String(), "legacy-output") || !strings.Contains(logs.String(), "legacy-format-7") || strings.Contains(logs.String(), "chromium startup observation") {
		t.Fatal("passive observer changed original debug forwarding")
	}
}
func hashAssertStartupOutcomes(t *testing.T, raw []byte, count int, runJoined bool) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	found := 0
	for {
		var record map[string]any
		err := decoder.Decode(&record)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if record["msg"] != "chromium startup outcome" {
			continue
		}
		found++
		if record["started"] != false || record["initial_run_joined"] != runJoined || record["initial_run_failed"] != runJoined || record["setup_failed"] != !runJoined || record["observation_finished"] != true {
			t.Fatalf("unfaithful original failure outcome: %+v", record)
		}
	}
	if found != count {
		t.Fatalf("got %d startup outcome records, want %d", found, count)
	}
}
