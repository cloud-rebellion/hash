// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package chromium

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	hashStartupFrameBytes     = 4096
	hashStartupFrameLimit     = 128
	hashStartupOutputLimit    = 64 * 1024
	hashStartupRecordLimit    = 32
	hashStartupDevToolsMarker = "DevTools listening on "
)

type hashStartupCommand uint8

const (
	hashStartupDiscoverBrowser hashStartupCommand = iota
	hashStartupAttach
	hashStartupRuntime
	hashStartupEvaluate
	hashStartupLog
	hashStartupNetwork
	hashStartupInspector
	hashStartupPage
	hashStartupDOM
	hashStartupCSS
	hashStartupDiscoverSession
	hashStartupAutoAttach
	hashStartupLifecycle
	hashStartupCommandCount
	hashStartupNoCommand = hashStartupCommandCount
)

func (c hashStartupCommand) label() string {
	switch c {
	case hashStartupDiscoverBrowser:
		return "browser_discovery"
	case hashStartupAttach:
		return "target_attachment"
	case hashStartupRuntime:
		return "runtime_enable"
	case hashStartupEvaluate:
		return "runtime_evaluate"
	case hashStartupLog:
		return "log_enable"
	case hashStartupNetwork:
		return "network_enable"
	case hashStartupInspector:
		return "inspector_enable"
	case hashStartupPage:
		return "page_enable"
	case hashStartupDOM:
		return "dom_enable"
	case hashStartupCSS:
		return "css_enable"
	case hashStartupDiscoverSession:
		return "session_discovery"
	case hashStartupAutoAttach:
		return "session_auto_attach"
	case hashStartupLifecycle:
		return "page_lifecycle"
	default:
		return "none"
	}
}
func hashStartupCommandFor(method string, session bool) hashStartupCommand {
	if method == "Target.setDiscoverTargets" {
		if session {
			return hashStartupDiscoverSession
		}
		return hashStartupDiscoverBrowser
	}
	if !session {
		if method == "Target.attachToTarget" {
			return hashStartupAttach
		}
		return hashStartupNoCommand
	}
	switch method {
	case "Runtime.enable":
		return hashStartupRuntime
	case "Runtime.evaluate":
		return hashStartupEvaluate
	case "Log.enable":
		return hashStartupLog
	case "Network.enable":
		return hashStartupNetwork
	case "Inspector.enable":
		return hashStartupInspector
	case "Page.enable":
		return hashStartupPage
	case "DOM.enable":
		return hashStartupDOM
	case "CSS.enable":
		return hashStartupCSS
	case "Target.setAutoAttach":
		return hashStartupAutoAttach
	case "Page.setLifecycleEventsEnabled":
		return hashStartupLifecycle
	default:
		return hashStartupNoCommand
	}
}

type hashStartupStage uint8

const (
	hashStartupCommandPrepared hashStartupStage = iota
	hashStartupChildOutput
	hashStartupDevTools
	hashStartupCDPDial
	hashStartupRequest
	hashStartupReply
	hashStartupRunJoined
	hashStartupSetupFailed
	hashStartupIncomplete
)

func (s hashStartupStage) label() string {
	switch s {
	case hashStartupCommandPrepared:
		return "command_prepared"
	case hashStartupChildOutput:
		return "child_output_seen"
	case hashStartupDevTools:
		return "devtools_announcement_seen"
	case hashStartupCDPDial:
		return "cdp_dial_succeeded"
	case hashStartupRequest:
		return "request_observed"
	case hashStartupReply:
		return "reply_observed"
	case hashStartupRunJoined:
		return "initial_run_joined"
	case hashStartupSetupFailed:
		return "setup_failed"
	default:
		return "observation_incomplete"
	}
}

type hashStartupFlags uint16

const (
	hashStartupOversize hashStartupFlags = 1 << iota
	hashStartupMalformed
	hashStartupUntracked
	hashStartupCorrelation
	hashStartupFramesLimited
	hashStartupOutputLimited
	hashStartupRecordsLimited
	hashStartupHookShape
)

type hashStartupRecord struct {
	Stage     hashStartupStage
	Command   hashStartupCommand
	Sequence  uint8
	ElapsedMS int64
	Failed    bool
	Flags     hashStartupFlags
	Frames    uint16
}

type hashStartupSnapshot struct {
	Records                     [hashStartupRecordLimit]hashStartupRecord
	Count                       uint8
	Frames                      uint16
	OutputBytes                 uint32
	Flags                       hashStartupFlags
	Finished, RunJoined, Failed bool
}

type hashStartupSlot struct {
	id                 int64
	requested, replied bool
}

// Passive, attempt-owned diagnostics. No browser handles, request data, raw
// output, CDP payloads or session identifiers survive a callback. Correlation IDs
// stay in thirteen fixed slots and are cleared when the original Run joins.
// This object has no authority over admission, deadlines, cancellation or Ready.
type hashStartupObserver struct {
	mu                                                                   sync.Mutex
	logger                                                               *slog.Logger
	started                                                              time.Time
	state                                                                hashStartupSnapshot
	slots                                                                [hashStartupCommandCount]hashStartupSlot
	prepared, outputSeen, markerSeen, dialSeen, incompleteSeen, reported bool
	markerEligible                                                       bool
	markerPosition                                                       uint8
}

func newHashStartupObserver(logger *slog.Logger) *hashStartupObserver {
	return &hashStartupObserver{logger: logger, started: time.Now(), markerEligible: true}
}

func (o *hashStartupObserver) appendLocked(stage hashStartupStage, command hashStartupCommand, failed bool) {
	if int(o.state.Count) >= len(o.state.Records) {
		o.state.Flags |= hashStartupRecordsLimited
		return
	}
	record := hashStartupRecord{Stage: stage, Command: command, Sequence: o.state.Count + 1, ElapsedMS: time.Since(o.started).Milliseconds(), Failed: failed, Flags: o.state.Flags, Frames: o.state.Frames}
	o.state.Records[o.state.Count] = record
	o.state.Count++
}
func (o *hashStartupObserver) flagLocked(flag hashStartupFlags) {
	o.state.Flags |= flag
	if !o.incompleteSeen {
		o.incompleteSeen = true
		o.appendLocked(hashStartupIncomplete, hashStartupNoCommand, false)
	}
}
func (o *hashStartupObserver) commandPrepared() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if !o.state.Finished && !o.prepared {
		o.prepared = true
		o.appendLocked(hashStartupCommandPrepared, hashStartupNoCommand, false)
	}
	o.mu.Unlock()
}
func (o *hashStartupObserver) childOutput(p []byte) {
	if o == nil || len(p) == 0 {
		return
	}
	o.mu.Lock()
	if o.state.Finished {
		o.mu.Unlock()
		return
	}
	if !o.outputSeen {
		o.outputSeen = true
		o.appendLocked(hashStartupChildOutput, hashStartupNoCommand, false)
	}
	// Byte-at-a-time prefix state supports split writes without retaining a line.
	remaining := hashStartupOutputLimit - int(o.state.OutputBytes)
	n := min(len(p), hashStartupFrameBytes, remaining)
	if n < len(p) {
		o.flagLocked(hashStartupOutputLimited)
	}
	for _, b := range p[:n] {
		if o.markerSeen {
			break
		}
		if b == '\n' {
			o.markerEligible = true
			o.markerPosition = 0
			continue
		}
		if !o.markerEligible {
			continue
		}
		if b == hashStartupDevToolsMarker[o.markerPosition] {
			o.markerPosition++
		} else {
			o.markerEligible = false
			o.markerPosition = 0
		}
		if int(o.markerPosition) == len(hashStartupDevToolsMarker) {
			o.markerSeen = true
			o.appendLocked(hashStartupDevTools, hashStartupNoCommand, false)
		}
	}
	if n < len(p) && !o.markerSeen {
		o.markerPosition = 0
		o.markerEligible = false
	}
	o.state.OutputBytes += uint32(n)
	o.mu.Unlock()
}

type hashStartupFrame struct {
	id                                               int64
	command                                          hashStartupCommand
	hasID, hasMethod, result, protocolError, session bool
}

// The caller bounds bytes before this parser. Selected duplicate fields and
// non-object result/error envelopes are incomplete observations, never replies.
// RawMessage values are callback-local bounded scratch; none enters observer state.
func hashParseStartupFrame(raw []byte) (hashStartupFrame, bool) {
	var f hashStartupFrame
	f.command = hashStartupNoCommand
	if len(raw) > hashStartupFrameBytes || !utf8.Valid(raw) || !json.Valid(raw) {
		return f, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return f, false
	}
	var seen uint8
	var method string
	var session bool
	fields := 0
	for d.More() {
		fields++
		if fields > 16 {
			return f, false
		}
		key, e := d.Token()
		if e != nil {
			return f, false
		}
		name, ok := key.(string)
		if !ok {
			return f, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return f, false
		}
		var bit uint8
		switch name {
		case "id":
			bit = 1
		case "method":
			bit = 2
		case "sessionId":
			bit = 4
		case "result":
			bit = 8
		case "error":
			bit = 16
		}
		if bit != 0 && seen&bit != 0 {
			return f, false
		}
		seen |= bit
		switch name {
		case "id":
			if json.Unmarshal(value, &f.id) != nil || f.id <= 0 {
				return f, false
			}
			f.hasID = true
		case "method":
			if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &method) != nil || method == "" {
				return f, false
			}
			f.hasMethod = true
		case "sessionId":
			var id string
			if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &id) != nil {
				return f, false
			}
			session = id != ""
		case "result":
			if len(value) == 0 || value[0] != '{' {
				return f, false
			}
			f.result = true
		case "error":
			if len(value) == 0 || value[0] != '{' {
				return f, false
			}
			f.protocolError = true
		}
	}
	if t, e = d.Token(); e != nil || t != json.Delim('}') {
		return f, false
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return f, false
	}
	f.session = session
	f.command = hashStartupCommandFor(method, session)
	return f, true
}
func (o *hashStartupObserver) protocol(format string, args ...any) {
	if o == nil {
		return
	}
	outbound := format == "-> %s"
	if !outbound && format != "<- %s" {
		return
	}
	o.mu.Lock()
	if o.state.Finished {
		o.mu.Unlock()
		return
	}
	if len(args) != 1 {
		o.flagLocked(hashStartupHookShape)
		o.mu.Unlock()
		return
	}
	raw, ok := args[0].([]byte)
	if !ok {
		o.flagLocked(hashStartupHookShape)
		o.mu.Unlock()
		return
	}
	if !o.dialSeen {
		o.dialSeen = true
		o.appendLocked(hashStartupCDPDial, hashStartupNoCommand, false)
	}
	if o.state.Frames >= hashStartupFrameLimit {
		o.flagLocked(hashStartupFramesLimited)
		o.mu.Unlock()
		return
	}
	o.state.Frames++
	if len(raw) > hashStartupFrameBytes {
		o.flagLocked(hashStartupOversize)
		o.mu.Unlock()
		return
	}
	frame, valid := hashParseStartupFrame(raw)
	if !valid {
		o.flagLocked(hashStartupMalformed)
	} else if outbound {
		if !frame.hasID || !frame.hasMethod || frame.result || frame.protocolError {
			o.flagLocked(hashStartupMalformed)
		} else if frame.command == hashStartupNoCommand {
			o.flagLocked(hashStartupUntracked)
		} else {
			collision := o.slots[frame.command].requested
			for _, slot := range o.slots {
				if slot.requested && slot.id == frame.id {
					collision = true
				}
			}
			if collision {
				o.flagLocked(hashStartupCorrelation)
			} else {
				o.slots[frame.command] = hashStartupSlot{id: frame.id, requested: true}
				o.appendLocked(hashStartupRequest, frame.command, false)
			}
		}
	} else if frame.hasMethod {
		if frame.hasID || frame.result || frame.protocolError {
			o.flagLocked(hashStartupMalformed)
		}
	} else if !frame.hasID || frame.result == frame.protocolError {
		o.flagLocked(hashStartupMalformed)
	} else {
		command := hashStartupNoCommand
		for i, slot := range o.slots {
			if slot.requested && slot.id == frame.id && !slot.replied {
				command = hashStartupCommand(i)
				break
			}
		}
		if command == hashStartupNoCommand || frame.session != (command != hashStartupDiscoverBrowser && command != hashStartupAttach) {
			o.flagLocked(hashStartupCorrelation)
		} else {
			o.slots[command].replied = true
			o.appendLocked(hashStartupReply, command, frame.protocolError)
		}
	}
	o.mu.Unlock()
}
func (o *hashStartupObserver) finish(runJoined, failed bool) {
	if o == nil {
		return
	}
	o.mu.Lock()
	if !o.state.Finished {
		o.state.Finished = true
		o.state.RunJoined = runJoined
		o.state.Failed = failed
		o.slots = [hashStartupCommandCount]hashStartupSlot{}
		stage := hashStartupRunJoined
		if !runJoined {
			stage = hashStartupSetupFailed
		}
		o.appendLocked(stage, hashStartupNoCommand, failed)
	}
	o.mu.Unlock()
}
func (o *hashStartupObserver) snapshot() hashStartupSnapshot {
	if o == nil {
		return hashStartupSnapshot{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.state
}

// A nil Run result can still lose the outer deadline/lifetime check. This
// separate bounded outcome never changes the frozen Run observation or Ready.
func (o *hashStartupObserver) reportOutcome(started bool) {
	if o == nil || o.logger == nil {
		return
	}
	o.mu.Lock()
	if o.reported {
		o.mu.Unlock()
		return
	}
	o.reported = true
	s := o.state
	o.mu.Unlock()
	// No logging occurs in child/protocol hooks or before original Run publication.
	// The owning Start calls this only after state publication or retirement.
	for i := uint8(0); i < s.Count; i++ {
		r := s.Records[i]
		o.logger.Info("chromium startup observation", "stage", r.Stage.label(), "command", r.Command.label(), "sequence", r.Sequence, "elapsed_ms", r.ElapsedMS, "failed", r.Failed, "observation_flags", uint16(r.Flags), "examined_frames", r.Frames)
	}
	o.logger.Info("chromium startup outcome", "started", started, "initial_run_joined", s.RunJoined, "initial_run_failed", s.RunJoined && s.Failed, "setup_failed", s.Finished && !s.RunJoined && s.Failed, "observation_finished", s.Finished, "observation_flags", uint16(s.Flags), "examined_frames", s.Frames, "records", s.Count)
}
