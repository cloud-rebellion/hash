// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

func taskObservationFixture186() fstest.MapFS {
	return fstest.MapFS{
		"sys/fs/cgroup/pids.current": {Data: []byte("61\n")},
		"sys/fs/cgroup/pids.max":     {Data: []byte("128\n")},
		"sys/fs/cgroup/pids.peak":    {Data: []byte("128\n")},
		"sys/fs/cgroup/pids.events":  {Data: []byte("max 2\n")},
		"sys/fs/cgroup/cgroup.procs": {Data: []byte("1\n2\n3\n4\n")},
		"proc/1/stat":                {Data: taskObservationStat186(1, "tini", 1, "S")},
		"proc/2/stat":                {Data: taskObservationStat186(2, "gotenberg", 8, "S")},
		"proc/3/stat":                {Data: taskObservationStat186(3, "chromium", 30, "S")},
		"proc/4/stat":                {Data: taskObservationStat186(4, "chromium", 22, "S")},
		"proc/3/cmdline":             {Data: []byte("/private/secret-profile/chrome\x00--user-data-dir=secret-token\x00https://secret.example/document\x00")},
		"proc/4/cmdline":             {Data: []byte("/usr/lib/chromium/chrome\x00--type=renderer\x00--private=secret-cookie\x00")},
	}
}

func taskObservationStat186(pid int, name string, threads int, state string) []byte {
	return []byte(fmt.Sprintf("%d (%s) %s %s%d\n", pid, name, state, strings.Repeat("0 ", 16), threads))
}

type taskObservationFS186 struct {
	fs.FS
	opens, closes, reads, bytes atomic.Int64
	closeFailure                bool
}

func (s *taskObservationFS186) Open(name string) (fs.File, error) {
	s.opens.Add(1)
	f, err := s.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return &taskObservationFile186{File: f, owner: s}, nil
}

type taskObservationFile186 struct {
	fs.File
	owner *taskObservationFS186
}

func (f *taskObservationFile186) Read(b []byte) (int, error) {
	f.owner.reads.Add(1)
	n, err := f.File.Read(b)
	f.owner.bytes.Add(int64(n))
	return n, err
}

func (f *taskObservationFile186) Close() error {
	f.owner.closes.Add(1)
	err := f.File.Close()
	if f.owner.closeFailure {
		return fs.ErrPermission
	}
	return err
}

func taskObserver186(source fs.FS, output *bytes.Buffer) *hashTaskObserver {
	return &hashTaskObserver{logger: slog.New(slog.NewJSONHandler(output, nil)), source: source, now: func() time.Time { return time.Unix(0, 0) }}
}

func TestHashTaskObservationFixedSchemaAndPrivacy(t *testing.T) {
	var output bytes.Buffer
	o := taskObserver186(taskObservationFixture186(), &output)
	o.observe(hashTaskTargetAllocated)
	var event map[string]any
	if json.Unmarshal(output.Bytes(), &event) != nil || len(event) != 50 {
		t.Fatal("unexpected fixed JSON schema", len(event))
	}
	if bytes.Contains(output.Bytes(), []byte("secret")) || bytes.Contains(output.Bytes(), []byte("/proc/")) || bytes.Contains(output.Bytes(), []byte("cmdline")) {
		t.Fatal("diagnostic exposed raw process/request content")
	}
	for key, value := range event {
		if key == "time" || key == "level" || key == "msg" {
			continue
		}
		switch value.(type) {
		case bool, float64:
		default:
			t.Fatal("non-scalar diagnostic value", key)
		}
	}
	if event["cgroup_complete"] != true || event["process_complete"] != true || event["max_events"] != float64(2) || event["browser_threads"] != float64(30) || event["renderer_threads"] != float64(22) || event["go_threads"] != float64(8) || event["file_reads"] != float64(13) {
		t.Fatal("fixed counters lost their actual source values")
	}
}

func TestHashTaskObservationRosterAndIOBounds(t *testing.T) {
	for _, count := range []int{128, 129} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			files := taskObservationFixture186()
			var roster strings.Builder
			for pid := 1; pid <= count; pid++ {
				fmt.Fprintf(&roster, "%d\n", pid)
				prefix := "proc/" + strconv.Itoa(pid) + "/"
				files[prefix+"stat"] = &fstest.MapFile{Data: taskObservationStat186(pid, "chromium", 1, "S")}
				files[prefix+"cmdline"] = &fstest.MapFile{Data: []byte("chrome\x00--type=renderer\x00")}
			}
			files["sys/fs/cgroup/cgroup.procs"] = &fstest.MapFile{Data: []byte(roster.String())}
			source := &taskObservationFS186{FS: files}
			var output bytes.Buffer
			s := taskObserver186(source, &output).snapshot()
			if s.roles[hashTaskChromeRenderer].processes != 128 || source.opens.Load() != 263 || source.closes.Load() != source.opens.Load() || source.reads.Load() > 8*263 || source.bytes.Load() > 398855 || s.reads != source.opens.Load() || s.readBytes != source.bytes.Load() {
				t.Fatal("bounded process/file/byte ownership changed", source.opens.Load(), source.closes.Load(), source.bytes.Load())
			}
			if s.processesOK != (count == 128) || s.truncated != (count == 129) {
				t.Fatal("oversized roster was silently reported complete")
			}
		})
	}
}

func TestHashTaskObservationUnknownAndMalformedSources(t *testing.T) {
	cases := []struct {
		name string
		edit func(fstest.MapFS)
	}{
		{"unlimited", func(f fstest.MapFS) { f["sys/fs/cgroup/pids.max"].Data = []byte("max\n") }},
		{"foreign-profile", func(f fstest.MapFS) { f["sys/fs/cgroup/pids.max"].Data = []byte("512\n") }},
		{"missing", func(f fstest.MapFS) { delete(f, "proc/4/stat") }},
		{"path-selector", func(f fstest.MapFS) { f["sys/fs/cgroup/cgroup.procs"].Data = []byte("../../secret") }},
		{"duplicate-pid", func(f fstest.MapFS) { f["sys/fs/cgroup/cgroup.procs"].Data = []byte("1\n1\n") }},
		{"counter-overflow", func(f fstest.MapFS) { f["sys/fs/cgroup/pids.events"].Data = []byte("max 9223372036854775808\n") }},
		{"duplicate-event", func(f fstest.MapFS) { f["sys/fs/cgroup/pids.events"].Data = []byte("max 1\nmax 2\n") }},
		{"wrong-pid", func(f fstest.MapFS) { f["proc/4/stat"].Data = taskObservationStat186(5, "chromium", 1, "S") }},
		{"long-stat", func(f fstest.MapFS) { f["proc/4/stat"].Data = bytes.Repeat([]byte("x"), 1025) }},
		{"long-argv", func(f fstest.MapFS) { f["proc/4/cmdline"].Data = bytes.Repeat([]byte("x"), 2049) }},
		{"ambiguous-role", func(f fstest.MapFS) {
			f["proc/4/cmdline"].Data = []byte("chrome\x00--type=renderer\x00--type=utility\x00")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := taskObservationFixture186()
			tc.edit(files)
			var output bytes.Buffer
			s := taskObserver186(files, &output).snapshot()
			if s.processesOK || s.reads > hashTaskReadLimit || s.readBytes > 398855 {
				t.Fatal("invalid/changing source gained a complete or unbounded observation")
			}
		})
	}
}

func TestHashTaskObservationCooperativeBudgetAndCloseFailures(t *testing.T) {
	for _, closeFailure := range []bool{false, true} {
		var output bytes.Buffer
		source := &taskObservationFS186{FS: taskObservationFixture186(), closeFailure: closeFailure}
		o := taskObserver186(source, &output)
		var clock atomic.Int64
		o.now = func() time.Time { return time.Unix(0, clock.Add(int64(time.Millisecond))) }
		s := o.snapshot()
		if !s.budget || s.processesOK || source.opens.Load() > 2 || source.closes.Load() != source.opens.Load() || (closeFailure && s.readErrors == 0) {
			t.Fatal("cooperative budget or descriptor-close failure was lost")
		}
	}
}

func TestHashTaskObservationConcurrentLifetimeCapAndNil(t *testing.T) {
	var output bytes.Buffer
	source := &taskObservationFS186{FS: taskObservationFixture186()}
	o := taskObserver186(source, &output)
	(*hashTaskObserver)(nil).observe(hashTaskStartupBefore)
	o.observe(0)
	o.observe(255)
	if source.opens.Load() != 0 {
		t.Fatal("nil/invalid diagnostic phase performed I/O")
	}
	var wg sync.WaitGroup
	for range 256 {
		wg.Add(1)
		go func() { defer wg.Done(); o.observe(hashTaskTargetBefore) }()
	}
	wg.Wait()
	for range 256 {
		o.observe(hashTaskTargetCleanupJoined)
	}
	before := source.opens.Load()
	o.observe(hashTaskStartupReady)
	if o.count.Load() != 64 || bytes.Count(output.Bytes(), []byte("\n")) != 64 || source.opens.Load() != before || source.closes.Load() != before {
		t.Fatal("diagnostic lifetime cap or ownership is not bounded")
	}
}
