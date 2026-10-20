package chromium

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

type hashTaskPhase uint8

const (
	hashTaskStartupBefore hashTaskPhase = iota + 1
	hashTaskStartupReady
	hashTaskTargetBefore
	hashTaskTargetAllocated
	hashTaskTargetAllocationFailed
	hashTaskTargetCleanupJoined
	hashTaskTargetCleanupUnconfirmed
)

const (
	hashTaskRecordLimit = 64
	hashTaskPIDLimit    = 128
	hashTaskReadLimit   = 263 // four counters + roster + two files/PID + two end counters
	hashTaskBudget      = 5 * time.Millisecond
)

type hashTaskRole uint8

const (
	hashTaskInit hashTaskRole = iota
	hashTaskGo
	hashTaskChromeBrowser
	hashTaskChromeRenderer
	hashTaskChromeGPU
	hashTaskChromeUtility
	hashTaskChromeOther
	hashTaskCrashpad
	hashTaskProbe
	hashTaskOther
	hashTaskRoleCount
)

type hashTaskCounts struct{ processes, threads, zombies int64 }
type hashTaskSnapshot struct {
	current, limit, peak, events, endCurrent, endEvents int64
	cgroupOK, processesOK, profile, budget, truncated   bool
	reads, readBytes, readErrors                        int64
	roles                                               [hashTaskRoleCount]hashTaskCounts
}

// Diagnostic only. This object has no request data, business error, process
// launcher, restart capability or resource-release authority. Its trusted module
// logger is deliberately separate from conversion/request loggers.
type hashTaskObserver struct {
	logger *slog.Logger
	source fs.FS
	now    func() time.Time
	busy   atomic.Bool
	count  atomic.Uint32
}

func newHashTaskObserver(logger *slog.Logger) *hashTaskObserver {
	if runtime.GOOS != "linux" || logger == nil {
		return nil
	}
	return &hashTaskObserver{logger: logger, source: os.DirFS("/"), now: time.Now}
}

func (o *hashTaskObserver) observe(phase hashTaskPhase) {
	if o == nil || o.logger == nil || phase < hashTaskStartupBefore || phase > hashTaskTargetCleanupUnconfirmed || !o.logger.Enabled(context.Background(), slog.LevelInfo) || !o.busy.CompareAndSwap(false, true) {
		return
	}
	defer o.busy.Store(false)
	sequence := o.count.Load()
	if sequence >= hashTaskRecordLimit {
		return
	}
	o.count.Store(sequence + 1)
	s := o.snapshot()
	// Every key and string is static. Neither process identities nor raw procfs,
	// command lines, paths, document data or errors enter logging attributes.
	attrs := [47]slog.Attr{
		slog.Int("schema", 1), slog.Int("phase", int(phase)), slog.Uint64("sequence", uint64(sequence+1)),
		slog.Bool("cgroup_complete", s.cgroupOK), slog.Bool("process_complete", s.processesOK), slog.Bool("profile_128", s.profile),
		slog.Bool("budget_exhausted", s.budget), slog.Bool("truncated", s.truncated),
		slog.Int64("current", s.current), slog.Int64("limit", s.limit), slog.Int64("peak", s.peak), slog.Int64("max_events", s.events),
		slog.Int64("end_current", s.endCurrent), slog.Int64("end_max_events", s.endEvents),
		slog.Int64("file_reads", s.reads), slog.Int64("read_bytes", s.readBytes), slog.Int64("read_errors", s.readErrors),
	}
	keys := [hashTaskRoleCount][3]string{
		{"init_processes", "init_threads", "init_zombies"}, {"go_processes", "go_threads", "go_zombies"},
		{"browser_processes", "browser_threads", "browser_zombies"}, {"renderer_processes", "renderer_threads", "renderer_zombies"},
		{"gpu_processes", "gpu_threads", "gpu_zombies"}, {"utility_processes", "utility_threads", "utility_zombies"},
		{"chrome_other_processes", "chrome_other_threads", "chrome_other_zombies"}, {"crashpad_processes", "crashpad_threads", "crashpad_zombies"},
		{"probe_processes", "probe_threads", "probe_zombies"}, {"other_processes", "other_threads", "other_zombies"},
	}
	for i, role := range s.roles {
		attrs[17+3*i], attrs[18+3*i], attrs[19+3*i] = slog.Int64(keys[i][0], role.processes), slog.Int64(keys[i][1], role.threads), slog.Int64(keys[i][2], role.zombies)
	}
	o.logger.LogAttrs(context.Background(), slog.LevelInfo, "hash renderer task snapshot", attrs[:]...)
}

type hashTaskReader struct {
	observer *hashTaskObserver
	start    time.Time
	snapshot *hashTaskSnapshot
	buffer   [4097]byte
}

func (r *hashTaskReader) allowed() bool {
	if r.observer.now == nil || r.observer.source == nil {
		return false
	}
	elapsed := r.observer.now().Sub(r.start)
	if elapsed < 0 || elapsed >= hashTaskBudget || r.snapshot.reads >= hashTaskReadLimit {
		r.snapshot.budget = true
		return false
	}
	return true
}

// Cooperative checks precede every local procfs/sysfs operation. Kernel reads
// are synchronous: this is not a claim of preempting a blocked kernel syscall.
// Each open reads at most limit+1 bytes in at most eight Read calls, then closes.
func (r *hashTaskReader) read(name string, limit int) (body []byte, ok bool) {
	if limit < 1 || limit >= len(r.buffer) {
		r.snapshot.readErrors++
		return nil, false
	}
	if !r.allowed() {
		return nil, false
	}
	r.snapshot.reads++
	f, err := r.observer.source.Open(name)
	if err != nil {
		r.snapshot.readErrors++
		return nil, false
	}
	defer func() {
		if f.Close() != nil {
			r.snapshot.readErrors++
			body, ok = nil, false
		}
	}()
	total := 0
	for range 8 {
		if !r.allowedRead() {
			return nil, false
		}
		n, err := f.Read(r.buffer[total : limit+1])
		if n < 0 || n > limit+1-total {
			r.snapshot.readErrors++
			return nil, false
		}
		total += n
		r.snapshot.readBytes += int64(n)
		if total > limit {
			r.snapshot.truncated = true
			return nil, false
		}
		if err == io.EOF {
			return r.buffer[:total], true
		}
		if err != nil || n == 0 {
			r.snapshot.readErrors++
			return nil, false
		}
	}
	r.snapshot.truncated = true
	return nil, false
}

func (r *hashTaskReader) allowedRead() bool {
	elapsed := r.observer.now().Sub(r.start)
	if elapsed < 0 || elapsed >= hashTaskBudget {
		r.snapshot.budget = true
		return false
	}
	return true
}

func hashTaskNumber(b []byte) (int64, bool) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || len(b) > 19 {
		return 0, false
	}
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' || n > (1<<63-1-int64(c-'0'))/10 {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

func hashTaskToken(b []byte) (token, rest []byte) {
	b = bytes.TrimLeft(b, " \t\n\r")
	i := bytes.IndexAny(b, " \t\n\r")
	if i < 0 {
		return b, nil
	}
	return b[:i], b[i:]
}

func (r *hashTaskReader) counter(name string, events bool) (int64, bool) {
	limit := 64
	if events {
		limit = 512
	}
	b, ok := r.read("sys/fs/cgroup/"+name, limit)
	if !ok {
		return 0, false
	}
	if !events {
		return hashTaskNumber(b)
	}
	found, value := false, int64(0)
	for len(b) > 0 {
		var key, token []byte
		key, b = hashTaskToken(b)
		token, b = hashTaskToken(b)
		if len(key) == 0 {
			break
		}
		n, valid := hashTaskNumber(token)
		if !valid {
			return 0, false
		}
		if bytes.Equal(key, []byte("max")) {
			if found {
				return 0, false
			}
			found, value = true, n
		}
	}
	return value, found
}

func (o *hashTaskObserver) snapshot() (s hashTaskSnapshot) {
	if o.source == nil || o.now == nil {
		return s
	}
	r := hashTaskReader{observer: o, start: o.now(), snapshot: &s}
	var a, b, c, d bool
	s.current, a = r.counter("pids.current", false)
	s.limit, b = r.counter("pids.max", false)
	s.peak, c = r.counter("pids.peak", false)
	s.events, d = r.counter("pids.events", true)
	s.cgroupOK = a && b && c && d
	s.profile = s.cgroupOK && s.limit == hashTaskPIDLimit
	// Never inspect arbitrary host processes or an unbounded/unverified profile.
	if s.profile {
		s.processesOK = r.processes()
	}
	s.endCurrent, a = r.counter("pids.current", false)
	s.endEvents, b = r.counter("pids.events", true)
	s.cgroupOK = s.cgroupOK && a && b
	return s
}

func (r *hashTaskReader) processes() bool {
	b, ok := r.read("sys/fs/cgroup/cgroup.procs", 4096)
	if !ok {
		return false
	}
	var pids [hashTaskPIDLimit]int64
	count, complete := 0, true
	for len(bytes.TrimSpace(b)) > 0 {
		if !r.allowedRead() {
			return false
		}
		var token []byte
		token, b = hashTaskToken(b)
		pid, valid := hashTaskNumber(token)
		if !valid || pid <= 0 || pid > 1<<31-1 {
			return false
		}
		for _, previous := range pids[:count] {
			if previous == pid {
				return false
			}
		}
		if count == len(pids) {
			r.snapshot.truncated = true
			complete = false
			break
		}
		pids[count] = pid
		count++
	}
	for _, pid := range pids[:count] {
		prefix := "proc/" + strconv.FormatInt(pid, 10) + "/"
		stat, valid := r.read(prefix+"stat", 1024)
		if !valid {
			complete = false
			continue
		}
		role, threads, zombie, chrome, valid := hashTaskStat(stat, pid)
		if !valid {
			complete = false
			continue
		}
		if chrome && !zombie {
			args, valid := r.read(prefix+"cmdline", 2048)
			if valid {
				role, valid = hashTaskChromeRole(args)
			}
			if !valid {
				role, complete = hashTaskChromeOther, false
			}
		}
		counts := &r.snapshot.roles[role]
		counts.processes++
		counts.threads += threads
		if zombie {
			counts.zombies++
		}
	}
	return complete && !r.snapshot.budget
}

func hashTaskStat(b []byte, expectedPID int64) (role hashTaskRole, threads int64, zombie, chrome, ok bool) {
	role = hashTaskOther
	open, close := bytes.IndexByte(b, '('), bytes.LastIndex(b, []byte(") "))
	if open < 1 || close <= open {
		return
	}
	pid, valid := hashTaskNumber(b[:open])
	if !valid || pid != expectedPID {
		return
	}
	name, rest := b[open+1:close], b[close+2:]
	var field []byte
	for i := 0; i <= 17; i++ {
		field, rest = hashTaskToken(rest)
		if len(field) == 0 {
			return
		}
		if i == 0 {
			if len(field) != 1 || !bytes.ContainsRune([]byte("RSDZTWtXxKWPIN"), rune(field[0])) {
				return
			}
			zombie = field[0] == 'Z'
		}
	}
	threads, valid = hashTaskNumber(field)
	if !valid || threads < 1 || threads > hashTaskPIDLimit {
		return role, 0, zombie, false, false
	}
	switch string(name) {
	case "tini":
		role = hashTaskInit
	case "gotenberg":
		role = hashTaskGo
	case "chromium", "chrome", "chromium-browse":
		role, chrome = hashTaskChromeOther, true
	case "chrome_crashpad", "chrome_crashpad_":
		role = hashTaskCrashpad
	case "sh", "ash", "wget", "cat":
		role = hashTaskProbe
	}
	return role, threads, zombie, chrome, true
}

func hashTaskChromeRole(b []byte) (hashTaskRole, bool) {
	if len(b) == 0 || b[len(b)-1] != 0 {
		return hashTaskChromeOther, false
	}
	typeSeen, first, role := false, true, hashTaskChromeBrowser
	for len(b) > 0 {
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			return hashTaskChromeOther, false
		}
		arg := b[:i]
		b = b[i+1:]
		if first {
			first = false
			if j := bytes.LastIndexByte(arg, '/'); j >= 0 {
				arg = arg[j+1:]
			}
			if !bytes.Equal(arg, []byte("chrome")) && !bytes.Equal(arg, []byte("chromium")) && !bytes.Equal(arg, []byte("chromium-browser")) {
				return hashTaskChromeOther, false
			}
			continue
		}
		if !bytes.HasPrefix(arg, []byte("--type=")) {
			continue
		}
		if typeSeen {
			return hashTaskChromeOther, false
		}
		typeSeen = true
		switch string(arg[len("--type="):]) {
		case "renderer":
			role = hashTaskChromeRenderer
		case "gpu-process":
			role = hashTaskChromeGPU
		case "utility":
			role = hashTaskChromeUtility
		default:
			role = hashTaskChromeOther
		}
	}
	return role, true
}
