// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build linux

package main

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Go reserves virtual address space for its runtime, so RLIMIT_AS is larger
// than the GC target. This is a hard per-child address-space bound, not a claim
// of a 384MiB RSS cap. Aggregate parent/child RSS still needs a container limit.
func restrictPDFWorker() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, limit := range []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_AS, 2 << 30}, {unix.RLIMIT_CPU, 10},
		{unix.RLIMIT_CORE, 0}, {unix.RLIMIT_FSIZE, 0}, {unix.RLIMIT_NOFILE, 64},
	} {
		if err := unix.Setrlimit(limit.resource, &unix.Rlimit{Cur: limit.value, Max: limit.value}); err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return errors.New("unsupported PDF worker architecture")
	}
	// Validate the ABI first. Everything except the minimal Go/in-memory parser
	// syscall set is denied, including file opens, sockets, exec and ptrace.
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}
	allowed := []uint32{
		unix.SYS_READ, unix.SYS_WRITE, unix.SYS_CLOSE, unix.SYS_FSTAT, unix.SYS_LSEEK,
		unix.SYS_MMAP, unix.SYS_MPROTECT, unix.SYS_MUNMAP, unix.SYS_MADVISE, unix.SYS_BRK,
		unix.SYS_FUTEX, unix.SYS_SCHED_YIELD, unix.SYS_SCHED_GETAFFINITY,
		unix.SYS_GETPID, unix.SYS_GETTID,
		unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_SIGALTSTACK,
		unix.SYS_CLOCK_GETTIME, unix.SYS_NANOSLEEP, unix.SYS_CLOCK_NANOSLEEP, unix.SYS_RESTART_SYSCALL,
		unix.SYS_GETRANDOM, unix.SYS_SET_ROBUST_LIST, unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
		unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_PWAIT, unix.SYS_EVENTFD2,
	}
	// Fcntl pipe ownership/O_ASYNC can signal a same-UID parent without a kill
	// syscall. The tested runtime initializes its standard descriptors before
	// this boundary; no fcntl command is needed by the in-memory parser.
	for _, syscall := range allowed {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: syscall, Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	}
	// Runtime asynchronous preemption signals its own threads. A compromised
	// child must not use its shared UID to signal the parent or another service.
	filter = append(filter,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_TGKILL, Jf: 4},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.Getpid()), Jf: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	)
	// The TGKILL argument branch loaded arg0; reload the syscall for clone.
	filter = append(filter, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0})
	// Go may need another runtime thread. Only CLONE_THREAD is permitted; a
	// forked process cannot outlive the parent's CommandContext cancellation.
	filter = append(filter,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_CLONE, Jf: 3},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: unix.CLONE_THREAD, Jf: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	)
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	// Synchronize all already-started Go runtime threads; filtering only main's
	// OS thread leaves an exploitable unrestricted parser goroutine.
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	if result != 0 {
		return errors.New("PDF worker syscall policy synchronization failed")
	}
	return nil
}
