// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build linux && !race

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPDFSandboxChild(t *testing.T) {
	if os.Getenv("HASH_PDF_SANDBOX_TEST") != "1" {
		return
	}
	parent, err := strconv.Atoi(os.Getenv("HASH_PDF_SANDBOX_PARENT"))
	if err != nil {
		os.Exit(2)
	}
	if restrictPDFWorker() != nil {
		os.Exit(3)
	}
	if _, err := unix.Open("/etc/passwd", unix.O_RDONLY, 0); !errors.Is(err, unix.EPERM) {
		os.Exit(4)
	}
	if _, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); !errors.Is(err, unix.EPERM) {
		os.Exit(5)
	}
	if err := unix.Tgkill(parent, parent, unix.SIGKILL); !errors.Is(err, unix.EPERM) {
		os.Exit(6)
	}
	if err := unix.Tgkill(unix.Getpid(), unix.Gettid(), 0); err != nil {
		os.Exit(7)
	}
	for _, command := range []struct {
		op    int
		value int
	}{
		{unix.F_SETOWN, parent},
		{unix.F_SETSIG, int(unix.SIGUSR1)},
		{unix.F_SETFL, unix.O_ASYNC},
	} {
		if _, err := unix.FcntlInt(0, command.op, command.value); !errors.Is(err, unix.EPERM) {
			os.Exit(11)
		}
	}
	if _, err := unix.Mmap(-1, 0, 3<<30, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON); !errors.Is(err, unix.ENOMEM) {
		os.Exit(8)
	}
	if err := unix.Exec("/bin/sh", []string{"sh"}, nil); !errors.Is(err, unix.EPERM) {
		os.Exit(9)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if _, err := unix.Open("/etc/passwd", unix.O_RDONLY, 0); !errors.Is(err, unix.EPERM) {
				os.Exit(10)
			}
		}()
	}
	wg.Wait()
	fmt.Println("sandbox-denials-confirmed")
	os.Exit(0)
}

func TestPDFSandboxResourceAndAllThreadDenials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestPDFSandboxChild$")
	cmd.Env = []string{"GOMAXPROCS=1", "GOMEMLIMIT=384MiB", "HASH_PDF_SANDBOX_TEST=1", "HASH_PDF_SANDBOX_PARENT=" + strconv.Itoa(os.Getpid())}
	output, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("sandbox-denials-confirmed")) {
		t.Fatalf("sandbox child: %v %s", err, output)
	}
}
