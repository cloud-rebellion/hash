//go:build linux

package chromium

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestHashLinuxCommandPolicyPreservesPinnedDefaults(t *testing.T) {
	for _, mode := range []string{"default", "existing-attributes", "lambda-present-empty"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("LAMBDA_TASK_ROOT", "")
			if mode != "lambda-present-empty" {
				if err := os.Unsetenv("LAMBDA_TASK_ROOT"); err != nil {
					t.Fatal(err)
				}
			}
			cmd := &exec.Cmd{}
			if mode != "default" {
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
			}
			previous := cmd.SysProcAttr
			hashAllocateCommandOptions(cmd)
			if mode == "lambda-present-empty" {
				if cmd.SysProcAttr != previous || cmd.SysProcAttr.Pdeathsig != syscall.SIGTERM || !cmd.SysProcAttr.Setpgid {
					t.Fatal("present-empty Lambda policy changed")
				}
				return
			}
			if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL || (previous != nil && (cmd.SysProcAttr != previous || !cmd.SysProcAttr.Setpgid)) {
				t.Fatal("parent-death or unrelated existing attributes changed")
			}
		})
	}
}
