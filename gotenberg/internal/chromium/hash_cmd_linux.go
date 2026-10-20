//go:build linux

package chromium

import (
	"os"
	"os/exec"
	"syscall"
)

// Retained from chromedp v0.14.2 allocate_linux.go under its MIT license.
// ModifyCmdFunc replaces that default, so command capture must preserve it.
func hashAllocateCommandOptions(cmd *exec.Cmd) {
	if _, ok := os.LookupEnv("LAMBDA_TASK_ROOT"); ok {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}
