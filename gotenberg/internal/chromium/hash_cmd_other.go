//go:build !linux

package chromium

import "os/exec"

// Retained from chromedp v0.14.2 allocate_other.go under its MIT license.
func hashAllocateCommandOptions(cmd *exec.Cmd) {}
