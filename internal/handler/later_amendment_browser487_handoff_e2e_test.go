//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"os"
	"path/filepath"
	"testing"
)

func amendment487AssertPending(t *testing.T, path string) {
	t.Helper()
	complete, success, err := amendment487ReadDone(path)
	if err != nil || complete || success {
		t.Fatalf("unfinished publication must remain pending: complete=%v success=%v err=%v", complete, success, err)
	}
}

func amendment487AssertDoneRejected(t *testing.T, path string) {
	t.Helper()
	_, _, err := amendment487ReadDone(path)
	if err == nil {
		t.Fatal("unsafe or malformed publication was not refused")
	}
}

// Exercise the actual filesystem protocol: O_EXCL publishes the name before
// Write supplies JSON. Every stable prefix is observed through the real safe
// reader, then the same open inode receives its remaining bytes. No fake reader
// or timer increase can conceal an early acceptance or a partial-JSON failure.
func TestAmendment487DonePublicationPrefixesRemainPendingE2E(t *testing.T) {
	path := filepath.Join(t.TempDir(), "done.json")
	amendment487AssertPending(t, path)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	amendment487AssertPending(t, path)
	const wire = `{"schema":1,"exit_code":0,"verified":true}`
	for index := 0; index < len(wire); index++ {
		if _, err := file.Write([]byte{wire[index]}); err != nil {
			t.Fatal(err)
		}
		if index+1 < len(wire) {
			amendment487AssertPending(t, path)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	complete, success, err := amendment487ReadDone(path)
	if err != nil || !complete || !success {
		t.Fatalf("complete original publication must succeed: complete=%v success=%v err=%v", complete, success, err)
	}
}

func TestAmendment487DoneCompleteJSONRemainsStrictE2E(t *testing.T) {
	for _, wire := range []string{
		`{"schema":1,"exit_code":0,"verified":true,"unknown":1}`,
		`{"schema":1,"exit_code":0,"verified":true} {}`,
		`{"schema":1,"exit_code":0,"verified":true} {`,
		`{"schema":1,"exit_code":0,"verified":true} garbage`,
		`{"schema":2,"exit_code":0,"verified":true}`,
		`{"schema":1,"exit_code":0,"verified":false}`,
		`{"schema":1,"exit_code":2,"verified":false}`,
		`{"schema":1,"exit_code":-1,"verified":false}`,
		`{"schema":1,"exit_code":0.5,"verified":true}`,
		`{"schema":1,"exit_code":0,"verified":truX}`,
		`[]`,
		`null`,
		` `,
	} {
		t.Run(wire, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "done.json")
			if err := os.WriteFile(path, []byte(wire), 0600); err != nil {
				t.Fatal(err)
			}
			amendment487AssertDoneRejected(t, path)
		})
	}
	path := filepath.Join(t.TempDir(), "negative.json")
	if err := os.WriteFile(path, []byte(`{"schema":1,"exit_code":1,"verified":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	complete, success, err := amendment487ReadDone(path)
	if err != nil || !complete || success {
		t.Fatalf("explicit failure must remain a completed negative result: %v %v %v", complete, success, err)
	}
}

func TestAmendment487DoneUnsafeFilesRemainRejectedE2E(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "empty"}[empty], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "done.json")
			wire := []byte(`{"schema":1,"exit_code":0,"verified":true}`)
			if empty {
				wire = nil
			}
			if err := os.WriteFile(path, wire, 0600); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(dir, "alias.json")
			if err := os.Link(path, alias); err != nil {
				t.Fatal(err)
			}
			amendment487AssertDoneRejected(t, path)
			amendment487AssertDoneRejected(t, alias)
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path, alias); err != nil {
				t.Fatal(err)
			}
			amendment487AssertDoneRejected(t, alias)
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			amendment487AssertDoneRejected(t, path)
		})
	}
	path := filepath.Join(t.TempDir(), "oversize.json")
	if err := os.WriteFile(path, make([]byte, 2049), 0600); err != nil {
		t.Fatal(err)
	}
	amendment487AssertDoneRejected(t, path)
	amendment487AssertDoneRejected(t, t.TempDir())
}
