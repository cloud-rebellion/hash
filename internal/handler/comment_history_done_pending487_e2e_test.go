//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func chatDonePendingFixture487V1() ownedChatDone169V1 {
	return ownedChatDone169V1{ExitCode: 0, Verified: true, Posted: []ownedChatRow169V1{
		{ID: "00000000-0000-0000-0000-000000000001", Body: "Owned browser staff message ÅÄÖ"},
		{ID: "00000000-0000-0000-0000-000000000002", Body: "Owned browser signer message ÅÄÖ"},
	}}
}

func TestOwnedChatDone169RealExclusiveFilePublication487(t *testing.T) {
	path := filepath.Join(t.TempDir(), "done.json")
	if _, complete, err := ownedChatReadDone169V1(path); err != nil || complete {
		t.Fatal("missing owned completion must remain pending", complete, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, complete, err := ownedChatReadDone169V1(path); err != nil || complete {
		t.Fatal("actual create-before-write must remain pending", complete, err)
	}
	want := chatDonePendingFixture487V1()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise every actual first-read prefix, including incomplete UTF8 text.
	// One still-open writer adds each next byte to the same exclusive inode.
	for i := 0; i < len(raw); i++ {
		if _, err := file.Write(raw[i : i+1]); err != nil {
			t.Fatal(err)
		}
		got, complete, err := ownedChatReadDone169V1(path)
		if i+1 < len(raw) {
			if err != nil || complete {
				t.Fatalf("prefix%d must remain pending: complete=%t err=%v", i+1, complete, err)
			}
		} else if err != nil || !complete || len(got.Posted) != 2 || got.Posted[0] != want.Posted[0] || got.Posted[1] != want.Posted[1] {
			t.Fatal("complete exact publication must accept", complete, err)
		}
	}
}

func TestOwnedChatDone169CompletedWireRefusals487(t *testing.T) {
	good, err := json.Marshal(chatDonePendingFixture487V1())
	if err != nil {
		t.Fatal(err)
	}
	vectors := []string{
		`!`, `null`, `{}`, string(good) + `{}`, string(good) + `false`,
		strings.Replace(string(good), `"exit_code":0`, `"exit_code":1`, 1),
		strings.Replace(string(good), `"verified":true`, `"verified":false`, 1),
		strings.Replace(string(good), `"exit_code":0`, `"exit_code":0,"foreign":true`, 1),
		strings.Replace(string(good), `00000000-0000-0000-0000-000000000002`, `00000000-0000-0000-0000-000000000001`, 1),
		strings.Replace(string(good), `00000000-0000-0000-0000-000000000002`, `00000000-0000-0000-0000-000000000000`, 1),
		strings.Replace(string(good), `Owned browser signer message ÅÄÖ`, `wrong`, 1),
		strings.Replace(string(good), `"posted":[`, `"posted":[{"id":"foreign","body":"wrong"},`, 1),
		string(good) + strings.Repeat(" ", 1025-len(good)),
	}
	for i, raw := range vectors {
		path := filepath.Join(t.TempDir(), "done.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ownedChatReadDone169V1(path); err == nil {
			t.Fatalf("completed invalid wire%d must refuse", i)
		}
	}
}

func TestOwnedChatDone169PrivateFileRefusals487(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "done.json")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hardlink.json")
	if err := os.Link(file, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ownedChatReadDone169V1(file); err == nil {
		t.Fatal("unsafe empty hardlinked inode must refuse before pending")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ownedChatReadDone169V1(file); err == nil {
		t.Fatal("unsafe empty mode must refuse before pending")
	}
	if err := os.Symlink(file, filepath.Join(dir, "symlink.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ownedChatReadDone169V1(filepath.Join(dir, "symlink.json")); err == nil {
		t.Fatal("symlink must refuse")
	}
	if _, _, err := ownedChatReadDone169V1(dir); err == nil {
		t.Fatal("directory must refuse")
	}
}
