//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	"nhooyr.io/websocket"
)

func TestCollabTwoSocketCanonicalSaveAndReconnectE2E(t *testing.T) {
	baseCtx, _, q, s, org, user := setupDSRE2E(t)
	ctx, cancel := context.WithTimeout(baseCtx, 30*time.Second)
	defer cancel()
	var err error
	s.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(bytes.Repeat([]byte{28}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.PublicURL = "https://hash.example.test"
	s.Collab = collab.NewHub(q)
	s.Collab.FlushEvery = 0
	defer s.Collab.Shutdown(context.Background())
	payload, _ := json.Marshal(auth.SessionPayload{UserID: user})
	cookie := s.Cookies.Mint(payload, time.Hour)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, Name: "socket save", SenderID: user, BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s.Routes())
	defer server.Close()
	endpoint := server.URL + "/api/v1/documents/" + doc.ID.String()
	connect := func() *websocket.Conn {
		current, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
		if err != nil {
			t.Fatal(err)
		}
		headers := http.Header{"Cookie": []string{SessionCookieName + "=" + cookie}, "Origin": []string{s.PublicURL}}
		conn, _, err := websocket.Dial(ctx, strings.Replace(endpoint, "http:", "ws:", 1)+"/collab?expected_updated_at="+url.QueryEscape(current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)), &websocket.DialOptions{HTTPHeader: headers})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.CloseNow() })
		return conn
	}
	read := func(conn *websocket.Conn) []byte {
		kind, frame, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if kind != websocket.MessageBinary {
			t.Fatal("nonbinary frame")
		}
		return frame
	}
	write := func(conn *websocket.Conn, frame []byte) {
		if err := conn.Write(ctx, websocket.MessageBinary, frame); err != nil {
			t.Fatal(err)
		}
	}
	initial := func(conn *websocket.Conn, wantGeneration byte) [][]byte {
		generation := read(conn)
		if !bytes.Equal(generation, []byte{collab.MessageGeneration, 1, wantGeneration}) {
			t.Fatalf("generation %v", generation)
		}
		grant := read(conn)
		if len(grant) != 2 || grant[0] != collab.MessageBootstrap {
			t.Fatalf("grant %v", grant)
		}
		var frames [][]byte
		for {
			frame := read(conn)
			if frame[0] != collab.MessageSync {
				t.Fatalf("unexpected initial frame %v", frame)
			}
			frames = append(frames, frame)
			if frame[1] == collab.SyncStep2 {
				return frames
			}
		}
	}
	// Installed Yjs-generated v1 updates for text test: first, then second.
	first := []byte{18, 1, 1, 123, 0, 4, 1, 4, 116, 101, 115, 116, 5, 102, 105, 114, 115, 116, 0}
	second := []byte{16, 1, 1, 123, 5, 132, 123, 4, 7, 32, 115, 101, 99, 111, 110, 100, 0}
	alice := connect()
	initial(alice, '1')
	write(alice, append([]byte{0, 2}, first...))
	// Checkpoint on the same socket fences its prior update before Bob joins.
	checkpoint := func(conn *websocket.Conn) (collabSaveInput, [][]byte) {
		nonce := bytes.Repeat([]byte{31}, 16)
		write(conn, append([]byte{collab.MessageCheckpoint, 0}, nonce...))
		var frames [][]byte
		for {
			frame := read(conn)
			if frame[0] == collab.MessageSync {
				frames = append(frames, frame)
				continue
			}
			if frame[0] != collab.MessageCheckpoint || len(frame) < 18 || frame[1] != 1 || !bytes.Equal(frame[2:18], nonce) {
				t.Fatalf("unexpected checkpoint frame %v", frame)
			}
			rest := frame[18:]
			values := make([]string, 3)
			for i := range values {
				n, prefix := binary.Uvarint(rest)
				if prefix <= 0 || n > uint64(len(rest)-prefix) {
					t.Fatal("invalid checkpoint string")
				}
				values[i] = string(rest[prefix : prefix+int(n)])
				rest = rest[prefix+int(n):]
			}
			if len(rest) != 32 {
				t.Fatal("invalid checkpoint token")
			}
			return collabSaveInput{PeerID: values[0], Generation: values[1], Checkpoint: hex.EncodeToString(rest), BlocksJSON: doc.BlocksJson}, frames
		}
	}
	checkpoint(alice)
	bob := connect()
	bobInitial := initial(bob, '1')
	if len(bobInitial) != 1 || !bytes.Equal(bobInitial[0][2:], first) {
		t.Fatal("second socket missing first edit")
	}
	write(bob, append([]byte{0, 2}, second...))
	received := read(alice)
	if !bytes.Equal(received, append([]byte{0, 2}, second...)) {
		t.Fatal("live second edit missing")
	}
	input, replay := checkpoint(alice)
	input.ExpectedUpdatedAt = doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)
	save := func(in collabSaveInput) struct {
		Document   documentResponse `json:"document"`
		Generation string           `json:"generation"`
	} {
		body, _ := json.Marshal(in)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/collab/save", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", s.PublicURL)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			t.Fatalf("save %d: %s", response.StatusCode, raw)
		}
		var receipt struct {
			Document   documentResponse `json:"document"`
			Generation string           `json:"generation"`
		}
		if err := json.Unmarshal(raw, &receipt); err != nil {
			t.Fatal(err)
		}
		return receipt
	}
	receipt := save(input)
	if receipt.Generation != "2" {
		t.Fatal("first save did not advance")
	}
	for _, conn := range []*websocket.Conn{alice, bob} {
		frame := read(conn)
		if len(frame) < 3 || frame[0] != collab.MessageSaved || frame[2] != '2' {
			t.Fatalf("peer missing committed receipt: %v", frame)
		}
	}
	input, _ = checkpoint(bob)
	input.ExpectedUpdatedAt = receipt.Document.UpdatedAt
	receipt = save(input)
	if receipt.Generation != "3" {
		t.Fatal("second peer save did not advance")
	}
	for _, conn := range []*websocket.Conn{alice, bob} {
		frame := read(conn)
		if frame[0] != collab.MessageSaved || frame[2] != '3' {
			t.Fatalf("second receipt %v", frame)
		}
	}
	alice.CloseNow()
	bob.CloseNow()
	reconnect := connect()
	reconnected := initial(reconnect, '3')
	if len(reconnected) != 2 || !bytes.Equal(reconnected[0][2:], first) || !bytes.Equal(reconnected[1][2:], second) {
		t.Fatal("reconnect lost history")
	}
	ints := make([][]int, len(replay))
	for i, frame := range replay {
		for _, value := range frame {
			ints[i] = append(ints[i], int(value))
		}
	}
	raw, _ := json.Marshal(ints)
	t.Logf("YJS_SOCKET_SAVE_FRAMES=%s", raw)
}
