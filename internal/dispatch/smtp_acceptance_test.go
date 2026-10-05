// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

func TestSMTPAcceptanceSurvivesQuitDisconnect(t *testing.T) {
	for _, accept := range []bool{true, false} {
		t.Run(fmt.Sprintf("accepted_%v", accept), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(2 * time.Second))
				rw := bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))
				reply := func(value string) error {
					if _, err := rw.WriteString(value + "\r\n"); err != nil {
						return err
					}
					return rw.Flush()
				}
				if err := reply("220 smtp.example ESMTP"); err != nil {
					done <- err
					return
				}
				for _, prefix := range []string{"EHLO ", "MAIL FROM:", "RCPT TO:", "DATA"} {
					line, err := rw.ReadString('\n')
					if err != nil {
						done <- err
						return
					}
					if !strings.HasPrefix(line, prefix) {
						done <- fmt.Errorf("expected %s got %q", prefix, line)
						return
					}
					response := "250 OK"
					if prefix == "DATA" {
						response = "354 send message"
					}
					if err := reply(response); err != nil {
						done <- err
						return
					}
				}
				for {
					line, err := rw.ReadString('\n')
					if err != nil {
						done <- err
						return
					}
					if line == ".\r\n" {
						break
					}
				}
				response := "250 queued"
				if !accept {
					response = "451 queue unavailable"
				}
				if err := reply(response); err != nil {
					done <- err
					return
				}
				if accept {
					line, err := rw.ReadString('\n')
					if err != nil {
						done <- err
						return
					}
					if line != "QUIT\r\n" {
						done <- fmt.Errorf("expected QUIT got %q", line)
						return
					}
				}
				// Disconnect without a QUIT reply after acceptance.
				done <- nil
			}()
			c, err := smtp.NewClient(client, "smtp.example")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err = c.Mail("from@example.test"); err != nil {
				t.Fatal(err)
			}
			if err = c.Rcpt("to@example.test"); err != nil {
				t.Fatal(err)
			}
			data, err := c.Data()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = data.Write([]byte("Subject: test\r\n\r\nmessage\r\n")); err != nil {
				t.Fatal(err)
			}
			err = finishSMTPDelivery(context.Background(), c, data)
			if accept && err != nil {
				t.Fatalf("accepted message failed: %v", err)
			}
			if !accept && err == nil {
				t.Fatal("rejected DATA accepted")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
