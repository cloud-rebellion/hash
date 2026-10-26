// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/bootstrapowner"
)

func commandArgs() []string {
	return []string{"--org-id", "10101010-1010-4010-8010-101010101010", "--company", "Example Company", "--owner-name", "Example Owner", "--owner-email", "owner@example.test", "--review-ref", "review-first-owner"}
}

func TestBootstrapOwnerCLIRequiresExplicitCanonicalIdentity(t *testing.T) {
	if _, err := parseInput(commandArgs()); err != nil {
		t.Fatal("explicit valid command refused")
	}
	for _, args := range [][]string{
		nil,
		commandArgs()[:8],
		append(commandArgs(), "--company", "Changed"),
		append(commandArgs(), "--dsn", "private-connection-input"),
		append(commandArgs(), "extra"),
		append([]string{"--org-id", "00000000-0000-0000-0000-000000000000"}, commandArgs()[2:]...),
		append([]string{"--org-id", "{10101010-1010-4010-8010-101010101010}"}, commandArgs()[2:]...),
	} {
		var out bytes.Buffer
		if err := runBootstrapOwner(context.Background(), args, &out); err != bootstrapowner.ErrInput || out.Len() != 0 {
			t.Fatal("ambiguous or invalid command reached connection configuration")
		}
	}
}

func TestBootstrapOwnerCLINeverPrintsConnectionOrParserInputs(t *testing.T) {
	private := "private-connection-marker"
	t.Setenv("HASH_DB_URL", "postgres://invalid/%"+private)
	var out bytes.Buffer
	err := runBootstrapOwner(context.Background(), commandArgs(), &out)
	if err != bootstrapowner.ErrUnavailable || strings.Contains(err.Error(), private) || out.Len() != 0 {
		t.Fatal("connection parser detail escaped the fixed refusal")
	}
	t.Setenv("HASH_DB_URL", "")
	if err := runBootstrapOwner(context.Background(), commandArgs(), &out); err != bootstrapowner.ErrUnavailable || out.Len() != 0 {
		t.Fatal("missing connection configuration was not refused")
	}
}

func TestBootstrapOwnerCLICancellationHasNoSuccessOutput(t *testing.T) {
	t.Setenv("HASH_DB_URL", "postgres://localhost/unreachable-bootstrap-fixture?sslmode=disable")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := runBootstrapOwner(ctx, commandArgs(), &out); err != bootstrapowner.ErrUnavailable || out.Len() != 0 {
		t.Fatal("cancelled command reported provisioning success")
	}
}
