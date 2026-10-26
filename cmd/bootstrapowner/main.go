// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Command bootstrapowner provisions the first genuine pending workspace owner.
// It never installs a password or issues authentication. Stage owns the
// separate maintenance, candidate and first-writer authorization boundary.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bright-interaction/hash/internal/bootstrapowner"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runBootstrapOwner(ctx, os.Args[1:], os.Stdout); err != nil {
		// SQL, connection, parser and user-input errors can contain private
		// values. Print only our fixed refusal classes.
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseInput(args []string) (bootstrapowner.Input, error) {
	var in bootstrapowner.Input
	flags := flag.NewFlagSet("bootstrap-owner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	seen := map[string]bool{}
	values := map[string]*string{"company": &in.Company, "owner-name": &in.OwnerName, "owner-email": &in.OwnerEmail, "review-ref": &in.ReviewRef}
	for name, destination := range values {
		flags.Func(name, "explicit nonsecret provisioning identity", func(value string) error {
			if seen[name] {
				return bootstrapowner.ErrInput
			}
			seen[name] = true
			*destination = value
			return nil
		})
	}
	flags.Func("org-id", "canonical planned organization UUID", func(value string) error {
		id, err := uuid.Parse(value)
		if seen["org-id"] || err != nil || id == uuid.Nil || id.String() != value {
			return bootstrapowner.ErrInput
		}
		seen["org-id"] = true
		in.OrgID = id
		return nil
	})
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || len(seen) != 5 {
		return bootstrapowner.Input{}, bootstrapowner.ErrInput
	}
	return bootstrapowner.Normalize(in)
}

func runBootstrapOwner(parent context.Context, args []string, out io.Writer) error {
	in, err := parseInput(args)
	if err != nil {
		return bootstrapowner.ErrInput
	}
	if parent == nil || out == nil {
		return bootstrapowner.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, bootstrapowner.OperationTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return bootstrapowner.ErrUnavailable
	}
	// HASH_DB_URL is the sole connection input. Do not silently inherit libpq
	// overrides or accept a credential-bearing URL in command arguments.
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if ok && strings.HasPrefix(name, "PG") && value != "" {
			return bootstrapowner.ErrUnavailable
		}
	}
	dsn := os.Getenv("HASH_DB_URL")
	if dsn == "" {
		return bootstrapowner.ErrUnavailable
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return bootstrapowner.ErrUnavailable
	}
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = make(map[string]string)
	}
	cfg.RuntimeParams["application_name"] = "hash-bootstrap-owner"
	cfg.RuntimeParams["search_path"] = "public,pg_catalog"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return bootstrapowner.ErrUnavailable
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = conn.Close(cleanup)
	}()
	result, err := bootstrapowner.Provision(ctx, conn, in)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return bootstrapowner.ErrUnavailable
	}
	return nil
}
