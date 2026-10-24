// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package passwordhash uses the estate's TrustIssues Argon2id PHC format.
// Both allocation cost and the number of active/waiting computations are fixed.
package passwordhash

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	memory           = 64 * 1024
	iterations       = 3
	threads          = 4
	saltLength       = 16
	keyLength        = 32
	MaxPasswordBytes = 1024
	waitBudget       = 2 * time.Second
)

var (
	ErrBusy        = errors.New("password hashing is busy")
	ErrInvalidHash = errors.New("invalid password hash")
	slots          = make(chan struct{}, 4)
	waiters        = make(chan struct{}, 32)
)

// DummyHash has the same strictly bounded parameters as real credentials.
// Its all-zero expected key is only a timing substitute, never an account.
var DummyHash = "$argon2id$v=19$m=65536,t=3,p=4$" +
	base64.RawStdEncoding.EncodeToString(make([]byte, saltLength)) + "$" +
	base64.RawStdEncoding.EncodeToString(make([]byte, keyLength))

func acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	release := func() { <-slots }
	select {
	case slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			release()
			return nil, err
		}
		return release, nil
	default:
	}
	select {
	case waiters <- struct{}{}:
		defer func() { <-waiters }()
	default:
		return nil, ErrBusy
	}
	timer := time.NewTimer(waitBudget)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			release()
			return nil, err
		}
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrBusy
	}
}

func Hash(ctx context.Context, password string) (string, error) {
	if password == "" || len(password) > MaxPasswordBytes {
		return "", errors.New("invalid password length")
	}
	release, err := acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, iterations, memory, threads, keyLength)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func decode(encoded string) ([]byte, []byte, error) {
	if len(encoded) > 512 {
		return nil, nil, ErrInvalidHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" ||
		parts[2] != fmt.Sprintf("v=%d", argon2.Version) || parts[3] != "m=65536,t=3,p=4" {
		return nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != saltLength {
		return nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) != keyLength {
		return nil, nil, ErrInvalidHash
	}
	if base64.RawStdEncoding.EncodeToString(salt) != parts[4] ||
		base64.RawStdEncoding.EncodeToString(key) != parts[5] {
		return nil, nil, ErrInvalidHash
	}
	return salt, key, nil
}

func Verify(ctx context.Context, password, encoded string) (bool, error) {
	if len(password) > MaxPasswordBytes {
		return false, ErrInvalidHash
	}
	salt, expected, err := decode(encoded)
	if err != nil {
		return false, err
	}
	release, err := acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	// Argon2 itself is synchronous: cancellation never abandons an allocating
	// goroutine or releases its slot before the computation actually finishes.
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, keyLength)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected, got) == 1, nil
}
