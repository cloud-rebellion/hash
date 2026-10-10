// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build !linux

package main

import "errors"

func restrictPDFWorker() error { return errors.New("isolated PDF worker requires Linux") }
