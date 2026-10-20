// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	_ "github.com/bright-interaction/hash/gotenberg/internal/chromium"
	_ "github.com/bright-interaction/hash/gotenberg/internal/hashapi"
	gotenbergcmd "github.com/gotenberg/gotenberg/v8/cmd"
)

func main() {
	gotenbergcmd.Run()
}
