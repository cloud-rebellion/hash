// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"context"
	"strings"
	"testing"
)

func TestWorkspaceSMTP730MissingOrgRefusesBeforeQueueDependency(t *testing.T) {
	err := (QueueingMailer{}).Send(context.Background(), Message{To: "recipient@example.test", Subject: "Synthetic"})
	if err == nil || !strings.Contains(err.Error(), "genuine workspace org") {
		t.Fatalf("missing org reached queue: %v", err)
	}
}
