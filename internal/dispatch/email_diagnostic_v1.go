// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"context"
	"errors"
	"net"
	"net/textproto"
	"strconv"
)

// SafeEmailDiagnosticV1 is the durable queue/log boundary. SMTP replies and
// transport errors can echo the private message, recipient or authentication
// material. Preserve closed operational categories, never provider free text.
func SafeEmailDiagnosticV1(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "email_delivery_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "email_delivery_timeout"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "email_delivery_timeout"
	}
	var status *textproto.Error
	if errors.As(err, &status) && status.Code >= 100 && status.Code <= 599 {
		return "email_delivery_smtp_" + strconv.Itoa(status.Code)
	}
	return "email_delivery_transport_unavailable"
}
