// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

// SafeWebhookDiagnostic hides historical provider/error text on read without
// rewriting durable delivery rows. New worker writes use these fixed codes.
func SafeWebhookDiagnostic(value string) string {
	switch value {
	case "", "endpoint_missing", "endpoint_inactive", "endpoint_dependency_unavailable", "endpoint_secret_invalid",
		"event_missing", "event_dependency_unavailable", "event_invalid",
		"delivery_transport_unavailable", "delivery_http_refused":
		return value
	default:
		return "legacy_delivery_error"
	}
}
