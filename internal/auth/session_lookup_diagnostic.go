// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"
)

// logSessionLookupFailure records closed classifications only. In particular,
// ConnectError and PgError can contain connection settings, SQL and identities;
// none of their strings or arbitrary fields belong in authentication logs.
func logSessionLookupFailure(ctx context.Context, err error) {
	requestState := "active"
	if requestErr := ctx.Err(); requestErr != nil {
		switch {
		case errors.Is(requestErr, context.Canceled):
			requestState = "canceled"
		case errors.Is(requestErr, context.DeadlineExceeded):
			requestState = "deadline"
		default:
			requestState = "other"
		}
	}
	var connectError *pgconn.ConnectError
	var postgresError *pgconn.PgError
	serverClass := "none"
	if errors.As(err, &postgresError) && postgresError != nil {
		switch postgresError.Code {
		case "57014":
			serverClass = "query_canceled"
		case "55P03":
			serverClass = "lock_unavailable"
		case "53300":
			serverClass = "connection_limit"
		case "57P01", "57P02", "57P03":
			serverClass = "server_unavailable"
		case "08000", "08001", "08003", "08004", "08006", "08007", "08P01":
			serverClass = "connection_exception"
		default:
			serverClass = "other"
		}
	}
	slog.WarnContext(ctx, "session authorization lookup failed",
		"operation", "get_user",
		"request_context", requestState,
		"lookup_error_canceled", errors.Is(err, context.Canceled),
		"lookup_error_deadline", errors.Is(err, context.DeadlineExceeded),
		"pgconn_timeout", pgconn.Timeout(err),
		"connect_error", errors.As(err, &connectError),
		"postgres_class", serverClass,
	)
}
