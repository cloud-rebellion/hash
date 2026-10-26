// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package bootstrapowner

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// TableHasBusinessRows treats an ordinary nonempty table conservatively. Only
// the two exact rows inserted by migration89 count as empty scaffolding;
// missing, additional, populated or READY resource state is never exempted.
// Callers separately validate Goose and billing-plan seeds.
func TableHasBusinessRows(ctx context.Context, tx pgx.Tx, table string) (bool, error) {
	if ctx == nil || tx == nil || table == "" {
		return false, ErrUnavailable
	}
	var query string
	switch table {
	case "signing_resource_control":
		query = `SELECT (SELECT count(*)=1 FROM public.signing_resource_control)
 AND EXISTS (SELECT 1 FROM public.signing_resource_control
     WHERE singleton AND state='uninitialized' AND active_snapshot_id IS NULL
       AND controller_verification_receipt_id IS NULL)`
	case "signing_resource_accounts":
		query = `SELECT (SELECT count(*)=1 FROM public.signing_resource_accounts)
 AND EXISTS (SELECT 1 FROM public.signing_resource_accounts
     WHERE account_key='00000000-0000-0000-0000-000000000000'::uuid
       AND scope='global' AND org_id IS NULL AND state='uninitialized'
       AND baseline_snapshot_id IS NULL
       AND baseline_db_capacity_bytes=0 AND baseline_db_retained_bytes=0
       AND baseline_provider_bytes=0 AND baseline_provider_objects=0
       AND db_capacity_bytes=0 AND db_retained_bytes=0
       AND provider_reserved_bytes=0 AND provider_reserved_objects=0
       AND db_capacity_limit IS NULL AND provider_bytes_limit IS NULL
       AND provider_objects_limit IS NULL)`
	default:
		var nonempty bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM "+pgx.Identifier{"public", table}.Sanitize()+" LIMIT 1)").Scan(&nonempty); err != nil {
			return false, ErrUnavailable
		}
		return nonempty, nil
	}
	var initial bool
	if err := tx.QueryRow(ctx, query).Scan(&initial); err != nil {
		return false, ErrUnavailable
	}
	return !initial, nil
}
