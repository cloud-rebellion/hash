// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/render"
)

func renderRedactionReportSection(raw json.RawMessage) string {
	return render.RedactionReportSectionV1(raw)
}
