// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import "encoding/json"

func jsonMarshalLite(v any) ([]byte, error) {
	return json.Marshal(v)
}

func jsonUnmarshalLite(raw []byte, v any) error {
	return json.Unmarshal(raw, v)
}

// SyntheticTemplateReport preserves an explicit unknown record for templates
// whose original intake was not measured. It never attests removed metadata.
// New templates carry their observed, object-bound report instead.
func SyntheticTemplateReport() ([]byte, error) {
	return MergeReports(nil, Report{
		Asset:       "template-pdf",
		ContentType: "application/pdf",
		Method:      "legacy-template",
		Provenance:  "legacy-unknown",
		Stripped:    []string{},
	})
}
