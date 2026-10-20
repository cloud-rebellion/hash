// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// One strong entity tag binds both public commitments. These observations
// never supply tenant, recipient, package identity or storage authority.
func signerPackageMemberExpectedV1(position string, header http.Header) (pdfadmission.SignerPackageMemberExpectedV1, int) {
	var out pdfadmission.SignerPackageMemberExpectedV1
	n, err := strconv.ParseUint(position, 10, 8)
	if err != nil || n > documentpackage.MaxAnnexesV1 || strconv.FormatUint(n, 10) != position {
		return out, http.StatusBadRequest
	}
	values := header.Values("If-Match")
	if len(values) == 0 || (len(values) == 1 && strings.Trim(values[0], " \t") == "") {
		return out, http.StatusPreconditionRequired
	}
	if len(values) != 1 {
		return out, http.StatusBadRequest
	}
	value := strings.Trim(values[0], " \t")
	if len(value) != 131 || value[0] != '"' || value[130] != '"' || value[65] != '.' {
		return out, http.StatusBadRequest
	}
	for i := 1; i < 130; i++ {
		if i == 65 {
			continue
		}
		if !(value[i] >= '0' && value[i] <= '9' || value[i] >= 'a' && value[i] <= 'f') {
			return out, http.StatusBadRequest
		}
	}
	if _, err := hex.Decode(out.ManifestSHA256[:], []byte(value[1:65])); err != nil {
		return pdfadmission.SignerPackageMemberExpectedV1{}, http.StatusBadRequest
	}
	if _, err := hex.Decode(out.LegalCommitmentSHA256[:], []byte(value[66:130])); err != nil {
		return pdfadmission.SignerPackageMemberExpectedV1{}, http.StatusBadRequest
	}
	out.Position = int32(n)
	return out, 0
}
