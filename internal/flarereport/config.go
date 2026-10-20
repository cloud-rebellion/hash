// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// BrowserConfig contains only the intentionally public ingest identifier and
// immutable process identity. Never serialize a general configuration object.
type BrowserConfig struct {
	Enabled     bool   `json:"enabled"`
	DSN         string `json:"dsn,omitempty"`
	Environment string `json:"environment,omitempty"`
	Release     string `json:"release,omitempty"`
	Service     string `json:"service,omitempty"`
}

func identityValue(value string) string {
	if len(value) == 0 || len(value) > 128 {
		return ""
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._@+-", c)) {
			return ""
		}
	}
	return value
}
func publicDSN(raw, environment string) (string, string, bool) {
	if len(raw) == 0 || len(raw) > 2048 {
		return "", "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || u.Host == "" || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", "", false
	}
	host := strings.ToLower(u.Hostname())
	if !safeHost(host) {
		return "", "", false
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", "", false
	}
	port := u.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", "", false
		}
		port = strconv.Itoa(number)
	} else if strings.Contains(u.Host, ":") && net.ParseIP(host) == nil {
		return "", "", false
	}
	if port == "443" && u.Scheme == "https" || port == "80" && u.Scheme == "http" {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || environment != "development" || (host != "localhost" && host != "127.0.0.1" && host != "::1") {
			return "", "", false
		}
	}
	if strings.ContainsAny(u.Host, "\r\n\t ") || len(u.Host) > 253 {
		return "", "", false
	}
	key := u.User.Username()
	validPart := func(s string) bool {
		if len(s) == 0 || len(s) > 64 {
			return false
		}
		for _, r := range s {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				return false
			}
		}
		return true
	}
	if !validPart(key) {
		return "", "", false
	}
	path := strings.TrimRight(u.Path, "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(path) > 256 || len(parts) == 0 {
		return "", "", false
	}
	for _, part := range parts {
		if !validPart(part) {
			return "", "", false
		}
	}
	// A server DSN can carry a private password. Browsers get only its public
	// username; query/fragment and every other config value are excluded.
	u.User = url.User(key)
	u.Path = path
	u.RawPath = ""
	return u.String(), u.Scheme + "://" + u.Host, true
}
func BrowserConfiguration(release, environment string) BrowserConfig {
	release, environment = identityValue(release), identityValue(environment)
	if release == "" || !validEnvironment(environment) {
		return BrowserConfig{}
	}
	dsn, _, ok := publicDSN(os.Getenv("FLARE_DSN"), environment)
	if !ok {
		return BrowserConfig{}
	}
	return BrowserConfig{Enabled: true, DSN: dsn, Environment: environment, Release: release, Service: "hash-browser"}
}
func BrowserIngestOrigin(release, environment string) string {
	cfg := BrowserConfiguration(release, environment)
	if !cfg.Enabled {
		return ""
	}
	_, origin, ok := publicDSN(cfg.DSN, environment)
	if !ok {
		return ""
	}
	return origin
}

func validEnvironment(environment string) bool {
	switch environment {
	case "development", "test", "staging", "production", "unknown":
		return true
	}
	return false
}
func safeHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	numeric := true
	for _, c := range host {
		if !(c >= '0' && c <= '9' || c == '.') {
			numeric = false
		}
	}
	if numeric {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
