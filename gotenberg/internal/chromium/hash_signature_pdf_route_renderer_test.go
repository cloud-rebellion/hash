//go:build renderer_e2e

package chromium

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

// This exercises a real HTTP connection, the registered closed route, the
// existing real browser/supervisor factory and exact package decoding. The
// upstream API's independent hard-timeout middleware is not exported; its
// full production wrapper still needs the parent's actual service HTTP gate.
func TestHashSignaturePDFRouteGenuineHTTP(t *testing.T) {
	mod, browser := hashPublicFixtureModule(t)
	mod.hashSignatureAPITimeout = 30 * time.Second
	t.Setenv("HASH_SIGNATURE_FIT_TOKEN", hashRouteTestToken)
	routes, err := mod.Routes()
	if err != nil {
		t.Fatal("route configuration")
	}
	e := echo.New()
	registered := 0
	for _, route := range routes {
		if route.Path == hashSignaturePDFRoutePath {
			registered++
			if route.Method != http.MethodPost || route.IsMultipart || !route.DisableTelemetry {
				t.Fatal("route scope")
			}
			e.Add(route.Method, route.Path, route.Handler)
		}
	}
	if registered != 1 {
		t.Fatal("exact private route absent")
	}
	server := httptest.NewUnstartedServer(e)
	// Match the ordinary default API connection deadlines. No route test can
	// disable these deadlines to make fitting succeed.
	server.Config.ReadTimeout = 30 * time.Second
	server.Config.WriteTimeout = 60 * time.Second
	server.Start()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 35 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	initial := hashBrowserTargets(t, browser)
	for _, fontName := range []string{"Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple"} {
		t.Run(fontName, func(t *testing.T) {
			p := hashTestMeasurePlan()
			p.Font = fontName
			p.Text = "Start" + strings.Repeat("Åb", 95) + "SlutZ"
			p.WidthPoints, p.HeightPoints = "1000", "600"
			p.Targets = append(p.Targets, hashMeasureTarget{ID: "22222222-2222-4222-8222-222222222222", X: ".05", Y: ".5", W: ".8", H: ".45"})
			fontPin, _ := hashPinnedMeasureFont(fontName)
			font, err := os.ReadFile(filepath.Join("/tmp/hash-fit-inputs", fontPin.file))
			if err != nil {
				t.Fatal("pinned font fixture unavailable")
			}
			raw, err := json.Marshal(hashSignaturePDFRequest{Schema: 1, Plan: *p, FontBytes: font})
			if err != nil || len(raw) > hashSignaturePDFRequestLimit {
				t.Fatal("bounded canonical request")
			}
			r, err := http.NewRequest(http.MethodPost, server.URL+hashSignaturePDFRoutePath, bytes.NewReader(raw))
			if err != nil {
				t.Fatal("private HTTP request")
			}
			r.Header.Set("Authorization", "Bearer "+hashRouteTestToken)
			r.Header.Set("Content-Type", "application/json")
			response, err := client.Do(r)
			if err != nil {
				t.Fatal("private HTTP conversion unavailable")
			}
			limit := int64(hashSignaturePackageHeader + hashSignatureReportLimit + hashSignaturePDFLimit + hashSignatureHTMLLimit + hashSignatureFontLimit + hashSignatureSnapshotLimit)
			body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != hashSignaturePDFRouteMIME || response.Header.Get("Cache-Control") != "no-store" || int64(len(body)) > limit || response.ContentLength != int64(len(body)) {
				t.Fatal("exact HTTP response unavailable")
			}
			if hashBrowserTargets(t, browser) != initial {
				t.Fatal("HTTP output preceded owned target cleanup")
			}
			decoded, err := decodeHashSignaturePDFPackage(body, p)
			if err != nil {
				t.Fatal("HTTP package binding invalid")
			}
			var report hashSignaturePDFReport
			if json.Unmarshal(decoded.Report(), &report) != nil || report.InputSHA256 != p.inputSHA() || report.FontSHA256 != fontPin.sha || len(report.Measurement.DOM.Targets) != len(p.Targets) {
				t.Fatal("all-target HTTP report binding")
			}
			for i, target := range report.Measurement.DOM.Targets {
				text := ""
				for _, line := range target.Lines {
					text += line.Text + line.HardBreak
				}
				if target.ID != p.Targets[i].ID || text != p.Text {
					t.Fatal("HTTP signature target/text incomplete")
				}
			}
		})
	}
}
