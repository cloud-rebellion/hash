// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package catalog

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"hash/crc32"
	"image/png"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/bright-interaction/hash/internal/imageguard"
)

type preparedAssetV1 struct {
	original, render                         []byte
	width, height, renderWidth, renderHeight int32
	method                                   string
}

func decodeAssetV1(in AssetUploadV1) (preparedAssetV1, error) {
	var p preparedAssetV1
	if !textV1(in.Name, 160, true) || in.RequestID == [16]byte{} || in.ExpectedRevision < 0 || len(in.OriginalBase64) > base64.StdEncoding.EncodedLen(MaxOriginalBytesV1) || len(in.RenderPNGBase64) > base64.StdEncoding.EncodedLen(MaxRenderBytesV1) {
		return p, ErrInputV1
	}
	var err error
	p.original, err = base64.StdEncoding.Strict().DecodeString(in.OriginalBase64)
	if err != nil || len(p.original) < 1 || len(p.original) > MaxOriginalBytesV1 {
		return p, ErrInputV1
	}
	if in.RenderPNGBase64 != "" {
		p.render, err = base64.StdEncoding.Strict().DecodeString(in.RenderPNGBase64)
		if err != nil || len(p.render) < 1 || len(p.render) > MaxRenderBytesV1 {
			return p, ErrInputV1
		}
		p.method = "provided_png_v1"
	} else if in.MediaType == "image/png" && len(p.original) <= MaxRenderBytesV1 {
		p.render = p.original
		p.method = "original_png_v1"
	} else {
		return p, ErrInputV1
	}
	return p, nil
}
func validateAssetV1(ctx context.Context, in AssetUploadV1, p *preparedAssetV1) error {
	var err error
	switch in.MediaType {
	case "image/png":
		p.width, p.height, err = validateOriginalPNGV1(ctx, p.original)
	case "image/svg+xml":
		p.width, p.height, err = validateOriginalSVGV1(p.original)
	default:
		return ErrInputV1
	}
	if err != nil {
		return err
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(p.render))
	if err != nil {
		return ErrInputV1
	}
	if _, err = imageguard.Decode(bytes.NewReader(p.render), "png"); err != nil {
		return ErrInputV1
	}
	p.renderWidth, p.renderHeight = int32(cfg.Width), int32(cfg.Height)
	return ctx.Err()
}

type contextReaderV1 struct {
	context.Context
	io.Reader
}

func (r contextReaderV1) Read(b []byte) (int, error) {
	if e := r.Context.Err(); e != nil {
		return 0, e
	}
	return r.Reader.Read(b)
}

// Originals may exceed render dimensions. Validate PNG container CRCs and the
// bounded compressed stream without allocating a full original pixel buffer.
// Only the separately decoded <=4M pixel PNG is ever used by a renderer.
func validateOriginalPNGV1(ctx context.Context, raw []byte) (int32, int32, error) {
	if len(raw) < 33 || !bytes.Equal(raw[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
		return 0, 0, ErrInputV1
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 16384 || cfg.Height > 16384 || int64(cfg.Width)*int64(cfg.Height) > 16<<20 {
		return 0, 0, ErrInputV1
	}
	pos := 8
	chunks := 0
	seenHeader, ended := false, false
	var compressed []io.Reader
	for pos < len(raw) {
		if ctx.Err() != nil {
			return 0, 0, ctx.Err()
		}
		if len(raw)-pos < 12 {
			return 0, 0, ErrInputV1
		}
		n := int(binary.BigEndian.Uint32(raw[pos:]))
		if n > len(raw)-pos-12 {
			return 0, 0, ErrInputV1
		}
		kind := string(raw[pos+4 : pos+8])
		body := raw[pos+8 : pos+8+n]
		want := binary.BigEndian.Uint32(raw[pos+8+n:])
		if crc32.ChecksumIEEE(raw[pos+4:pos+8+n]) != want {
			return 0, 0, ErrInputV1
		}
		chunks++
		if chunks > 16384 {
			return 0, 0, ErrInputV1
		}
		switch kind {
		case "IHDR":
			if seenHeader || pos != 8 || n != 13 {
				return 0, 0, ErrInputV1
			}
			seenHeader = true
		case "IDAT":
			compressed = append(compressed, bytes.NewReader(body))
		case "IEND":
			if n != 0 || pos+12 != len(raw) {
				return 0, 0, ErrInputV1
			}
			ended = true
		case "acTL", "fcTL", "fdAT":
			return 0, 0, ErrInputV1
		}
		pos += 12 + n
	}
	if !ended || len(compressed) == 0 {
		return 0, 0, ErrInputV1
	}
	z, err := zlib.NewReader(io.MultiReader(compressed...))
	if err != nil {
		return 0, 0, ErrInputV1
	}
	defer z.Close()
	limit := int64(cfg.Width)*int64(cfg.Height)*8 + int64(cfg.Height)*8 + 1024
	n, err := io.Copy(io.Discard, io.LimitReader(contextReaderV1{ctx, z}, limit+1))
	if err != nil || n > limit || n == 0 {
		return 0, 0, ErrInputV1
	}
	return int32(cfg.Width), int32(cfg.Height), nil
}

// Accepted SVGs are inert, well-formed vector originals. They are downloaded
// as attachments, never inserted into HTML or fetched by a renderer. Unknown
// elements/attributes, active content and external resources are refused rather
// than silently stripping and changing the original bytes.
func validateOriginalSVGV1(raw []byte) (int32, int32, error) {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return 0, 0, ErrInputV1
	}
	tags := map[string]bool{"svg": true, "g": true, "path": true, "rect": true, "circle": true, "ellipse": true, "line": true, "polyline": true, "polygon": true, "defs": true, "clipPath": true, "mask": true, "linearGradient": true, "radialGradient": true, "stop": true, "title": true, "desc": true}
	attrs := map[string]bool{}
	for _, s := range strings.Fields("id xmlns viewBox width height x y x1 y1 x2 y2 cx cy r rx ry d points fill fill-rule fill-opacity stroke stroke-width stroke-linecap stroke-linejoin stroke-miterlimit stroke-dasharray stroke-dashoffset stroke-opacity opacity transform clip-path clip-rule mask offset stop-color stop-opacity gradientUnits gradientTransform spreadMethod fx fy preserveAspectRatio vector-effect role aria-label aria-labelledby aria-describedby aria-hidden") {
		attrs[s] = true
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = true
	nodes, depth := 0, 0
	root, prolog := false, false
	var width, height float64
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return 0, 0, ErrInputV1
		}
		switch x := t.(type) {
		case xml.Directive:
			return 0, 0, ErrInputV1
		case xml.ProcInst:
			if x.Target != "xml" || root || prolog || depth != 0 || len(x.Inst) > 256 {
				return 0, 0, ErrInputV1
			}
			prolog = true
		case xml.StartElement:
			nodes++
			depth++
			if nodes > 8192 || depth > 32 || !tags[x.Name.Local] || x.Name.Space != "" && x.Name.Space != "http://www.w3.org/2000/svg" || len(x.Attr) > 48 {
				return 0, 0, ErrInputV1
			}
			if !root {
				if x.Name.Local != "svg" {
					return 0, 0, ErrInputV1
				}
				root = true
			} else if depth == 1 || x.Name.Local == "svg" {
				return 0, 0, ErrInputV1
			}
			seen := map[string]bool{}
			for _, a := range x.Attr {
				if seen[a.Name.Local] || !attrs[a.Name.Local] || a.Name.Space != "" && a.Name.Space != "xmlns" || len(a.Value) > 256<<10 {
					return 0, 0, ErrInputV1
				}
				seen[a.Name.Local] = true
				lower := strings.ToLower(a.Value)
				if strings.ContainsAny(a.Value, "<>") || strings.Contains(lower, "javascript:") || strings.Contains(lower, "data:") || strings.Contains(lower, "http:") && a.Name.Local != "xmlns" || strings.Contains(lower, "https:") {
					return 0, 0, ErrInputV1
				}
				if strings.Contains(lower, "url(") && !(strings.HasPrefix(a.Value, "url(#") && strings.HasSuffix(a.Value, ")") && tokenV1.MatchString(a.Value[5:len(a.Value)-1])) {
					return 0, 0, ErrInputV1
				}
				if depth == 1 && a.Name.Local == "viewBox" {
					parts := strings.Fields(strings.ReplaceAll(a.Value, ",", " "))
					if len(parts) != 4 {
						return 0, 0, ErrInputV1
					}
					for _, v := range parts {
						n, e := strconv.ParseFloat(v, 64)
						if e != nil || math.IsNaN(n) || math.IsInf(n, 0) {
							return 0, 0, ErrInputV1
						}
					}
					width, _ = strconv.ParseFloat(parts[2], 64)
					height, _ = strconv.ParseFloat(parts[3], 64)
				}
				if depth == 1 && (a.Name.Local == "width" || a.Name.Local == "height") {
					n, e := strconv.ParseFloat(strings.TrimSuffix(a.Value, "px"), 64)
					if e == nil {
						if a.Name.Local == "width" {
							width = n
						} else {
							height = n
						}
					}
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(x)) != "" {
				return 0, 0, ErrInputV1
			}
		}
	}
	if !root || depth != 0 || !finiteBetweenV1(width, 1, 16384) || !finiteBetweenV1(height, 1, 16384) {
		return 0, 0, ErrInputV1
	}
	return int32(math.Ceil(width)), int32(math.Ceil(height)), nil
}
