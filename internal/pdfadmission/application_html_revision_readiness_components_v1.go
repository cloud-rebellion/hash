// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"mime"
	"net/mail"
	"reflect"
	"unsafe"

	"github.com/bright-interaction/hash/internal/htmlmaster"
)

// Logical expression components for ONE unchanged ContractReadiness call.
// This is neither a validation receipt nor a work grant. The private native
// source owner supplies its actual immutable compiled Master/Input projections
// and retains the original input backing while these result aliases are live.
// parentBytes includes retainedResultBytes; do not add the latter twice.
// Allocator/GC/pool/unique.Make retention and process RSS are separate gates.
type htmlRevisionContractReadinessComponentsV1 struct {
	parentBytes         int64
	retainedResultBytes int64
	mailBytes           int64
	profileJSONBytes    int64
}

// Mirrors describe only fixed typed local state in pinned Go1.26.9 fmt. They
// do not inspect a runtime object, price preexisting pooled capacity, or give
// cleanup/retirement authority. Dynamic formatting buffers are separate below.
type htmlRevisionReadinessFmtV1 struct {
	buf              *[]byte
	flags            [9]bool
	width, precision int
	integer          [68]byte
}
type htmlRevisionReadinessPrinterV1 struct {
	buf     []byte
	arg     any
	value   reflect.Value
	format  htmlRevisionReadinessFmtV1
	flags   [5]bool
	wrapped []int
}

func htmlRevisionReadinessAddV1(total *int64, count, size int64) bool {
	return htmlInputAddV1(total, count, size)
}

// Each append/builder family below includes old/current logical buffers. The
// finite mail input is <=254 bytes; byte-consuming loops progress, groups do
// not nest, and only consumeAddrSpec restores a failed prefix. At most two
// addr-spec attempts and one phrase/comment route occur per address. Four
// (N+1) invocations OF EACH family therefore covers all prefixes, group members,
// failed attempts and terminal errors, including ignored invalid MIME words.
// This deliberately sums expression families instead of asserting one pass.
func htmlRevisionReadinessMailBytesV1(n int64) (int64, error) {
	if n < 0 || n > 254 {
		return 0, ErrHTMLAuthoringInputV1
	}
	visits := 4 * (n + 1)
	per := int64(0)
	add := func(count, size int64) bool { return htmlRevisionReadinessAddV1(&per, count, size) }
	// consumeQuotedString: initial ten runes, grown old/current rune arrays and
	// its conversion; UTF-8 output cannot exceed four bytes per input rune.
	if !add(2*n+10, 4) || !add(1, 4*n) {
		return 0, ErrHTMLAuthoringInputV1
	}
	// consumeComment and the MIME-encoded run Builder (three-byte ASCII
	// replacement is the largest supported charset expansion).
	if !add(1, 4*n+16) || !add(1, 12*n+16) {
		return 0, ErrHTMLAuthoringInputV1
	}
	// Phrase words may append twice per consumed word. Eight slots per input
	// byte includes these appends and all old/current geometrically grown arrays.
	if !add(8*(n+1), 16) || !add(1, 4*n+1) {
		return 0, ErrHTMLAuthoringInputV1
	}
	// FieldsFunc's initial32 span slots are explicit, as are its grown spans,
	// returned string headers and the decoded display-name Join.
	if !add(32+8*(n+1), 16) || !add(8*(n+1), 16) || !add(1, 4*n+1) {
		return 0, ErrHTMLAuthoringInputV1
	}
	// DecodeString source copy/output, Q output, lowercase charset, conversion
	// Builder and bytes.Reader. The default mail CharsetReader always errors:
	// no arbitrary decoder or io.Copy reader is reachable through ParseAddress.
	if !add(3, n) || !add(1, 4*n) || !add(1, 12*n+16) || !add(1, int64(unsafe.Sizeof(bytes.Reader{}))) || !add(2, int64(unsafe.Sizeof(mime.WordDecoder{}))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	// Address spec/domain strings and group/address slice/model construction.
	if !add(1, 8*n+8) || !add(8*(n+1), int64(unsafe.Sizeof((*mail.Address)(nil)))) || !add(1, int64(unsafe.Sizeof(mail.Address{}))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	// All reachable mail/MIME formats use only fixed diagnostics, a byte/rune,
	// or bounded input/charset text. %q is <=6*N+2. Two nested printers suffice
	// (charsetError.Error inside an outer missing-word error). Four output
	// buffers include builders/returned strings across that nesting. The fixed
	// diagnostic component is a sum of the longest reachable fixed prefixes,
	// quotes and the decimal/hex integer scratch width, not an arbitrary floor.
	diagnostic := int64(len("mail: invalid utf-8 in quoted-string: ") + len("mail: missing word in phrase: ") + len("charset not supported: ") + len("mime: invalid hex byte ") + 2 + 20)
	formatted := 6*n + diagnostic
	if !add(4, formatted) || !add(2, int64(unsafe.Sizeof(htmlRevisionReadinessPrinterV1{}))) || !add(2*8, 8) {
		return 0, ErrHTMLAuthoringInputV1
	}
	// addrParser + saved prefix, decoder closure, error interfaces, parseAddrError
	// three string headers, IPv6 bytes/zone view and a possible unique zone copy.
	// A zone intern can outlive the call: no immediate physical refund is claimed.
	if !add(2, 24) || !add(1, 16) || !add(4, 16) || !add(3, 16) || !add(1, 16+24+16) || !add(1, n) {
		return 0, ErrHTMLAuthoringInputV1
	}
	total := int64(0)
	if !htmlRevisionReadinessAddV1(&total, visits, per) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return total, nil
}

// The caller must use an actual already compiled Master. These checks make
// existing finite profile topology/ASCII name assumptions explicit without
// invoking Compile, CanonicalTemplate, ContractReadiness or json.Marshal.
func htmlRevisionReadinessProfileShapeV1(p *htmlmaster.ContractProfile) bool {
	if p == nil {
		return true
	}
	name := func(s string) bool {
		if len(s) == 0 || len(s) > 64 {
			return false
		}
		for i := range len(s) {
			b := s[i]
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_') {
				return false
			}
		}
		return true
	}
	if !htmlmaster.AmendmentPolicyShapeV1(p.AmendmentPolicy) {
		return false
	}
	if !name(p.ID) || p.Version < 1 || p.Version > 1000000 || (p.Kind != "proposal" && p.Kind != "b2b_services") || len(p.Parties) != 2 || len(p.Terms) > 16 {
		return false
	}
	for _, v := range p.Parties {
		if v.Slot != "provider" && v.Slot != "customer" {
			return false
		}
		for _, s := range [...]string{v.CompanyName, v.CompanyID, v.RepresentativeName, v.RepresentativeEmail, v.RepresentativeAuthority} {
			if !name(s) {
				return false
			}
		}
	}
	for _, v := range p.Terms {
		if !name(v.Name) || (v.Value == "") == (v.Section == "") {
			return false
		}
		if v.Value != "" && !name(v.Value) || v.Section != "" && !name(v.Section) {
			return false
		}
	}
	return true
}

func htmlRevisionContractReadinessComponentsForV1(master htmlmaster.Master, input htmlmaster.Input) (htmlRevisionContractReadinessComponentsV1, error) {
	var out htmlRevisionContractReadinessComponentsV1
	if !htmlAuthoringInputRuntimeOKV1 || !htmlRevisionReadinessProfileShapeV1(master.ContractProfile) {
		return out, ErrHTMLAuthoringInputV1
	}
	total := int64(0)
	add := func(count, size int64) bool { return htmlRevisionReadinessAddV1(&total, count, size) }
	// validateValues(false)/validateSections only scan existing string storage.
	// Their possible error embeds at most one known compiled name (64 bytes).
	// Unknown names use a fixed diagnostic; values are never interpolated.
	early := int64(len("section text: ") + 64 + len("HTML master exceeds limits: ") + len("invalid HTML master: "))
	if !add(2, early) || !add(2, int64(unsafe.Sizeof(htmlRevisionReadinessPrinterV1{}))) || !add(2, 16) {
		return out, ErrHTMLAuthoringInputV1
	}
	if master.ContractProfile == nil {
		out.parentBytes = total
		return out, nil
	}
	// Exact validated typed profile ceiling3493 includes id64, version1000000,
	// kind b2b_services, two parties with five64-byte binding names and16 terms
	// with64-byte names+one64-byte target. All characters are unescaped ASCII.
	profileJSON := int64(3493)
	if p := master.ContractProfile.AmendmentPolicy; p != nil {
		// Canonical declaration keys/commas plus maximal JSON escaping of actual
		// quoted strings; the fixed lists contain at most four known ASCII names.
		profileJSON += 256 + 6*int64(len(p.Term)+len(p.ClauseReference)+len(p.EffectiveCondition))
		for _, m := range p.AllowedModes {
			profileJSON += 6*int64(len(m)) + 3
		}
		for _, c := range p.AllowedChannels {
			profileJSON += 6*int64(len(c)) + 3
		}
		// Presented policy projection: one returned value, its clone and bounded
		// array copies; immutable clause strings alias the owned original source.
		if !add(2, int64(unsafe.Sizeof(htmlmaster.AmendmentPolicyV1{}))) || !add(1, int64(unsafe.Sizeof(htmlmaster.PresentedAmendmentPolicyV1{}))) || !add(8, 16) || !add(2, 256) {
			return out, ErrHTMLAuthoringInputV1
		}
	}
	out.profileJSONBytes = profileJSON
	// json.Marshal's logical geometrically grown encode buffers, returned copy; SHA256
	// Digest120, block/hash/hex outputs and the fixed domain string conversion.
	if !add(4, profileJSON) || !add(1, profileJSON) || !add(1, 120) || !add(1, 32) || !add(2, 64) || !add(2, int64(len("hash.contract-profile.v1")+1)) || !add(1, int64(unsafe.Sizeof(struct {
		buffer   bytes.Buffer
		ptrLevel uint
		ptrSeen  map[any]struct{}
	}{}))) || !add(1, 48) {
		return out, ErrHTMLAuthoringInputV1
	}
	// Output party strings alias immutable input; no input text is silently
	// cloned or refunded here. Count all party/issue backing arrays and paths,
	// including empty/incomplete profiles, with old/current append storage.
	message := int64(len("Signing page requires a single printable line of at most ") + 3 + len(" characters and display units; wide characters use two units. Controls and outer whitespace are unavailable."))
	retained := int64(0)
	for _, part := range [][2]int64{{1, int64(unsafe.Sizeof(htmlmaster.ContractReadiness{}))}, {4, int64(unsafe.Sizeof(htmlmaster.ContractPartyValues{}))}, {64, int64(unsafe.Sizeof(htmlmaster.ContractIssue{}))}, {32, 70}, {10, message}, {2, int64(len("parties.") + len("customer") + len("."))}, {1, 64}} {
		if !htmlRevisionReadinessAddV1(&retained, part[0], part[1]) {
			return out, ErrHTMLAuthoringInputV1
		}
	}
	if !add(1, retained) || !add(10, int64(unsafe.Sizeof(htmlRevisionReadinessPrinterV1{}))) || !add(10, 2*message) {
		return out, ErrHTMLAuthoringInputV1
	}
	// requireContractComplete's optional failure projection remains live beside
	// readiness:32 path headers, Join separators/text, wrapped error output.
	incomplete := int64(32*70 + 31*len(", "))
	if !add(32, 16) || !add(2, incomplete) || !add(1, incomplete+int64(len("reviewed contract profile is incomplete or conflicting: "))) || !add(1, int64(unsafe.Sizeof(htmlRevisionReadinessPrinterV1{}))) || !add(2, 16) {
		return out, ErrHTMLAuthoringInputV1
	}
	for _, party := range master.ContractProfile.Parties {
		email := input.Values[party.RepresentativeEmail]
		// The original function refuses >254 before ParseAddress; whitespace and
		// controls can refuse even earlier, so pricing them is conservative.
		if len(email) > 254 {
			continue
		}
		mailBytes, err := htmlRevisionReadinessMailBytesV1(int64(len(email)))
		if err != nil || !htmlRevisionReadinessAddV1(&out.mailBytes, 1, mailBytes) {
			return out, ErrHTMLAuthoringInputV1
		}
	}
	if !add(1, out.mailBytes) {
		return out, ErrHTMLAuthoringInputV1
	}
	out.parentBytes = total
	out.retainedResultBytes = retained
	return out, nil
}
