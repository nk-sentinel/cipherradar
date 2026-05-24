package yarax

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// YARA-X JSON output shape (verified against yara-x-cli 1.14.0 by running
// `yr scan --output-format json --print-strings --print-meta --print-namespace
// --print-tags <rules> <target>`):
//
//	{
//	  "version": "1.14.0",
//	  "matches": [
//	    {
//	      "rule": "probe_openssl_3_0",
//	      "file": "/path/to/openssl-versions",
//	      "meta":      { "description": "...", "author": "..." },  // when --print-meta
//	      "tags":      [],                                         // when --print-tags
//	      "strings":   [ { "identifier": "$a",
//	                       "offset":     8222,
//	                       "match":      "OpenSSL 3.0" } ]         // when --print-strings
//	    }
//	  ]
//	}
//
// Without the `--print-*` flags, each per-match object collapses to just
// `rule` + `file`. Sub-PR A only requests `--output-format json` (no
// `--print-*` flags) to keep the wire format minimal and the parser
// resilient — the richer metadata vocabulary (cbom_primitive etc.) lands
// in Sub-PR B alongside the embedded ruleset.
//
// Pass attribution: every finding produced here carries Pass=3 so the
// `--passes` filter Sub-PR C introduces can route Pass-3 results
// correctly without re-tagging.

// yaraxOutput is the top-level JSON object yr emits in `--output-format
// json` mode. The `version` field is captured for future diagnostics but
// is otherwise unused.
type yaraxOutput struct {
	Version string       `json:"version"`
	Matches []yaraxMatch `json:"matches"`
}

// yaraxMatch is a single rule-against-file match. `file` is YARA-X's
// echo of the target path passed on the command line. When we invoke
// `yr scan` with a single target file, all matches share the same
// `file` value; we fall back to the runner-provided target when an
// individual match omits it (defensive — present in current 1.14.0
// output).
type yaraxMatch struct {
	Rule    string         `json:"rule"`
	File    string         `json:"file"`
	Meta    map[string]any `json:"meta,omitempty"`
	Tags    []string       `json:"tags,omitempty"`
	Strings []yaraxString  `json:"strings,omitempty"`
}

// yaraxString is one of the per-rule string matches surfaced when the
// caller passes `--print-strings`. Sub-PR A doesn't request that flag,
// so the slice is empty in production output — but the parser handles
// it when present so test fixtures can exercise the offset/snippet
// pathway end-to-end.
type yaraxString struct {
	Identifier string `json:"identifier"`
	Offset     int    `json:"offset"`
	Match      string `json:"match"`
}

// ParseResults converts YARA-X JSON output into CipherRadar findings.
// All returned findings have Pass=3. The fallbackTarget argument is the
// path the runner asked YARA-X to scan; it populates the location's
// File field when a match omits its own `file` (defensive — keeps the
// path always populated).
//
// Empty input or `matches == []` returns (nil, nil) — no error, no
// findings. This matches the OpenGrep parser's "0 results is fine"
// stance for the happy path.
func ParseResults(jsonData []byte, fallbackTarget string) ([]types.Finding, error) {
	trimmed := bytes.TrimSpace(jsonData)
	if len(trimmed) == 0 {
		return nil, nil
	}

	var out yaraxOutput
	if err := json.Unmarshal(trimmed, &out); err != nil {
		return nil, fmt.Errorf("invalid yara-x JSON: %w", err)
	}
	if len(out.Matches) == 0 {
		return nil, nil
	}

	findings := make([]types.Finding, 0, len(out.Matches))
	for _, m := range out.Matches {
		filePath := m.File
		if filePath == "" {
			filePath = fallbackTarget
		}
		f := types.Finding{
			RuleID:      m.Rule,
			Pass:        3,
			AssetType:   types.AssetAlgorithm,
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidenceMedium,
			Name:        m.Rule,
			Description: describeMatch(m),
			Location:    locationFromMatch(filePath, m),
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// describeMatch builds the human-readable Description for a Pass-3
// finding. Sub-PR A keeps this minimal because the rule metadata
// vocabulary (cbom_primitive, cbom_asset_type, ...) lands in Sub-PR B —
// once that ships, `meta.description` becomes the preferred source and
// this helper grows a precedence chain.
func describeMatch(m yaraxMatch) string {
	if desc, ok := metaString(m.Meta, "description"); ok && desc != "" {
		return desc
	}
	return fmt.Sprintf("YARA-X rule %q matched", m.Rule)
}

// metaString looks up a string-valued key in YARA-X's `meta` map. YARA
// metadata values can be strings, integers, or booleans; the JSON
// decoder gives us `any`, so we narrow here to keep call sites
// straight-line.
func metaString(meta map[string]any, key string) (string, bool) {
	if meta == nil {
		return "", false
	}
	v, ok := meta[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return s, true
}

// locationFromMatch builds a types.Location for a YARA-X match. Binaries
// have no meaningful line numbers, so we mirror the native binary
// scanner's convention: encode the byte offset of the first matched
// string in StartCol. When `--print-strings` wasn't requested (Sub-PR A
// default), the strings slice is empty and the offset degrades to 0 —
// still a valid location, just less precise.
func locationFromMatch(filePath string, m yaraxMatch) types.Location {
	offset := 0
	snippet := fmt.Sprintf("[binary] yara-x match: %s", m.Rule)
	if len(m.Strings) > 0 {
		first := m.Strings[0]
		offset = first.Offset
		snippet = fmt.Sprintf("[binary] %s %s at offset 0x%x", m.Rule, first.Identifier, offset)
	}
	return types.Location{
		File:      filePath,
		StartLine: 0,
		StartCol:  offset,
		EndLine:   0,
		EndCol:    offset,
		Snippet:   snippet,
	}
}
