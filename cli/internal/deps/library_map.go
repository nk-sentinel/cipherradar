package deps

import (
	"regexp"
	"strings"
)

// libTarget maps a logical crypto library to a concrete ecosystem package.
// stdlib targets carry no package (no purl is generated for them). snippet, when
// set, disambiguates between candidates that share an ecosystem by matching the
// import line in the finding.
type libTarget struct {
	eco     Ecosystem
	pkg     string
	group   string // Maven groupId
	stdlib  bool
	snippet *regexp.Regexp
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile("(?i)" + s) }

// libTargets maps a coarse cbom-library candidate (or a Java provider class
// name) to one or more concrete package targets. Keys are lowercased.
var libTargets = map[string][]libTarget{
	// Python
	"pyca-cryptography": {{eco: EcosystemPyPI, pkg: "cryptography", snippet: rx(`cryptography`)}},
	"cryptography":      {{eco: EcosystemPyPI, pkg: "cryptography", snippet: rx(`cryptography`)}},
	"pycryptodome":      {{eco: EcosystemPyPI, pkg: "pycryptodome", snippet: rx(`Crypto\.|Cryptodome`)}},
	"pynacl":            {{eco: EcosystemPyPI, pkg: "pynacl", snippet: rx(`nacl`)}},
	"hashlib":           {{stdlib: true}},
	"hmac":              {{stdlib: true}},
	"ssl":               {{stdlib: true}},

	// JavaScript / npm
	"node-forge":   {{eco: EcosystemNPM, pkg: "node-forge", snippet: rx(`forge`)}},
	"forge":        {{eco: EcosystemNPM, pkg: "node-forge", snippet: rx(`forge`)}},
	"jwt":          {{eco: EcosystemNPM, pkg: "jsonwebtoken", snippet: rx(`jsonwebtoken|jwt`)}},
	"jsonwebtoken": {{eco: EcosystemNPM, pkg: "jsonwebtoken", snippet: rx(`jsonwebtoken|jwt`)}},
	// bcrypt exists as both an npm package and a Ruby gem; the project's
	// manifest disambiguates which one is actually present.
	"bcrypt":        {{eco: EcosystemNPM, pkg: "bcrypt", snippet: rx(`bcrypt`)}, {eco: EcosystemGem, pkg: "bcrypt", snippet: rx(`bcrypt`)}},
	"argon2":        {{eco: EcosystemNPM, pkg: "argon2", snippet: rx(`argon2`)}},
	"crypto-js":     {{eco: EcosystemNPM, pkg: "crypto-js", snippet: rx(`crypto-js`)}},
	"nodejs-crypto": {{stdlib: true}},
	"webcrypto":     {{stdlib: true}},

	// Java / Maven
	"bouncycastle":         {{eco: EcosystemMaven, pkg: "bcprov-jdk18on", group: "org.bouncycastle", snippet: rx(`bouncycastle|org\.bouncycastle|\bbc`)}},
	"bouncycastleprovider": {{eco: EcosystemMaven, pkg: "bcprov-jdk18on", group: "org.bouncycastle"}},
	"jca":                  {{stdlib: true}},

	// Rust / Cargo
	"ring":    {{eco: EcosystemCargo, pkg: "ring", snippet: rx(`ring`)}},
	"rustls":  {{eco: EcosystemCargo, pkg: "rustls", snippet: rx(`rustls`)}},
	"openssl": {{eco: EcosystemCargo, pkg: "openssl", snippet: rx(`openssl`)}},

	// Ruby / RubyGems: openssl + digest are stdlib (no purl); bcrypt handled above.
	"digest": {{stdlib: true}},

	// Python additional
	"pycrypto": {{eco: EcosystemPyPI, pkg: "pycryptodome", snippet: rx(`Crypto\.|Cryptodome`)}},

	// Go: the standard library's crypto/* — no purl.
	"go-crypto": {{stdlib: true}},

	// Dart / pub.dev (both are real pub packages, not stdlib).
	"pointycastle": {{eco: EcosystemPub, pkg: "pointycastle", snippet: rx(`pointycastle`)}},
	"dart-crypto":  {{eco: EcosystemPub, pkg: "crypto", snippet: rx(`crypto`)}},

	// PHP mcrypt extension; name surfaced, no purl.
	"mcrypt": {{}},
}

// expandCandidates splits a coarse cbom-library token (e.g.
// "pyca-cryptography-or-hashlib-or-pynacl") into lowercased candidate names.
func expandCandidates(token string) []string {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return nil
	}
	parts := strings.Split(token, "-or-")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ResolveLibrary maps a finding's coarse cbom-library token to a concrete
// package, using the import snippet to disambiguate and the project Index to pin
// a version. Returns ok=false for stdlib-only or unresolvable tokens.
//
// Resolution order: expand candidates → map to targets → snippet-disambiguate →
// confirm against the nearest manifest (yields a version) → else, if a single
// unambiguous concrete package, return it without a version.
func ResolveLibrary(ix *Index, libToken, snippet, fromFile string) (Package, bool) {
	var targets []libTarget
	for _, c := range expandCandidates(libToken) {
		targets = append(targets, libTargets[c]...)
	}
	if len(targets) == 0 {
		return Package{}, false
	}

	// Snippet disambiguation when multiple candidates remain.
	if len(targets) > 1 && snippet != "" {
		var matched []libTarget
		for _, t := range targets {
			if t.snippet != nil && t.snippet.MatchString(snippet) {
				matched = append(matched, t)
			}
		}
		if len(matched) > 0 {
			targets = matched
		}
	}

	// Index confirmation — the manifest both disambiguates and supplies a version.
	// Pass 1 prefers a manifest that is an ancestor of the finding's file, so a
	// package name present in multiple ecosystems (e.g. bcrypt = npm + gem)
	// resolves to the one matching the file's own project. Pass 2 allows the
	// cross-tree fallback.
	if ix != nil && !ix.Empty() {
		for _, t := range targets {
			if t.stdlib || t.pkg == "" {
				continue
			}
			if p, ok := ix.ResolveAncestor(t.eco, t.pkg, fromFile); ok {
				if p.Group == "" {
					p.Group = t.group
				}
				return p, true
			}
		}
		for _, t := range targets {
			if t.stdlib || t.pkg == "" {
				continue
			}
			if p, ok := ix.Resolve(t.eco, t.pkg, fromFile); ok {
				if p.Group == "" {
					p.Group = t.group
				}
				return p, true
			}
		}
	}

	// No manifest match — return a version-less package only if exactly one
	// concrete (non-stdlib) candidate identity remains.
	var concrete []libTarget
	for _, t := range targets {
		if !t.stdlib && t.pkg != "" {
			concrete = append(concrete, t)
		}
	}
	if len(concrete) == 1 {
		t := concrete[0]
		return Package{Ecosystem: t.eco, Name: t.pkg, Group: t.group}, true
	}
	return Package{}, false
}
