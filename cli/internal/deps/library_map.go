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
	"passlib":           {{eco: EcosystemPyPI, pkg: "passlib", snippet: rx(`passlib`)}},
	"pyjwt":             {{eco: EcosystemPyPI, pkg: "pyjwt", snippet: rx(`jwt`)}},
	"python-jose":       {{eco: EcosystemPyPI, pkg: "python-jose", snippet: rx(`jose`)}},
	"authlib":           {{eco: EcosystemPyPI, pkg: "authlib", snippet: rx(`authlib`)}},
	"bcrypt-py":         {{eco: EcosystemPyPI, pkg: "bcrypt", snippet: rx(`bcrypt`)}},
	"argon2-cffi":       {{eco: EcosystemPyPI, pkg: "argon2-cffi", snippet: rx(`argon2`)}},
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
	"bcrypt":             {{eco: EcosystemNPM, pkg: "bcrypt", snippet: rx(`bcrypt`)}, {eco: EcosystemGem, pkg: "bcrypt", snippet: rx(`bcrypt`)}},
	"argon2":             {{eco: EcosystemNPM, pkg: "argon2", snippet: rx(`argon2`)}},
	"crypto-js":          {{eco: EcosystemNPM, pkg: "crypto-js", snippet: rx(`crypto-js`)}},
	"jose":               {{eco: EcosystemNPM, pkg: "jose", snippet: rx(`jose`)}},
	"noble-hashes":       {{eco: EcosystemNPM, pkg: "@noble/hashes", snippet: rx(`@noble/hashes`)}},
	"noble-curves":       {{eco: EcosystemNPM, pkg: "@noble/curves", snippet: rx(`@noble/curves`)}},
	"noble-ciphers":      {{eco: EcosystemNPM, pkg: "@noble/ciphers", snippet: rx(`@noble/ciphers`)}},
	"libsodium-wrappers": {{eco: EcosystemNPM, pkg: "libsodium-wrappers", snippet: rx(`libsodium-wrappers`)}},
	"sodium-native":      {{eco: EcosystemNPM, pkg: "sodium-native", snippet: rx(`sodium-native`)}},
	"nodejs-crypto":      {{stdlib: true}},
	"webcrypto":          {{stdlib: true}},

	// Java / Maven
	"bouncycastle":         {{eco: EcosystemMaven, pkg: "bcprov-jdk18on", group: "org.bouncycastle", snippet: rx(`bouncycastle|org\.bouncycastle|\bbc`)}},
	"bouncycastleprovider": {{eco: EcosystemMaven, pkg: "bcprov-jdk18on", group: "org.bouncycastle"}},
	"spring-security-crypto": {{
		eco: EcosystemMaven, pkg: "spring-security-crypto", group: "org.springframework.security",
		snippet: rx(`springframework\.security\.crypto`),
	}},
	"jjwt": {
		{eco: EcosystemMaven, pkg: "jjwt-api", group: "io.jsonwebtoken", snippet: rx(`io\.jsonwebtoken`)},
		{eco: EcosystemMaven, pkg: "jjwt-impl", group: "io.jsonwebtoken", snippet: rx(`io\.jsonwebtoken`)},
		{eco: EcosystemMaven, pkg: "jjwt-jackson", group: "io.jsonwebtoken", snippet: rx(`io\.jsonwebtoken`)},
		{eco: EcosystemMaven, pkg: "jjwt-gson", group: "io.jsonwebtoken", snippet: rx(`io\.jsonwebtoken`)},
	},
	"nimbus-jose-jwt": {{
		eco: EcosystemMaven, pkg: "nimbus-jose-jwt", group: "com.nimbusds",
		snippet: rx(`com\.nimbusds`),
	}},
	"jasypt": {{
		eco: EcosystemMaven, pkg: "jasypt", group: "org.jasypt",
		snippet: rx(`org\.jasypt`),
	}},
	"commons-codec": {{
		eco: EcosystemMaven, pkg: "commons-codec", group: "commons-codec",
		snippet: rx(`org\.apache\.commons\.codec`),
	}},
	"google-tink": {
		{eco: EcosystemMaven, pkg: "tink", group: "com.google.crypto.tink", snippet: rx(`google\.crypto\.tink`)},
		{eco: EcosystemMaven, pkg: "tink-awskms", group: "com.google.crypto.tink", snippet: rx(`google\.crypto\.tink`)},
		{eco: EcosystemMaven, pkg: "tink-gcpkms", group: "com.google.crypto.tink", snippet: rx(`google\.crypto\.tink`)},
	},
	"jbcrypt": {{
		eco: EcosystemMaven, pkg: "jbcrypt", group: "org.mindrot",
		snippet: rx(`mindrot\.jbcrypt`),
	}},
	"argon2-jvm": {{
		eco: EcosystemMaven, pkg: "argon2-jvm", group: "de.mkammerer",
		snippet: rx(`mkammerer\.argon2`),
	}},
	"jca": {{stdlib: true}},

	// Rust / Cargo
	"ring":             {{eco: EcosystemCargo, pkg: "ring", snippet: rx(`ring`)}},
	"rustls":           {{eco: EcosystemCargo, pkg: "rustls", snippet: rx(`rustls`)}},
	"openssl":          {{eco: EcosystemCargo, pkg: "openssl", snippet: rx(`openssl`)}},
	"aws-lc-rs":        {{eco: EcosystemCargo, pkg: "aws-lc-rs", snippet: rx(`aws_lc_rs`)}},
	"p256":             {{eco: EcosystemCargo, pkg: "p256", snippet: rx(`p256`)}},
	"ed25519-dalek":    {{eco: EcosystemCargo, pkg: "ed25519-dalek", snippet: rx(`ed25519_dalek`)}},
	"x25519-dalek":     {{eco: EcosystemCargo, pkg: "x25519-dalek", snippet: rx(`x25519_dalek`)}},
	"chacha20poly1305": {{eco: EcosystemCargo, pkg: "chacha20poly1305", snippet: rx(`chacha20poly1305`)}},

	// Ruby / RubyGems: openssl + digest are stdlib (no purl); bcrypt handled above.
	"digest": {{stdlib: true}},
	"jwt-rb": {{eco: EcosystemGem, pkg: "jwt", snippet: rx(`jwt`)}},
	"rbnacl": {{eco: EcosystemGem, pkg: "rbnacl", snippet: rx(`rbnacl`)}},

	// Python additional
	"pycrypto": {{eco: EcosystemPyPI, pkg: "pycryptodome", snippet: rx(`Crypto\.|Cryptodome`)}},

	// Go: the standard library's crypto/* — no purl.
	"go-crypto": {{stdlib: true}},

	// Dart / pub.dev (both are real pub packages, not stdlib).
	"pointycastle":      {{eco: EcosystemPub, pkg: "pointycastle", snippet: rx(`pointycastle`)}},
	"dart-crypto":       {{eco: EcosystemPub, pkg: "crypto", snippet: rx(`crypto`)}},
	"dart-cryptography": {{eco: EcosystemPub, pkg: "cryptography", snippet: rx(`cryptography`)}},

	// PHP mcrypt extension; name surfaced, no purl.
	"mcrypt": {{}},
	// Composer/NuGet/SPM ecosystems are not yet modeled in deps.Ecosystem; these
	// tokens remain detected but currently don't enrich with purl.
	"firebase-php-jwt":      {{}},
	"defuse-php-encryption": {{}},
	"swift-crypto":          {{}},
	"bouncycastle-dotnet":   {{}},
	"identitymodel-tokens":  {{}},
	"jose-jwt-dotnet":       {{}},
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
