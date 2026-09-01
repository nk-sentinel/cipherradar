package keystore

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// This file implements coverage-oriented keystore-password harvesting (issue
// #92). It scans a project's config files and source for values that are, by
// context, keystore passwords, and feeds them into the keystore open attempts
// so more keystores can be inventoried. It is NOT a secrets scanner: harvested
// values are used only as open candidates and are never logged or reported.
//
// Precision over recall: only values anchored to a keystore-password config key
// or a keystore-load API argument are collected, so the candidate list stays
// short (a locked keystore pays at most maxHarvested extra open attempts, and
// only because it did not open on a default — see passwordCandidates ordering).

// maxHarvested caps the number of distinct harvested candidates per scan so a
// pathological repo cannot blow up the per-keystore open-attempt cost.
const maxHarvested = 30

// harvestMaxFileBytes caps the size of a file we will read while harvesting;
// password-bearing config/source files are small.
const harvestMaxFileBytes = 512 << 10 // 512 KiB

var (
	// keyValuePassRE matches a keystore-password *key* and captures its value in
	// properties / YAML / .env style lines: the key name must contain a
	// store/key token AND a pass token (separators may be . _ or -).
	keyValuePassRE = regexp.MustCompile(`(?im)^[ \t]*["']?[\w.\-]*(?:key[._\-]?store|trust[._\-]?store|store|key)[._\-]?pass(?:word|phrase)?["']?[ \t]*[:=][ \t]*(.+?)[ \t]*$`)

	// xmlAttrPassRE matches keystorePass / truststorePass / key-store-password
	// style XML attributes (Tomcat server.xml, etc.).
	xmlAttrPassRE = regexp.MustCompile(`(?i)(?:key-?store|trust-?store|store|key|trust)[._\-]?pass(?:word|phrase)?[ \t]*=[ \t]*"([^"]+)"`)

	// javaLoadPassRE matches KeyStore.load(<stream>, "PASS".toCharArray()).
	javaLoadPassRE = regexp.MustCompile(`(?i)\.load\s*\([^,]*,\s*"([^"]+)"\s*\.toCharArray\(\)`)

	// sysPropPassRE matches -Djavax.net.ssl.keyStorePassword=PASS style values.
	sysPropPassRE = regexp.MustCompile(`(?i)javax\.net\.ssl\.(?:key|trust)StorePassword=([^\s"']+)`)

	// assignPassRE matches keyStorePassword = "PASS" assignments in source.
	assignPassRE = regexp.MustCompile(`(?i)(?:key|trust)StorePassword["']?\s*[:=]\s*"([^"]+)"`)
)

// configExts and sourceExts gate which files each pattern group is applied to.
var configExts = map[string]bool{
	".properties": true, ".yml": true, ".yaml": true, ".env": true,
	".xml": true, ".conf": true, ".cfg": true, ".ini": true, ".toml": true,
}

var sourceExts = map[string]bool{
	".java": true, ".kt": true, ".kts": true, ".scala": true, ".groovy": true,
	".go": true, ".py": true, ".rb": true, ".cs": true, ".js": true, ".ts": true,
}

// HarvestPasswords walks root and returns up to maxHarvested distinct candidate
// keystore passwords found in config keys and keystore-load API arguments.
// Returns nil when the tree contains no keystore files (nothing to unlock).
func HarvestPasswords(root string) []string {
	seenKeystore := false
	seen := make(map[string]bool)
	var out []string

	add := func(v string) {
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if !plausiblePassword(v) || seen[v] || len(out) >= maxHarvested {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip unreadable entries
		}
		if d.IsDir() {
			if skipHarvestDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if keystoreExts[ext] {
			seenKeystore = true
			return nil
		}
		isConfig := configExts[ext]
		isSource := sourceExts[ext]
		if !isConfig && !isSource {
			return nil
		}
		if info, e := d.Info(); e != nil || info.Size() > harvestMaxFileBytes {
			return nil
		}
		content, e := os.ReadFile(path) // #nosec G122 -- WalkDir over a path the operator asked cradar to scan; reading candidate config/source files is the harvester's purpose and the TOCTOU race is not a privilege boundary in a read-only inventory tool
		if e != nil {
			return nil
		}
		s := string(content)
		if isConfig {
			for _, m := range keyValuePassRE.FindAllStringSubmatch(s, -1) {
				add(m[1])
			}
			for _, m := range xmlAttrPassRE.FindAllStringSubmatch(s, -1) {
				add(m[1])
			}
		}
		if isSource {
			for _, re := range []*regexp.Regexp{javaLoadPassRE, sysPropPassRE, assignPassRE} {
				for _, m := range re.FindAllStringSubmatch(s, -1) {
					add(m[1])
				}
			}
		}
		return nil
	})

	if !seenKeystore {
		return nil
	}
	return out
}

// keystoreExts are the file extensions that indicate a keystore is present.
var keystoreExts = map[string]bool{
	".jks": true, ".keystore": true, ".p12": true, ".pfx": true,
	".bks": true, ".truststore": true, ".jceks": true,
}

// skipHarvestDir mirrors the scanner's default-ignored directories so the
// harvest walk does not descend into dependencies or VCS metadata.
func skipHarvestDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
		"dist", "build", ".idea", ".vscode", "target", ".gradle", ".mvn":
		return true
	}
	return false
}

// plausiblePassword rejects values that are clearly not passwords: empty,
// interpolation placeholders, paths, URLs, or oversized blobs (PEM/base64).
func plausiblePassword(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	if strings.ContainsAny(v, "\n\r") {
		return false
	}
	if strings.Contains(v, "${") || strings.Contains(v, "#{") || strings.Contains(v, "%(") {
		return false
	}
	if strings.Contains(v, "://") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") {
		return false
	}
	switch strings.ToLower(v) {
	case "null", "none", "true", "false":
		return false
	}
	// Looks like a keystore/cert filename rather than a password.
	lower := strings.ToLower(v)
	for e := range keystoreExts {
		if strings.HasSuffix(lower, e) {
			return false
		}
	}
	return true
}
