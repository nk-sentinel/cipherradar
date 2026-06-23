package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildPurl(t *testing.T) {
	cases := []struct {
		p    Package
		want string
	}{
		{Package{Ecosystem: EcosystemNPM, Name: "node-forge", Version: "1.3.1"}, "pkg:npm/node-forge@1.3.1"},
		{Package{Ecosystem: EcosystemNPM, Name: "@scope/pkg", Version: "2.0.0"}, "pkg:npm/%40scope/pkg@2.0.0"},
		{Package{Ecosystem: EcosystemPyPI, Name: "Cryptography", Version: "41.0.0"}, "pkg:pypi/cryptography@41.0.0"},
		{Package{Ecosystem: EcosystemMaven, Name: "bcprov-jdk18on", Group: "org.bouncycastle", Version: "1.77"}, "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.77"},
		{Package{Ecosystem: EcosystemNPM, Name: "node-forge"}, "pkg:npm/node-forge"}, // version-less
		{Package{Ecosystem: EcosystemNPM, Name: ""}, ""},
	}
	for _, tc := range cases {
		if got := BuildPurl(tc.p); got != tc.want {
			t.Errorf("BuildPurl(%+v) = %q, want %q", tc.p, got, tc.want)
		}
	}
}

func TestParseNpmLock_V3(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "package-lock.json", `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root"},
	    "node_modules/node-forge": {"version": "1.3.1"},
	    "node_modules/a/node_modules/node-forge": {"version": "0.10.0"}
	  }
	}`)
	pkgs, err := parseNpmLock(path)
	if err != nil {
		t.Fatal(err)
	}
	var found *Package
	for i := range pkgs {
		if pkgs[i].Name == "node-forge" {
			found = &pkgs[i]
		}
	}
	if found == nil || found.Version != "1.3.1" {
		t.Fatalf("expected node-forge@1.3.1 (direct), got %+v", found)
	}
	if !found.Direct {
		t.Error("top-level node-forge should be marked Direct")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "requirements.txt", "cryptography==41.0.0\nrequests>=2.0\n# comment\npynacl==1.5.0\n")
	pkgs, err := parseRequirementsTxt(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	if got["cryptography"] != "41.0.0" {
		t.Errorf("cryptography = %q, want 41.0.0", got["cryptography"])
	}
	if _, ok := got["requests"]; ok {
		t.Error("ranged requests should be skipped (unresolved)")
	}
}

func TestParsePomXML_PropertyResolution(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "pom.xml", `<project>
	  <properties><bc.version>1.77</bc.version></properties>
	  <dependencies>
	    <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>${bc.version}</version></dependency>
	    <dependency><groupId>com.acme</groupId><artifactId>lib</artifactId><version>2.1</version></dependency>
	  </dependencies>
	</project>`)
	pkgs, err := parsePomXML(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Package{}
	for _, p := range pkgs {
		got[p.Name] = p
	}
	if got["bcprov-jdk18on"].Version != "1.77" {
		t.Errorf("bcprov-jdk18on version = %q, want 1.77 (from ${bc.version})", got["bcprov-jdk18on"].Version)
	}
	if got["bcprov-jdk18on"].Group != "org.bouncycastle" {
		t.Errorf("group = %q, want org.bouncycastle", got["bcprov-jdk18on"].Group)
	}
}

func TestParsePomXML_DependencyManagementFallback(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "pom.xml", `<project>
	  <dependencyManagement>
	    <dependencies>
	      <dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-api</artifactId><version>0.12.6</version></dependency>
	    </dependencies>
	  </dependencyManagement>
	  <dependencies>
	    <dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-api</artifactId></dependency>
	  </dependencies>
	</project>`)
	pkgs, err := parsePomXML(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Version != "0.12.6" {
		t.Errorf("version = %q, want 0.12.6", pkgs[0].Version)
	}
	if pkgs[0].Group != "io.jsonwebtoken" {
		t.Errorf("group = %q, want io.jsonwebtoken", pkgs[0].Group)
	}
}

func TestResolveLibrary_SnippetDisambiguationAndVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "cryptography==41.0.0\n")
	src := writeFile(t, dir, "app.py", "from cryptography.hazmat import primitives\n")
	ix, _ := Build(dir)

	// Coarse token with multiple python candidates; snippet picks cryptography,
	// manifest pins the version.
	p, ok := ResolveLibrary(ix, "pyca-cryptography-or-hashlib-or-pycryptodome-or-pynacl-or-passlib-or-pyjwt-or-python-jose-or-authlib-or-bcrypt-py-or-argon2-cffi",
		"from cryptography.hazmat import primitives", src)
	if !ok {
		t.Fatal("expected resolution")
	}
	if p.Name != "cryptography" || p.Version != "41.0.0" {
		t.Errorf("got %+v, want cryptography@41.0.0", p)
	}
	if got := BuildPurl(p); got != "pkg:pypi/cryptography@41.0.0" {
		t.Errorf("purl = %q", got)
	}
}

func TestResolveLibrary_StdlibYieldsNoPurl(t *testing.T) {
	ix, _ := Build(t.TempDir())
	if _, ok := ResolveLibrary(ix, "hashlib", "import hashlib", "x.py"); ok {
		t.Error("stdlib hashlib should not resolve to a package")
	}
	if _, ok := ResolveLibrary(ix, "jca", "", "X.java"); ok {
		t.Error("jca (stdlib) should not resolve")
	}
}

func TestResolveLibrary_VersionlessFallback(t *testing.T) {
	ix, _ := Build(t.TempDir()) // no manifests
	p, ok := ResolveLibrary(ix, "node-forge", "const forge = require('node-forge')", "a.js")
	if !ok {
		t.Fatal("expected unambiguous node-forge to resolve without a version")
	}
	if p.Version != "" {
		t.Errorf("expected no version, got %q", p.Version)
	}
	if BuildPurl(p) != "pkg:npm/node-forge" {
		t.Errorf("purl = %q, want pkg:npm/node-forge", BuildPurl(p))
	}
}

func TestIndex_NearestAncestor(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.txt", "cryptography==1.0.0\n")
	writeFile(t, root, "svc/requirements.txt", "cryptography==2.0.0\n")
	deep := writeFile(t, root, "svc/app.py", "from cryptography import x\n")
	ix, _ := Build(root)

	p, ok := ix.Resolve(EcosystemPyPI, "cryptography", deep)
	if !ok {
		t.Fatal("expected resolution")
	}
	if p.Version != "2.0.0" {
		t.Errorf("nearest-ancestor version = %q, want 2.0.0 (svc/)", p.Version)
	}

	top := filepath.Join(root, "main.py")
	p2, _ := ix.Resolve(EcosystemPyPI, "cryptography", top)
	if p2.Version != "1.0.0" {
		t.Errorf("root version = %q, want 1.0.0", p2.Version)
	}
}

func TestBuildPurl_MoreEcosystems(t *testing.T) {
	cases := []struct {
		p    Package
		want string
	}{
		{Package{Ecosystem: EcosystemCargo, Name: "ring", Version: "0.16.20"}, "pkg:cargo/ring@0.16.20"},
		{Package{Ecosystem: EcosystemGem, Name: "bcrypt", Version: "3.1.18"}, "pkg:gem/bcrypt@3.1.18"},
		{Package{Ecosystem: EcosystemGolang, Name: "golang.org/x/crypto", Version: "v0.17.0"}, "pkg:golang/golang.org/x/crypto@v0.17.0"},
	}
	for _, tc := range cases {
		if got := BuildPurl(tc.p); got != tc.want {
			t.Errorf("BuildPurl(%+v) = %q, want %q", tc.p, got, tc.want)
		}
	}
}

func TestParseCargoLock(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "Cargo.lock", "[[package]]\nname = \"ring\"\nversion = \"0.16.20\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n")
	pkgs, err := parseCargoLock(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	if got["ring"] != "0.16.20" {
		t.Errorf("ring = %q, want 0.16.20", got["ring"])
	}
}

func TestParseGemfileLock(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    bcrypt (3.1.18)\n    json (2.6.3)\n\nPLATFORMS\n  ruby\n")
	pkgs, err := parseGemfileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	if got["bcrypt"] != "3.1.18" {
		t.Errorf("bcrypt = %q, want 3.1.18", got["bcrypt"])
	}
}

func TestParseGoMod(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "go.mod", "module example.com/m\n\ngo 1.21\n\nrequire golang.org/x/crypto v0.17.0\n\nrequire (\n\tgithub.com/foo/bar v1.2.3 // indirect\n)\n")
	pkgs, err := parseGoMod(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Package{}
	for _, p := range pkgs {
		got[p.Name] = p
	}
	if got["golang.org/x/crypto"].Version != "v0.17.0" || !got["golang.org/x/crypto"].Direct {
		t.Errorf("x/crypto = %+v, want v0.17.0 direct", got["golang.org/x/crypto"])
	}
	if got["github.com/foo/bar"].Direct {
		t.Error("foo/bar marked // indirect should not be Direct")
	}
}

func TestParseBuildGradle_VersionCatalogAlias(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "gradle/libs.versions.toml", `[versions]
bouncycastle = "1.78.1"
[libraries]
bcprov = { module = "org.bouncycastle:bcprov-jdk18on", version.ref = "bouncycastle" }
jjwtapi = { module = "io.jsonwebtoken:jjwt-api", version = "0.12.6" }
`)
	path := writeFile(t, dir, "build.gradle.kts", `dependencies {
  implementation(libs.bcprov)
  implementation(libs.jjwtapi)
}`)
	pkgs, err := parseBuildGradle(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Package{}
	for _, p := range pkgs {
		got[p.Group+":"+p.Name] = p
	}
	if got["org.bouncycastle:bcprov-jdk18on"].Version != "1.78.1" {
		t.Errorf("bcprov version = %q, want 1.78.1", got["org.bouncycastle:bcprov-jdk18on"].Version)
	}
	if got["io.jsonwebtoken:jjwt-api"].Version != "0.12.6" {
		t.Errorf("jjwt-api version = %q, want 0.12.6", got["io.jsonwebtoken:jjwt-api"].Version)
	}
}

func TestResolveLibrary_RustCargo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.lock", "[[package]]\nname = \"ring\"\nversion = \"0.17.7\"\n")
	src := writeFile(t, dir, "main.rs", "use ring::digest;\n")
	ix, _ := Build(dir)
	p, ok := ResolveLibrary(ix, "ring-or-rustls-or-openssl-or-aws-lc-rs-or-p256-or-ed25519-dalek-or-x25519-dalek-or-chacha20poly1305", "use ring::digest;", src)
	if !ok || p.Name != "ring" || p.Version != "0.17.7" {
		t.Fatalf("got %+v ok=%v, want ring@0.17.7", p, ok)
	}
	if BuildPurl(p) != "pkg:cargo/ring@0.17.7" {
		t.Errorf("purl = %q", BuildPurl(p))
	}
}

func TestParsePubspecLock_AndPurl(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pubspec.lock", "packages:\n  pointycastle:\n    dependency: \"direct main\"\n    source: hosted\n    version: \"3.7.3\"\n  http:\n    dependency: transitive\n    version: \"1.0.0\"\n")
	src := writeFile(t, dir, "main.dart", "import 'package:pointycastle/export.dart';\n")
	ix, _ := Build(dir)
	p, ok := ResolveLibrary(ix, "dart-crypto-or-pointycastle-or-dart-cryptography", "import 'package:pointycastle/export.dart';", src)
	if !ok || p.Name != "pointycastle" || p.Version != "3.7.3" {
		t.Fatalf("got %+v ok=%v, want pointycastle@3.7.3", p, ok)
	}
	if BuildPurl(p) != "pkg:pub/pointycastle@3.7.3" {
		t.Errorf("purl = %q", BuildPurl(p))
	}
}

func TestResolveLibrary_AncestorEcosystemPreference(t *testing.T) {
	// bcrypt exists as both an npm package and a Ruby gem. A finding in a Ruby
	// file must resolve to the gem (its own ancestor manifest), not the npm
	// package elsewhere in the repo.
	root := t.TempDir()
	writeFile(t, root, "js/package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/bcrypt":{"version":"5.1.1"}}}`)
	writeFile(t, root, "rb/Gemfile.lock", "GEM\n  specs:\n    bcrypt (3.1.20)\n")
	rbFile := writeFile(t, root, "rb/app.rb", "require 'bcrypt'\n")
	ix, _ := Build(root)

	p, ok := ResolveLibrary(ix, "openssl-or-bcrypt-or-digest-or-jwt-rb-or-rbnacl", "require 'bcrypt'", rbFile)
	if !ok {
		t.Fatal("expected bcrypt to resolve")
	}
	if p.Ecosystem != EcosystemGem || p.Version != "3.1.20" {
		t.Errorf("ruby bcrypt resolved to %s/%s@%s, want gem/bcrypt@3.1.20", p.Ecosystem, p.Name, p.Version)
	}
}

func TestResolvePomVersion(t *testing.T) {
	props := map[string]string{"bc.version": "1.77"}
	cases := []struct {
		in   string
		want string
	}{
		{"1.2.3", "1.2.3"},        // literal
		{"${bc.version}", "1.77"}, // resolved property
		{"${missing.prop}", ""},   // unresolved property -> empty
		{"[1.0,2.0)", ""},         // version range -> unpinned
		{"", ""},                  // absent
	}
	for _, tc := range cases {
		if got := resolvePomVersion(tc.in, props); got != tc.want {
			t.Errorf("resolvePomVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParsePomXML_UnresolvedProperty(t *testing.T) {
	// A dependency whose version is a ${property} that is neither defined in
	// <properties> nor covered by <dependencyManagement> must still be emitted,
	// but with an empty (unpinned) version rather than the literal "${...}".
	dir := t.TempDir()
	path := writeFile(t, dir, "pom.xml", `<project>
	  <dependencies>
	    <dependency><groupId>com.acme</groupId><artifactId>lib</artifactId><version>${undefined.ver}</version></dependency>
	  </dependencies>
	</project>`)
	pkgs, err := parsePomXML(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "lib" || pkgs[0].Version != "" {
		t.Errorf("got %+v, want lib with empty version", pkgs[0])
	}
}

func TestParseGradleVersionCatalog_EdgeCases(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "libs.versions.toml", `[versions]
good = "1.0.0"
[libraries]
goodlib = { module = "com.good:lib", version.ref = "good" }
unresolved = { module = "com.x:y", version.ref = "missing" }
nomodule = { version = "9.9" }
junk line without equals
`)
	libs, err := parseGradleVersionCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	// Valid library with a resolvable version.ref.
	if g := libs["goodlib"]; g.Group != "com.good" || g.Name != "lib" || g.Version != "1.0.0" {
		t.Errorf("goodlib = %+v, want com.good:lib@1.0.0", g)
	}
	// version.ref pointing at a missing [versions] key -> present but unpinned.
	if u, ok := libs["unresolved"]; !ok || u.Version != "" {
		t.Errorf("unresolved = %+v (ok=%v), want com.x:y with empty version", u, ok)
	}
	// A library entry with no module must be skipped, not panic.
	if _, ok := libs["nomodule"]; ok {
		t.Error("library without a module should be skipped")
	}
}

func TestParseBuildGradle_MalformedCatalogFallsBackToInline(t *testing.T) {
	// A present-but-unusable catalog must not lose the inline pinned deps, and an
	// unknown libs.<alias> reference must be silently ignored (fail-safe).
	dir := t.TempDir()
	writeFile(t, dir, "gradle/libs.versions.toml", "this is not valid toml @@@@\n[[[ broken\n")
	path := writeFile(t, dir, "build.gradle.kts", `dependencies {
  implementation("com.acme:lib:2.1")
  implementation(libs.unknownalias)
}`)
	pkgs, err := parseBuildGradle(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected only the inline dep, got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Group != "com.acme" || pkgs[0].Name != "lib" || pkgs[0].Version != "2.1" {
		t.Errorf("got %+v, want com.acme:lib@2.1", pkgs[0])
	}
}

func TestParseBuildGradle_InlineWinsOverCatalog(t *testing.T) {
	// When the same coordinate is declared both inline (pinned) and via a catalog
	// alias, the inline occurrence wins (processed first; per-coordinate dedup).
	dir := t.TempDir()
	writeFile(t, dir, "gradle/libs.versions.toml", `[versions]
bc = "1.78.1"
[libraries]
bcprov = { module = "org.bouncycastle:bcprov-jdk18on", version.ref = "bc" }
`)
	path := writeFile(t, dir, "build.gradle.kts", `dependencies {
  implementation("org.bouncycastle:bcprov-jdk18on:1.77")
  implementation(libs.bcprov)
}`)
	pkgs, err := parseBuildGradle(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 deduped package, got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Version != "1.77" {
		t.Errorf("version = %q, want 1.77 (inline wins over catalog 1.78.1)", pkgs[0].Version)
	}
}

func TestResolveLibrary_JavaJJWTMultiArtifact(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pom.xml", `<project><dependencies>
	  <dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-impl</artifactId><version>0.12.6</version></dependency>
	</dependencies></project>`)
	src := writeFile(t, dir, "App.java", "import io.jsonwebtoken.Jwts;\n")
	ix, _ := Build(dir)

	p, ok := ResolveLibrary(ix, "jjwt", "import io.jsonwebtoken.Jwts;", src)
	if !ok {
		t.Fatal("expected jjwt to resolve")
	}
	if p.Name != "jjwt-impl" || p.Version != "0.12.6" {
		t.Fatalf("got %+v, want jjwt-impl@0.12.6", p)
	}
	if got := BuildPurl(p); got != "pkg:maven/io.jsonwebtoken/jjwt-impl@0.12.6" {
		t.Errorf("purl = %q", got)
	}
}
