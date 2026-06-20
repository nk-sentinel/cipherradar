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

func TestResolveLibrary_SnippetDisambiguationAndVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "cryptography==41.0.0\n")
	src := writeFile(t, dir, "app.py", "from cryptography.hazmat import primitives\n")
	ix, _ := Build(dir)

	// Coarse token with multiple python candidates; snippet picks cryptography,
	// manifest pins the version.
	p, ok := ResolveLibrary(ix, "pyca-cryptography-or-hashlib-or-pycryptodome-or-pynacl",
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

func TestResolveLibrary_RustCargo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.lock", "[[package]]\nname = \"ring\"\nversion = \"0.17.7\"\n")
	src := writeFile(t, dir, "main.rs", "use ring::digest;\n")
	ix, _ := Build(dir)
	p, ok := ResolveLibrary(ix, "ring-or-rustls-or-openssl", "use ring::digest;", src)
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
	p, ok := ResolveLibrary(ix, "dart-crypto-or-pointycastle", "import 'package:pointycastle/export.dart';", src)
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

	p, ok := ResolveLibrary(ix, "openssl-or-bcrypt-or-digest", "require 'bcrypt'", rbFile)
	if !ok {
		t.Fatal("expected bcrypt to resolve")
	}
	if p.Ecosystem != EcosystemGem || p.Version != "3.1.20" {
		t.Errorf("ruby bcrypt resolved to %s/%s@%s, want gem/bcrypt@3.1.20", p.Ecosystem, p.Name, p.Version)
	}
}
