// Package astrules loads external, replaceable Pass-1 (tree-sitter AST)
// detection tables. Only the DATA (token -> crypto semantics) is externalized;
// the tree-sitter query machinery stays in each language scanner. This gives
// Pass 1 the same "bring your own rules" story Pass 2 (--rules-dir) and Pass 3
// (--yara-rules-dir) already have. See docs/ast-rules-external-design.md.
//
// The built-in tables ship embedded via //go:embed (source of truth in
// scanner/ast-rules/, synced by `go generate`). A caller-provided directory
// (--ast-rules-dir / CRADAR_AST_RULES_DIR) replaces the embedded tables on a
// per-language basis: a dir replaces only the languages whose <lang>.yml it
// contains; undefined languages keep the embedded tables.
package astrules

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:generate sh -c "cp ../../../../scanner/ast-rules/*.yml data/"

//go:embed data/*.yml
var embeddedFS embed.FS

// SupportedLanguages lists the languages that currently have an externalizable
// ast-rules file. Extended one language per Phase-B increment.
func SupportedLanguages() []string {
	return []string{"java", "go", "kotlin", "ruby", "rust", "cpp", "csharp", "php", "javascript", "python", "swift"}
}

// parseCheck loads lang's tables from dir purely to validate them, discarding
// the result. Returns nil for languages with no parser (should not happen for
// a SupportedLanguages entry).
func parseCheck(lang, dir string) error {
	switch lang {
	case "java":
		_, err := LoadJava(dir)
		return err
	case "go":
		_, err := LoadGo(dir)
		return err
	case "kotlin":
		_, err := LoadKotlin(dir)
		return err
	case "ruby":
		_, err := LoadRuby(dir)
		return err
	case "rust":
		_, err := LoadRust(dir)
		return err
	case "cpp":
		_, err := LoadCpp(dir)
		return err
	case "csharp":
		_, err := LoadCSharp(dir)
		return err
	case "php":
		_, err := LoadPHP(dir)
		return err
	case "javascript":
		_, err := LoadJavaScript(dir)
		return err
	case "python":
		_, err := LoadPython(dir)
		return err
	case "swift":
		_, err := LoadSwift(dir)
		return err
	}
	return nil
}

// --- Row types (exported so language scanners can consume them) ---

// JCAClass is one JCA factory class -> detection info row.
type JCAClass struct {
	Class     string `yaml:"class"`
	Primitive string `yaml:"primitive"`
	RuleTag   string `yaml:"rule_tag"`
}

// AlgorithmFamily maps a JCA algorithm name (uppercased) to a quantum family.
type AlgorithmFamily struct {
	Name   string `yaml:"name"`
	Family string `yaml:"family"`
}

// BCEngine is a Bouncy Castle engine/signer class -> algorithm info row.
type BCEngine struct {
	Class     string `yaml:"class"`
	Family    string `yaml:"family"`
	Name      string `yaml:"name"`
	Primitive string `yaml:"primitive"`
}

// BCMode maps a Bouncy Castle mode class to a mode string.
type BCMode struct {
	Class string `yaml:"class"`
	Mode  string `yaml:"mode"`
}

// BCDigest is a Bouncy Castle digest class -> algorithm info row.
type BCDigest struct {
	Class  string `yaml:"class"`
	Family string `yaml:"family"`
	Name   string `yaml:"name"`
}

// SSLProtocol maps an SSLContext.getInstance() protocol string to info.
// Severity is one of: critical, high, medium, low, info.
type SSLProtocol struct {
	Protocol string `yaml:"protocol"`
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Severity string `yaml:"severity"`
}

// JavaTables is the full set of Java Pass-1 detection tables.
type JavaTables struct {
	Version           int               `yaml:"version"`
	Language          string            `yaml:"language"`
	JCAClasses        []JCAClass        `yaml:"jca_classes"`
	AlgorithmFamilies []AlgorithmFamily `yaml:"algorithm_families"`
	BCEngines         []BCEngine        `yaml:"bc_engines"`
	BCAsymmetric      []BCEngine        `yaml:"bc_asymmetric"`
	BCModes           []BCMode          `yaml:"bc_modes"`
	BCDigests         []BCDigest        `yaml:"bc_digests"`
	SSLProtocols      []SSLProtocol     `yaml:"ssl_protocols"`
}

// readLangYAML returns the YAML bytes for lang. When dir is non-empty and
// dir/<lang>.yml exists, that external file is used (override); otherwise the
// embedded copy is returned (per-language fallback). The bool reports whether
// the source was external.
func readLangYAML(lang, dir string) ([]byte, bool, error) {
	if dir != "" {
		p := filepath.Join(dir, lang+".yml")
		b, err := os.ReadFile(p)
		if err == nil {
			return b, true, nil
		}
		if !os.IsNotExist(err) {
			return nil, false, fmt.Errorf("reading %s: %w", p, err)
		}
		// Absent — fall through to the embedded copy (per-language fallback).
	}
	b, err := embeddedFS.ReadFile("data/" + lang + ".yml")
	if err != nil {
		return nil, false, fmt.Errorf("no embedded ast-rules for language %q: %w", lang, err)
	}
	return b, false, nil
}

// LoadJava loads the Java tables from dir/java.yml when present, otherwise the
// embedded set. A present-but-malformed or empty file is an error.
func LoadJava(dir string) (*JavaTables, error) {
	b, _, err := readLangYAML("java", dir)
	if err != nil {
		return nil, err
	}
	var t JavaTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing java ast-rules: %w", err)
	}
	// A file that parses but defines none of the core tables is treated as
	// unusable, matching the Pass-2 "no loadable rules" contract.
	if len(t.JCAClasses) == 0 && len(t.AlgorithmFamilies) == 0 {
		return nil, fmt.Errorf("java ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadJavaEmbedded loads the embedded Java tables and panics on error. The
// embedded data is validated by tests, so a failure here is a build defect.
func MustLoadJavaEmbedded() *JavaTables {
	t, err := LoadJava("")
	if err != nil {
		panic("astrules: embedded java rules failed to load: " + err.Error())
	}
	return t
}

// --- Go ---

// GoTLSVersion maps a crypto/tls version constant name to its info.
// Severity is one of: critical, high, medium, low, info.
type GoTLSVersion struct {
	Const    string `yaml:"const"`
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Severity string `yaml:"severity"`
}

// GoSM2Func maps an SM2 package function name to its crypto role.
type GoSM2Func struct {
	Func      string `yaml:"func"`
	CryptoFn  string `yaml:"crypto_fn"`
	Primitive string `yaml:"primitive"`
}

// GoTables is the full set of Go Pass-1 detection tables.
type GoTables struct {
	Version      int            `yaml:"version"`
	Language     string         `yaml:"language"`
	TLSVersions  []GoTLSVersion `yaml:"tls_versions"`
	SM2Functions []GoSM2Func    `yaml:"sm2_functions"`
}

// LoadGo loads the Go tables from dir/go.yml when present, otherwise the
// embedded set. A present-but-malformed or empty file is an error.
func LoadGo(dir string) (*GoTables, error) {
	b, _, err := readLangYAML("go", dir)
	if err != nil {
		return nil, err
	}
	var t GoTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing go ast-rules: %w", err)
	}
	if len(t.TLSVersions) == 0 && len(t.SM2Functions) == 0 {
		return nil, fmt.Errorf("go ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadGoEmbedded loads the embedded Go tables and panics on error.
func MustLoadGoEmbedded() *GoTables {
	t, err := LoadGo("")
	if err != nil {
		panic("astrules: embedded go rules failed to load: " + err.Error())
	}
	return t
}

// ValidateRulesDir checks an explicitly provided --ast-rules-dir: it must
// contain at least one recognized <lang>.yml, and every recognized file that
// IS present must parse. Mirrors the Pass-2 --rules-dir "error if no loadable
// rules" contract. Undefined languages are not required (per-language fallback).
func ValidateRulesDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("empty rules directory")
	}
	found := 0
	for _, lang := range SupportedLanguages() {
		p := filepath.Join(dir, lang+".yml")
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("reading %s: %w", p, err)
		}
		found++
		if err := parseCheck(lang, dir); err != nil {
			return err
		}
	}
	if found == 0 {
		return fmt.Errorf("no recognized <lang>.yml files (expected one of: %s)",
			strings.Join(SupportedLanguages(), ", "))
	}
	return nil
}

// --- Kotlin ---

// KotlinTables is the full set of Kotlin Pass-1 detection tables. Kotlin runs
// on the JVM and uses the same JCA/JCE + Bouncy Castle APIs as Java, so it
// reuses the Java row types (JCAClass, AlgorithmFamily, BCEngine, BCMode,
// BCDigest, SSLProtocol).
type KotlinTables struct {
	Version           int               `yaml:"version"`
	Language          string            `yaml:"language"`
	JCAClasses        []JCAClass        `yaml:"jca_classes"`
	AlgorithmFamilies []AlgorithmFamily `yaml:"algorithm_families"`
	BCEngines         []BCEngine        `yaml:"bc_engines"`
	BCAsymmetric      []BCEngine        `yaml:"bc_asymmetric"`
	BCModes           []BCMode          `yaml:"bc_modes"`
	BCDigests         []BCDigest        `yaml:"bc_digests"`
	SSLProtocols      []SSLProtocol     `yaml:"ssl_protocols"`
}

// LoadKotlin loads the Kotlin tables from dir/kotlin.yml when present, otherwise
// the embedded set. A present-but-malformed or empty file is an error.
func LoadKotlin(dir string) (*KotlinTables, error) {
	b, _, err := readLangYAML("kotlin", dir)
	if err != nil {
		return nil, err
	}
	var t KotlinTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing kotlin ast-rules: %w", err)
	}
	if len(t.JCAClasses) == 0 && len(t.AlgorithmFamilies) == 0 {
		return nil, fmt.Errorf("kotlin ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadKotlinEmbedded loads the embedded Kotlin tables and panics on error.
func MustLoadKotlinEmbedded() *KotlinTables {
	t, err := LoadKotlin("")
	if err != nil {
		panic("astrules: embedded kotlin rules failed to load: " + err.Error())
	}
	return t
}

// --- Ruby ---

// CipherAlgorithm maps an OpenSSL::Cipher method string to algorithm details.
type CipherAlgorithm struct {
	Method string `yaml:"method"`
	Family string `yaml:"family"`
	Mode   string `yaml:"mode"`
	Name   string `yaml:"name"`
}

// DigestAlgorithm maps an OpenSSL/Digest algorithm key to algorithm details.
type DigestAlgorithm struct {
	Key    string `yaml:"key"`
	Family string `yaml:"family"`
	Name   string `yaml:"name"`
}

// RubyTables is the full set of Ruby Pass-1 detection tables.
type RubyTables struct {
	Version          int               `yaml:"version"`
	Language         string            `yaml:"language"`
	CipherAlgorithms []CipherAlgorithm `yaml:"cipher_algorithms"`
	DigestAlgorithms []DigestAlgorithm `yaml:"digest_algorithms"`
}

// LoadRuby loads the Ruby tables from dir/ruby.yml when present, otherwise the
// embedded set. A present-but-malformed or empty file is an error.
func LoadRuby(dir string) (*RubyTables, error) {
	b, _, err := readLangYAML("ruby", dir)
	if err != nil {
		return nil, err
	}
	var t RubyTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing ruby ast-rules: %w", err)
	}
	// A file that parses but defines none of the core tables is treated as
	// unusable, matching the Pass-2 "no loadable rules" contract.
	if len(t.CipherAlgorithms) == 0 && len(t.DigestAlgorithms) == 0 {
		return nil, fmt.Errorf("ruby ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadRubyEmbedded loads the embedded Ruby tables and panics on error. The
// embedded data is validated by tests, so a failure here is a build defect.
func MustLoadRubyEmbedded() *RubyTables {
	t, err := LoadRuby("")
	if err != nil {
		panic("astrules: embedded ruby rules failed to load: " + err.Error())
	}
	return t
}

// --- Rust ---

// RustRingDigest is a ring::digest algorithm identifier -> info row.
// Severity is one of: critical, high, medium, low, info.
type RustRingDigest struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Family   string `yaml:"family"`
	Severity string `yaml:"severity"`
}

// RustAESGCM maps a RustCrypto aes-gcm crate cipher type to its info.
type RustAESGCM struct {
	Cipher  string `yaml:"cipher"`
	Name    string `yaml:"name"`
	KeySize int    `yaml:"key_size"`
}

// RustTables is the full set of Rust Pass-1 detection tables.
type RustTables struct {
	Version              int              `yaml:"version"`
	Language             string           `yaml:"language"`
	RingDigestAlgorithms []RustRingDigest `yaml:"ring_digest_algorithms"`
	RustCryptoAESGCM     []RustAESGCM     `yaml:"rustcrypto_aes_gcm"`
}

// LoadRust loads the Rust tables from dir/rust.yml when present, otherwise the
// embedded set. A present-but-malformed or empty file is an error.
func LoadRust(dir string) (*RustTables, error) {
	b, _, err := readLangYAML("rust", dir)
	if err != nil {
		return nil, err
	}
	var t RustTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing rust ast-rules: %w", err)
	}
	if len(t.RingDigestAlgorithms) == 0 && len(t.RustCryptoAESGCM) == 0 {
		return nil, fmt.Errorf("rust ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadRustEmbedded loads the embedded Rust tables and panics on error.
func MustLoadRustEmbedded() *RustTables {
	t, err := LoadRust("")
	if err != nil {
		panic("astrules: embedded rust rules failed to load: " + err.Error())
	}
	return t
}

// --- C/C++ ---

// CppAsymFunc maps a classic OpenSSL asymmetric API function name to its
// algorithm info.
type CppAsymFunc struct {
	Func      string `yaml:"func"`
	Family    string `yaml:"family"`
	Name      string `yaml:"name"`
	Primitive string `yaml:"primitive"`
	Fn        string `yaml:"fn"`
}

// CppTLSMethod maps an OpenSSL SSL method function name to TLS version info.
// Severity is one of: critical, high, medium, low, info.
type CppTLSMethod struct {
	Method   string `yaml:"method"`
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Severity string `yaml:"severity"`
}

// CppTLSVersionConst maps an OpenSSL TLS version macro name to TLS version info.
// Severity is one of: critical, high, medium, low, info.
type CppTLSVersionConst struct {
	Const    string `yaml:"const"`
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Severity string `yaml:"severity"`
}

// CppTables is the full set of C/C++ Pass-1 detection tables.
type CppTables struct {
	Version             int                  `yaml:"version"`
	Language            string               `yaml:"language"`
	AsymFuncs           []CppAsymFunc        `yaml:"asym_funcs"`
	TLSMethods          []CppTLSMethod       `yaml:"tls_methods"`
	TLSVersionConstants []CppTLSVersionConst `yaml:"tls_version_constants"`
}

// LoadCpp loads the C/C++ tables from dir/cpp.yml when present, otherwise the
// embedded set. A present-but-malformed or empty file is an error.
func LoadCpp(dir string) (*CppTables, error) {
	b, _, err := readLangYAML("cpp", dir)
	if err != nil {
		return nil, err
	}
	var t CppTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing cpp ast-rules: %w", err)
	}
	// A file that parses but defines none of the core tables is treated as
	// unusable, matching the Pass-2 "no loadable rules" contract.
	if len(t.AsymFuncs) == 0 && len(t.TLSMethods) == 0 && len(t.TLSVersionConstants) == 0 {
		return nil, fmt.Errorf("cpp ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadCppEmbedded loads the embedded C/C++ tables and panics on error. The
// embedded data is validated by tests, so a failure here is a build defect.
func MustLoadCppEmbedded() *CppTables {
	t, err := LoadCpp("")
	if err != nil {
		panic("astrules: embedded cpp rules failed to load: " + err.Error())
	}
	return t
}

// --- C# ---

// CSharpFactoryClass is one System.Security.Cryptography factory class
// (Xxx.Create()) -> detection info row. Severity is one of: critical, high,
// medium, low, info. MaterialTag is non-empty only for key-material findings.
type CSharpFactoryClass struct {
	Class       string `yaml:"class"`
	Family      string `yaml:"family"`
	Name        string `yaml:"name"`
	Primitive   string `yaml:"primitive"`
	Severity    string `yaml:"severity"`
	RuleTag     string `yaml:"rule_tag"`
	CryptoFunc  string `yaml:"crypto_func"`
	MaterialTag string `yaml:"material_tag"`
}

// CSharpBCEngine is a BouncyCastle.NET engine class -> algorithm info row.
type CSharpBCEngine struct {
	Class     string `yaml:"class"`
	Family    string `yaml:"family"`
	Name      string `yaml:"name"`
	Primitive string `yaml:"primitive"`
}

// CSharpBCDigest is a BouncyCastle.NET digest class -> algorithm info row.
type CSharpBCDigest struct {
	Class  string `yaml:"class"`
	Family string `yaml:"family"`
	Name   string `yaml:"name"`
}

// CSharpSSLProtocol maps an SslProtocols enum value to TLS version info.
// Severity is one of: critical, high, medium, low, info.
type CSharpSSLProtocol struct {
	Enum     string `yaml:"enum"`
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Severity string `yaml:"severity"`
}

// CSharpTables is the full set of C# Pass-1 detection tables.
type CSharpTables struct {
	Version        int                  `yaml:"version"`
	Language       string               `yaml:"language"`
	FactoryClasses []CSharpFactoryClass `yaml:"factory_classes"`
	BCEngines      []CSharpBCEngine     `yaml:"bc_engines"`
	BCDigests      []CSharpBCDigest     `yaml:"bc_digests"`
	SSLProtocols   []CSharpSSLProtocol  `yaml:"ssl_protocols"`
}

// LoadCSharp loads the C# tables from dir/csharp.yml when present, otherwise the
// embedded set. A present-but-malformed or empty file is an error.
func LoadCSharp(dir string) (*CSharpTables, error) {
	b, _, err := readLangYAML("csharp", dir)
	if err != nil {
		return nil, err
	}
	var t CSharpTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing csharp ast-rules: %w", err)
	}
	if len(t.FactoryClasses) == 0 && len(t.BCEngines) == 0 && len(t.BCDigests) == 0 && len(t.SSLProtocols) == 0 {
		return nil, fmt.Errorf("csharp ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadCSharpEmbedded loads the embedded C# tables and panics on error.
func MustLoadCSharpEmbedded() *CSharpTables {
	t, err := LoadCSharp("")
	if err != nil {
		panic("astrules: embedded csharp rules failed to load: " + err.Error())
	}
	return t
}

// --- PHP ---

// PHPOpenSSLFunc maps an openssl_* function name to its crypto operation details.
type PHPOpenSSLFunc struct {
	Func         string   `yaml:"func"`
	Primitive    string   `yaml:"primitive"`
	CryptoFuncs  []string `yaml:"crypto_funcs"`
	MethodArgIdx int      `yaml:"method_arg_idx"`
	IsKeyGen     bool     `yaml:"is_key_gen"`
}

// PHPOpenSSLMethod maps a PHP openssl cipher method string to algorithm details.
type PHPOpenSSLMethod struct {
	Method string `yaml:"method"`
	Family string `yaml:"family"`
	Mode   string `yaml:"mode"`
	Name   string `yaml:"name"`
}

// PHPHashAlgo maps a PHP hash algorithm name to a family and human-readable name.
type PHPHashAlgo struct {
	Algo   string `yaml:"algo"`
	Family string `yaml:"family"`
	Name   string `yaml:"name"`
}

// PHPPasswordAlgo maps a PHP PASSWORD_* constant to algorithm details.
type PHPPasswordAlgo struct {
	Const  string `yaml:"const"`
	Family string `yaml:"family"`
	Name   string `yaml:"name"`
}

// PHPSodiumFunc maps a sodium_* function name to crypto details.
type PHPSodiumFunc struct {
	Func      string   `yaml:"func"`
	Family    string   `yaml:"family"`
	Name      string   `yaml:"name"`
	Primitive string   `yaml:"primitive"`
	Funcs     []string `yaml:"funcs"`
}

// PHPMcryptFunc maps an mcrypt_* function name to crypto details.
type PHPMcryptFunc struct {
	Func  string   `yaml:"func"`
	Funcs []string `yaml:"funcs"`
}

// PHPTables is the full set of PHP Pass-1 detection tables.
type PHPTables struct {
	Version        int                `yaml:"version"`
	Language       string             `yaml:"language"`
	OpenSSLFuncs   []PHPOpenSSLFunc   `yaml:"openssl_funcs"`
	OpenSSLMethods []PHPOpenSSLMethod `yaml:"openssl_methods"`
	HashAlgos      []PHPHashAlgo      `yaml:"hash_algos"`
	PasswordAlgos  []PHPPasswordAlgo  `yaml:"password_algos"`
	SodiumFuncs    []PHPSodiumFunc    `yaml:"sodium_funcs"`
	McryptFuncs    []PHPMcryptFunc    `yaml:"mcrypt_funcs"`
}

// LoadPHP loads the PHP tables from dir/php.yml when present, otherwise the
// embedded set. A present-but-malformed or empty file is an error.
func LoadPHP(dir string) (*PHPTables, error) {
	b, _, err := readLangYAML("php", dir)
	if err != nil {
		return nil, err
	}
	var t PHPTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing php ast-rules: %w", err)
	}
	if len(t.OpenSSLFuncs) == 0 && len(t.HashAlgos) == 0 {
		return nil, fmt.Errorf("php ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadPHPEmbedded loads the embedded PHP tables and panics on error.
func MustLoadPHPEmbedded() *PHPTables {
	t, err := LoadPHP("")
	if err != nil {
		panic("astrules: embedded php rules failed to load: " + err.Error())
	}
	return t
}

// --- JavaScript ---

// JSHashAlgo maps a hash token (Node crypto / forge / Web Crypto digest) to its
// algorithm family and display name.
type JSHashAlgo struct {
	Token  string `yaml:"token"`
	Family string `yaml:"family"`
	Name   string `yaml:"name"`
}

// JSCipherAlgo maps a Node.js crypto cipher token to its algorithm info.
type JSCipherAlgo struct {
	Token     string `yaml:"token"`
	Family    string `yaml:"family"`
	Name      string `yaml:"name"`
	Mode      string `yaml:"mode"`
	Primitive string `yaml:"primitive"`
	KeySize   int    `yaml:"key_size"`
}

// JSForgeCipherAlgo maps a node-forge cipher token to its algorithm info.
type JSForgeCipherAlgo struct {
	Token     string `yaml:"token"`
	Family    string `yaml:"family"`
	Name      string `yaml:"name"`
	Mode      string `yaml:"mode"`
	Primitive string `yaml:"primitive"`
}

// JSWebCryptoAlgo maps a Web Crypto algorithm name to its algorithm info.
type JSWebCryptoAlgo struct {
	Token     string `yaml:"token"`
	Family    string `yaml:"family"`
	Name      string `yaml:"name"`
	Primitive string `yaml:"primitive"`
	Mode      string `yaml:"mode"`
}

// JSTables is the full set of JavaScript/TypeScript Pass-1 detection tables.
type JSTables struct {
	Version                 int                 `yaml:"version"`
	Language                string              `yaml:"language"`
	HashAlgorithms          []JSHashAlgo        `yaml:"hash_algorithms"`
	CipherAlgorithms        []JSCipherAlgo      `yaml:"cipher_algorithms"`
	ForgeHashAlgorithms     []JSHashAlgo        `yaml:"forge_hash_algorithms"`
	ForgeCipherAlgorithms   []JSForgeCipherAlgo `yaml:"forge_cipher_algorithms"`
	WebCryptoAlgorithms     []JSWebCryptoAlgo   `yaml:"web_crypto_algorithms"`
	WebCryptoHashAlgorithms []JSHashAlgo        `yaml:"web_crypto_hash_algorithms"`
	NobleSecpModules        []string            `yaml:"noble_secp_modules"`
	NobleBLSModules         []string            `yaml:"noble_bls_modules"`
}

// LoadJavaScript loads the JavaScript tables from dir/javascript.yml when
// present, otherwise the embedded set. A present-but-malformed or empty file is
// an error.
func LoadJavaScript(dir string) (*JSTables, error) {
	b, _, err := readLangYAML("javascript", dir)
	if err != nil {
		return nil, err
	}
	var t JSTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing javascript ast-rules: %w", err)
	}
	if len(t.HashAlgorithms) == 0 && len(t.CipherAlgorithms) == 0 {
		return nil, fmt.Errorf("javascript ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadJavaScriptEmbedded loads the embedded JavaScript tables and panics on
// error. The embedded data is validated by tests, so a failure here is a build
// defect.
func MustLoadJavaScriptEmbedded() *JSTables {
	t, err := LoadJavaScript("")
	if err != nil {
		panic("astrules: embedded javascript rules failed to load: " + err.Error())
	}
	return t
}

// --- Python ---

// PyKV is a simple key -> value string row, used for the several string->string
// Python tables (hashlib method/algorithm maps, cipher/mode maps, BLS methods).
type PyKV struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// PyCipherAlgo maps a pyca cipher class name to a family + primitive.
type PyCipherAlgo struct {
	Class     string `yaml:"class"`
	Family    string `yaml:"family"`
	Primitive string `yaml:"primitive"`
}

// PyClassInfo maps a class name to a family + human-readable name (crypto
// hashes, KDFs, PyCryptodome hash usage).
type PyClassInfo struct {
	Class  string `yaml:"class"`
	Family string `yaml:"family"`
	Name   string `yaml:"name"`
}

// PySSLProto maps an ssl protocol/version constant to info. Severity is one of
// critical, high, medium, low, info.
type PySSLProto struct {
	Const    string `yaml:"const"`
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Severity string `yaml:"severity"`
}

// PyImport maps a PyCryptodome import symbol to crypto info.
type PyImport struct {
	Imported  string `yaml:"imported"`
	Family    string `yaml:"family"`
	Name      string `yaml:"name"`
	Primitive string `yaml:"primitive"`
}

// PyCipherUsage maps a PyCryptodome cipher class (detected at ClassName.new())
// to crypto info.
type PyCipherUsage struct {
	Class     string `yaml:"class"`
	Family    string `yaml:"family"`
	Name      string `yaml:"name"`
	Primitive string `yaml:"primitive"`
}

// PyAEAD maps a pyca one-shot AEAD class to family + name + mode.
type PyAEAD struct {
	Class  string `yaml:"class"`
	Family string `yaml:"family"`
	Name   string `yaml:"name"`
	Mode   string `yaml:"mode"`
}

// PyTier2Rule ties a specific Tier-2 asymmetric API call to an algorithm family,
// gated on a required import token.
type PyTier2Rule struct {
	RequireImport string `yaml:"require_import"`
	Object        string `yaml:"object"`
	Method        string `yaml:"method"`
	Family        string `yaml:"family"`
	Name          string `yaml:"name"`
	Primitive     string `yaml:"primitive"`
	CryptoFn      string `yaml:"crypto_fn"`
	RuleSuffix    string `yaml:"rule_suffix"`
}

// PythonTables is the full set of Python Pass-1 detection tables.
type PythonTables struct {
	Version  int    `yaml:"version"`
	Language string `yaml:"language"`

	HashlibMethodAlgorithms []PyKV          `yaml:"hashlib_method_algorithms"`
	HashlibMethodNames      []PyKV          `yaml:"hashlib_method_names"`
	HashlibNewAlgorithms    []PyKV          `yaml:"hashlib_new_algorithms"`
	HashlibNewNames         []PyKV          `yaml:"hashlib_new_names"`
	CipherAlgorithms        []PyCipherAlgo  `yaml:"cipher_algorithms"`
	CipherModes             []PyKV          `yaml:"cipher_modes"`
	CryptoHashes            []PyClassInfo   `yaml:"crypto_hashes"`
	KDFs                    []PyClassInfo   `yaml:"kdfs"`
	SSLProtocols            []PySSLProto    `yaml:"ssl_protocols"`
	SSLTLSVersions          []PySSLProto    `yaml:"ssl_tls_versions"`
	PyCryptoImports         []PyImport      `yaml:"pycrypto_imports"`
	PyCryptoCipherUsage     []PyCipherUsage `yaml:"pycrypto_cipher_usage"`
	PyCryptoHashUsage       []PyClassInfo   `yaml:"pycrypto_hash_usage"`
	PyCryptoModes           []PyKV          `yaml:"pycrypto_modes"`
	PycaAEAD                []PyAEAD        `yaml:"pyca_aead"`
	WeakRandomMethods       []string        `yaml:"weak_random_methods"`
	BLSSignMethods          []PyKV          `yaml:"bls_sign_methods"`
	Tier2Rules              []PyTier2Rule   `yaml:"tier2_rules"`
}

// LoadPython loads the Python tables from dir/python.yml when present, otherwise
// the embedded set. A present-but-malformed or empty file is an error.
func LoadPython(dir string) (*PythonTables, error) {
	b, _, err := readLangYAML("python", dir)
	if err != nil {
		return nil, err
	}
	var t PythonTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing python ast-rules: %w", err)
	}
	// A file that parses but defines none of the core tables is treated as
	// unusable, matching the Pass-2 "no loadable rules" contract.
	if len(t.HashlibMethodAlgorithms) == 0 && len(t.CipherAlgorithms) == 0 &&
		len(t.CryptoHashes) == 0 && len(t.PyCryptoImports) == 0 {
		return nil, fmt.Errorf("python ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadPythonEmbedded loads the embedded Python tables and panics on error.
func MustLoadPythonEmbedded() *PythonTables {
	t, err := LoadPython("")
	if err != nil {
		panic("astrules: embedded python rules failed to load: " + err.Error())
	}
	return t
}

// --- Swift ---

// CCCryptAlgorithm maps a CommonCrypto CCCrypt kCCAlgorithm* constant to the
// algorithm-specific finding info that replaces the generic CCCrypt finding.
// Severity is one of: critical, high, medium, low, info. AssetType mirrors
// types.AssetType (e.g. "algorithm").
type CCCryptAlgorithm struct {
	Const       string   `yaml:"const"`
	Family      string   `yaml:"family"`
	Name        string   `yaml:"name"`
	Primitive   string   `yaml:"primitive"`
	Severity    string   `yaml:"severity"`
	RuleID      string   `yaml:"rule_id"`
	CryptoFuncs []string `yaml:"crypto_funcs"`
	AssetType   string   `yaml:"asset_type"`
}

// SwiftTables is the full set of Swift Pass-1 detection tables.
type SwiftTables struct {
	Version           int                `yaml:"version"`
	Language          string             `yaml:"language"`
	CCCryptAlgorithms []CCCryptAlgorithm `yaml:"cc_crypt_algorithms"`
}

// LoadSwift loads the Swift tables from dir/swift.yml when present, otherwise
// the embedded set. A present-but-malformed or empty file is an error.
func LoadSwift(dir string) (*SwiftTables, error) {
	b, _, err := readLangYAML("swift", dir)
	if err != nil {
		return nil, err
	}
	var t SwiftTables
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parsing swift ast-rules: %w", err)
	}
	if len(t.CCCryptAlgorithms) == 0 {
		return nil, fmt.Errorf("swift ast-rules: no detection tables found")
	}
	return &t, nil
}

// MustLoadSwiftEmbedded loads the embedded Swift tables and panics on error.
func MustLoadSwiftEmbedded() *SwiftTables {
	t, err := LoadSwift("")
	if err != nil {
		panic("astrules: embedded swift rules failed to load: " + err.Error())
	}
	return t
}
