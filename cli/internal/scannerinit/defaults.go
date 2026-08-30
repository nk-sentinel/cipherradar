// Package scannerinit provides a default scanner registry with all built-in
// language scanners pre-registered. It exists as a separate package to avoid
// an import cycle between the scanner interface package and its implementations.
package scannerinit

import (
	cradarConfig "github.com/nk-sentinel/cipherradar/cli/internal/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/binary"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/configfile"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/cpp"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/csharp"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/custom"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/dart"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/golang"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/java"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/javascript"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/keystore"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/kotlin"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/php"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/python"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/regex"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/ruby"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/rust"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/swift"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/yarax"
)

// RegistryOptions carries optional overrides for building the scanner
// registry. The zero value reproduces DefaultRegistry's behavior.
type RegistryOptions struct {
	// YaraRulesDir, when non-empty, overrides the YARA-X (Pass 3) rules
	// directory — mirroring --rules-dir for Pass 2. Empty means use the
	// default resolution order (CRADAR_YARA_RULES_DIR env, else the embedded
	// starter ruleset).
	YaraRulesDir string
}

// DefaultRegistry returns a registry with all built-in language scanners.
func DefaultRegistry() *scanner.Registry {
	return DefaultRegistryWithOptions(nil, RegistryOptions{})
}

// DefaultRegistryWithOptions is the single registry builder. It registers
// every built-in scanner, seeds a CustomScanner when cfg declares any
// custom_wrappers, and honors opts (e.g. an external YARA-X rules directory).
func DefaultRegistryWithOptions(cfg *cradarConfig.Config, opts RegistryOptions) *scanner.Registry {
	r := scanner.NewRegistry()

	// Language-specific scanners (dispatched by file extension)
	r.Register(python.New())
	r.Register(javascript.New())
	r.Register(java.New())
	r.Register(kotlin.New())
	r.Register(csharp.New())
	r.Register(php.New())
	r.Register(golang.New())
	r.Register(cpp.New())
	r.Register(rust.New())
	r.Register(swift.New())
	r.Register(ruby.New())
	r.Register(dart.New())

	// Config file scanner (dispatched by .env / .properties extensions)
	r.Register(config.New())

	// Infrastructure config scanners (nginx/httpd .conf, openssl .cnf,
	// java.security, k8s .yaml, Dockerfile).
	configfile.RegisterAll(r)

	// Binary scanners (compiled files and archives)
	r.Register(binary.New())
	r.Register(binary.NewJARScanner())
	r.Register(binary.NewWheelScanner())

	// Keystore scanner (JKS / PKCS#12, dispatched by .jks/.p12/.pfx/... ext)
	r.Register(keystore.New())

	// Universal scanners (run on every file regardless of extension)
	r.RegisterUniversal(regex.New())

	// YARA-X scanner (Pass 3 — binary crypto detection via the bundled
	// `yr` binary). Registered as Universal so it doesn't displace the
	// native binary / JAR / wheel scanners (Registry.ForExtension is
	// last-write-wins). An external rules directory (--yara-rules-dir /
	// CRADAR_YARA_RULES_DIR) replaces the embedded ruleset; empty means use
	// the default resolution inside yarax.New().
	if opts.YaraRulesDir != "" {
		r.RegisterUniversal(yarax.NewWithRunner(yarax.NewRunner(), opts.YaraRulesDir))
	} else {
		r.RegisterUniversal(yarax.New())
	}

	// CustomScanner from .cradar.yml custom_wrappers (ADR-025). Registered as
	// a Universal so it sees every file — its own language gate filters matches.
	if cfg != nil && len(cfg.CustomWrappers) > 0 {
		if cs := custom.New(cfg.CustomWrappers); cs != nil {
			r.RegisterUniversal(cs)
		}
	}

	return r
}

// DefaultRegistryWithConfig returns a registry seeded with the built-in
// scanners plus a CustomScanner when cfg declares any custom_wrappers
// (ADR-025 configuration extension). When cfg is nil or declares no wrappers,
// behavior is identical to DefaultRegistry.
func DefaultRegistryWithConfig(cfg *cradarConfig.Config) *scanner.Registry {
	return DefaultRegistryWithOptions(cfg, RegistryOptions{})
}
