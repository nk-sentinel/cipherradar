// Package scannerinit provides a default scanner registry with all built-in
// language scanners pre-registered. It exists as a separate package to avoid
// an import cycle between the scanner interface package and its implementations.
package scannerinit

import (
	cradarConfig "github.com/nk-sentinel/cipherradar/cli/internal/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/binary"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/cpp"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/csharp"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/custom"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/dart"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/golang"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/java"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/javascript"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/kotlin"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/php"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/python"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/regex"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/ruby"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/rust"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/swift"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/yarax"
)

// DefaultRegistry returns a registry with all built-in language scanners.
func DefaultRegistry() *scanner.Registry {
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

	// Binary scanners (compiled files and archives)
	r.Register(binary.New())
	r.Register(binary.NewJARScanner())
	r.Register(binary.NewWheelScanner())

	// Universal scanners (run on every file regardless of extension)
	r.RegisterUniversal(regex.New())

	// YARA-X scanner (Pass 3 — binary crypto detection via the bundled
	// `yr` binary). Registered as Universal so it doesn't displace the
	// native binary / JAR / wheel scanners (Registry.ForExtension is
	// last-write-wins). Until Sub-PR B ships an embedded ruleset and
	// Sub-PR C wires up `--passes 3`, the scanner soft-skips on every
	// file — registration is the seam for the upcoming work, not a
	// behavior change.
	r.RegisterUniversal(yarax.New())

	return r
}

// DefaultRegistryWithConfig returns a registry seeded with the built-in
// scanners plus a CustomScanner when cfg declares any custom_wrappers
// (ADR-025 configuration extension). The CustomScanner is registered as a
// Universal so it sees every file — its own language gate filters matches.
// When cfg is nil or declares no wrappers, behavior is identical to
// DefaultRegistry.
func DefaultRegistryWithConfig(cfg *cradarConfig.Config) *scanner.Registry {
	r := DefaultRegistry()
	if cfg == nil || len(cfg.CustomWrappers) == 0 {
		return r
	}
	if cs := custom.New(cfg.CustomWrappers); cs != nil {
		r.RegisterUniversal(cs)
	}
	return r
}
