// Package scannerinit provides a default scanner registry with all built-in
// language scanners pre-registered. It exists as a separate package to avoid
// an import cycle between the scanner interface package and its implementations.
package scannerinit

import (
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/config"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/csharp"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/golang"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/java"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/javascript"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/kotlin"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/php"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/python"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/regex"
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

	// Config file scanner (dispatched by .env / .properties extensions)
	r.Register(config.New())

	// Universal scanners (run on every file regardless of extension)
	r.RegisterUniversal(regex.New())

	return r
}
